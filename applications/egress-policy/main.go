// A guest-local HTTP gateway. Only this trusted process originates upstream TLS.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Rule struct {
	Name              string   `json:"name"`
	Port              int      `json:"port"`
	Methods           []string `json:"methods"`
	Paths             []string `json:"paths"`
	MaxRequestBytes   int64    `json:"max_request_bytes"`
	MaxResponseBytes  int64    `json:"max_response_bytes"`
	UploadBytes       int64    `json:"upload_bytes"`
	DownloadBytes     int64    `json:"download_bytes"`
	Requests          int      `json:"requests"`
	RequestsPerMinute int      `json:"requests_per_minute"`
	Burst             int      `json:"burst,omitempty"`
	WebSocketSeconds  int      `json:"websocket_seconds,omitempty"`
	// Optional, for fetch workloads: path prefixes and path.Match globs besides
	// exact paths, query strings forwarded verbatim, fixed request headers that
	// replace the default User-Agent, and no credential headers from the client.
	PathPrefixes    []string          `json:"path_prefixes,omitempty"`
	PathGlobs       []string          `json:"path_globs,omitempty"`
	Query           bool              `json:"query,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	DropCredentials bool              `json:"drop_credentials,omitempty"`
	// Optional, for logged-in sessions: Cookie and Set-Cookie pass through, the
	// named client headers are forwarded verbatim, the origin may negotiate
	// HTTP/2, and account counters carry caps that the gateway enforces.
	Cookies       bool     `json:"cookies,omitempty"`
	ClientHeaders []string `json:"client_headers,omitempty"`
	HTTP2         bool     `json:"http2,omitempty"`
	Account       *Account `json:"account,omitempty"`
}

// Account counters are shared by every rule with the same group (default: the
// rule name). A session is the SHA-256 of the named cookies present in a request;
// a request carrying none of them is anonymous. Login, signup and post patterns
// are path.Match globs that count only methods other than GET and HEAD.
type Account struct {
	Group           string   `json:"group,omitempty"`
	SessionCookies  []string `json:"session_cookies,omitempty"`
	MaxSessions     int      `json:"max_sessions,omitempty"`
	LoginPaths      []string `json:"login_paths,omitempty"`
	SignupPaths     []string `json:"signup_paths,omitempty"`
	Signup          bool     `json:"signup,omitempty"`
	PostPaths       []string `json:"post_paths,omitempty"`
	MaxPostsPerHour int      `json:"max_posts_per_hour,omitempty"`
}
type counter struct {
	sessions        map[string]bool
	logins, signups int
	posts           []time.Time
}
type hit struct {
	session             string
	login, signup, post bool
}
type Policy struct {
	Rules []Rule `json:"rules"`
}
type usage struct {
	upload, download int64
	requests         int
	tokens           float64
	last             time.Time
}
type gateway struct {
	policy   Policy
	client   *http.Transport
	mu       sync.Mutex
	usage    []usage
	counters map[string]*counter
	audit    *log.Logger
	timeout  time.Duration
	h2once   sync.Once
	h2       *http.Transport
	streams  atomic.Int64
}

func validName(s string) bool {
	if s != strings.ToLower(s) || len(s) > 253 || !strings.Contains(s, ".") || net.ParseIP(s) != nil {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
func validPath(s string) bool {
	return strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "//") && !strings.ContainsAny(s, "%?#\\\r\n") && (path.Clean(s) == s || path.Clean(s)+"/" == s)
}
func validGlob(s string) bool {
	_, err := path.Match(s, "/")
	return err == nil && strings.HasPrefix(s, "/") && !strings.ContainsAny(s, "%?#\\\r\n")
}
func validToken(s string) bool {
	return s != "" && strings.Trim(strings.ToLower(s), "abcdefghijklmnopqrstuvwxyz0123456789-") == ""
}
func loadPolicy(b []byte) (Policy, error) {
	var p Policy
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return p, err
	}
	if d.Decode(new(any)) != io.EOF {
		return p, errors.New("trailing policy input")
	}
	if len(p.Rules) == 0 || len(p.Rules) > 64 {
		return p, errors.New("rule count")
	}
	seen, groups := map[string]bool{}, map[string]*Account{}
	for _, r := range p.Rules {
		if !(validName(r.Name) || (strings.HasPrefix(r.Name, "*.") && validName(strings.TrimPrefix(r.Name, "*.")))) || seen[r.Name] || r.Port != 443 {
			return p, errors.New("DNS name or one-label wildcard and TLS port 443 required")
		}
		seen[r.Name] = true
		if len(r.Methods) == 0 || len(r.Paths)+len(r.PathPrefixes)+len(r.PathGlobs) == 0 {
			return p, errors.New("methods and paths required")
		}
		for _, s := range r.PathPrefixes {
			if !validPath(s) {
				return p, errors.New("canonical path prefix required")
			}
		}
		for _, s := range r.PathGlobs {
			if !validGlob(s) {
				return p, errors.New("valid path glob required")
			}
		}
		for _, k := range r.ClientHeaders {
			k = http.CanonicalHeaderKey(k)
			if !validToken(k) || contains(controlled, k) || contains(forwarded, k) || strings.HasPrefix(k, "Proxy-") || strings.HasPrefix(k, "X-Forwarded-") || strings.HasPrefix(k, "Sec-Websocket-") {
				return p, errors.New("client header " + k + " is controlled by the gateway")
			}
			for h := range r.Headers {
				if http.CanonicalHeaderKey(h) == k {
					return p, errors.New("client header " + k + " is also a fixed header")
				}
			}
		}
		if a := r.Account; a != nil {
			if a.Group == "" {
				a.Group = r.Name
			}
			if len(a.SessionCookies) > 0 && a.MaxSessions < 1 || len(a.PostPaths) > 0 && a.MaxPostsPerHour < 1 {
				return p, errors.New("session_cookies need max_sessions and post_paths need max_posts_per_hour")
			}
			for _, c := range a.SessionCookies {
				if c == "" || strings.ContainsAny(c, "=;, \t\r\n\"") {
					return p, errors.New("valid session cookie name required")
				}
			}
			for _, s := range append(append(append([]string{}, a.LoginPaths...), a.SignupPaths...), a.PostPaths...) {
				if !validGlob(s) {
					return p, errors.New("valid account path glob required")
				}
			}
			if g, ok := groups[a.Group]; ok && !reflect.DeepEqual(*g, *a) {
				return p, errors.New("rules in one account group need the same account settings")
			}
			groups[a.Group] = a
		}
		for k, v := range r.Headers {
			if !contains(settable, http.CanonicalHeaderKey(k)) || strings.ContainsAny(v, "\r\n") || len(v) > 512 {
				return p, errors.New("only User-Agent, Accept and Accept-Language may be set, without line breaks")
			}
		}
		for _, m := range r.Methods {
			if !contains([]string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}, m) {
				return p, errors.New("unsupported method")
			}
		}
		for _, s := range r.Paths {
			if !validPath(s) {
				return p, errors.New("canonical exact path required")
			}
		}
		if r.Burst < 0 || r.Burst > r.Requests {
			return p, errors.New("burst must be 0..requests")
		}
		if r.WebSocketSeconds < 0 || r.WebSocketSeconds > 3600 {
			return p, errors.New("websocket_seconds must be 0..3600")
		}
		if r.MaxRequestBytes < 1 || r.MaxRequestBytes > 1<<20 || r.MaxResponseBytes < 1 || r.MaxResponseBytes > 4<<20 || r.UploadBytes < r.MaxRequestBytes || r.DownloadBytes < r.MaxResponseBytes || r.Requests < 1 || r.RequestsPerMinute < 1 {
			return p, errors.New("positive bounded budgets required")
		}
	}
	return p, nil
}
func newGateway(p Policy, logger *log.Logger) *gateway {
	return &gateway{policy: p, usage: make([]usage, len(p.Rules)), counters: map[string]*counter{}, audit: logger, timeout: 15 * time.Second, client: &http.Transport{
		Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
		MaxResponseHeaderBytes: 16384, DisableKeepAlives: true, DisableCompression: true,
		// HTTP/1.1 only. No cross-authority connection coalescing.
		ForceAttemptHTTP2: false,
	}}
}

// The HTTP/2 transport copies the HTTP/1.1 one on first use, after main or a test configured it.
// WebSocket upgrades on it still use HTTP/1.1 (net/http requiresHTTP1).
func (g *gateway) http2() *http.Transport {
	g.h2once.Do(func() {
		g.h2 = g.client.Clone()
		g.h2.ForceAttemptHTTP2 = true
	})
	return g.h2
}
func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
func (g *gateway) event(rule int, decision, reason string, up, down int64) {
	g.record(evidence{Rule: rule, Decision: decision, Reason: reason, Upload: up, Download: down})
}

// evidence is one audit line. Allowed responses also carry the status and the
// hashes of what the gateway's own upstream connection saw, but no request data.
type evidence struct {
	Rule       int    `json:"rule"`
	Decision   string `json:"decision"`
	Reason     string `json:"reason"`
	Upload     int64  `json:"upload"`
	Download   int64  `json:"download"`
	Status     int    `json:"status,omitempty"`
	CertSHA256 string `json:"cert_sha256,omitempty"`
	BodySHA256 string `json:"body_sha256,omitempty"`
	BodyBytes  int    `json:"body_bytes,omitempty"`
	Stream     int64  `json:"stream,omitempty"`
}

func (g *gateway) record(e evidence) {
	b, _ := json.Marshal(e)
	g.audit.Print(string(b))
}

func pathAllowed(r Rule, p string) bool {
	if contains(r.Paths, p) {
		return true
	}
	for _, prefix := range r.PathPrefixes {
		if p == prefix || strings.HasPrefix(p, strings.TrimSuffix(prefix, "/")+"/") {
			return true
		}
	}
	return matchAny(r.PathGlobs, p)
}
func matchAny(globs []string, p string) bool {
	for _, glob := range globs {
		if ok, _ := path.Match(glob, p); ok {
			return true
		}
	}
	return false
}
func classify(a *Account, r *http.Request) hit {
	var b strings.Builder
	for _, name := range a.SessionCookies {
		if c, err := r.Cookie(name); err == nil {
			fmt.Fprintf(&b, "%s=%s\x00", name, c.Value)
		}
	}
	h, write := hit{}, r.Method != "GET" && r.Method != "HEAD"
	if b.Len() > 0 {
		sum := sha256.Sum256([]byte(b.String()))
		h.session = hex.EncodeToString(sum[:])
	}
	h.login = write && matchAny(a.LoginPaths, r.URL.Path)
	h.signup = write && matchAny(a.SignupPaths, r.URL.Path)
	h.post = write && matchAny(a.PostPaths, r.URL.Path)
	return h
}
func (g *gateway) index(name string) int {
	for i, r := range g.policy.Rules {
		if name == r.Name || (strings.HasPrefix(r.Name, "*.") && strings.HasSuffix(name, r.Name[1:]) && !strings.Contains(strings.TrimSuffix(name, r.Name[1:]), ".") && strings.TrimSuffix(name, r.Name[1:]) != "") {
			return i
		}
	}
	return -1
}

// reserve charges budgets and account counters together, or neither. It returns
// the reserved download bytes, a refusal reason, empty when allowed, and the
// account counters afterwards. The token bucket holds max(burst, 1) requests.
func (g *gateway) reserve(i int, up int64, h hit) (int64, string, string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	r := g.policy.Rules[i]
	u := &g.usage[i]
	now := time.Now()
	capacity := float64(max(r.Burst, 1))
	if u.last.IsZero() {
		u.tokens = capacity
	} else {
		u.tokens = min(capacity, u.tokens+now.Sub(u.last).Seconds()*float64(r.RequestsPerMinute)/60)
	}
	u.last = now
	down := r.MaxResponseBytes
	if u.tokens < 1 || u.requests >= r.Requests || up > r.UploadBytes-u.upload || down > r.DownloadBytes-u.download {
		return 0, "budget_or_rate", ""
	}
	a, c := r.Account, (*counter)(nil)
	if a != nil {
		if c = g.counters[a.Group]; c == nil {
			c = &counter{sessions: map[string]bool{}}
			g.counters[a.Group] = c
		}
		for len(c.posts) > 0 && now.Sub(c.posts[0]) >= time.Hour {
			c.posts = c.posts[1:]
		}
		reason := ""
		switch {
		case h.session != "" && !c.sessions[h.session] && len(c.sessions) >= a.MaxSessions:
			reason = "account_session_cap"
		case h.signup && !a.Signup:
			reason = "account_signup_policy"
		case h.post && len(c.posts) >= a.MaxPostsPerHour:
			reason = "account_post_rate"
		}
		if reason != "" {
			return 0, reason, c.String()
		}
		if h.session != "" {
			c.sessions[h.session] = true
		}
		if h.login {
			c.logins++
		}
		if h.signup {
			c.signups++
		}
		if h.post {
			c.posts = append(c.posts, now)
		}
	}
	u.tokens--
	u.requests++
	u.upload += up
	u.download += down
	return down, "", c.String()
}
func (c *counter) String() string {
	if c == nil {
		return ""
	}
	return fmt.Sprintf("sessions=%d logins=%d signups=%d posts_last_hour=%d", len(c.sessions), c.logins, c.signups, len(c.posts))
}
func (g *gateway) refundDownload(i int, reserved, used int64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.usage[i].download -= reserved - used
}

// Application-byte accounting includes names/values, method, target, authority,
// and body. It excludes framing, TLS, DNS, and TCP/IP overhead.
func headerBytes(h http.Header) int64 {
	var n int64
	for k, vs := range h {
		for _, v := range vs {
			n += int64(len(k) + len(v))
		}
	}
	return n
}

var forwarded = []string{"Accept", "Content-Type", "Authorization", "X-Api-Key", "Anthropic-Version", "Anthropic-Beta"}
var credentials = []string{"Authorization", "X-Api-Key"}
var settable = []string{"User-Agent", "Accept", "Accept-Language"}
var controlled = []string{"Host", "Connection", "Keep-Alive", "Upgrade", "Te", "Trailer", "Transfer-Encoding", "Content-Length", "Cookie", "Accept-Encoding", "Forwarded", "Via", "X-Real-Ip"}

func (g *gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	i := -1
	deny := func(status int, reason string) { g.event(i, "deny", reason, 0, 0); http.Error(w, reason, status) }
	// Reject absolute-form altogether: Go's parser replaces Host from an absolute
	// target, obscuring a conflicting raw Host. There is one authority input here.
	if r.Method == "CONNECT" || r.URL.IsAbs() || r.URL.Host != "" || !strings.HasPrefix(r.RequestURI, "/") {
		deny(403, "origin_form_required")
		return
	}
	if len(r.TransferEncoding) > 0 || len(r.Trailer) > 0 || r.URL.ForceQuery || strings.ContainsAny(r.URL.RawQuery, "#\\\r\n ") || !validPath(r.URL.EscapedPath()) {
		deny(403, "unsupported_request_form")
		return
	}
	name := r.Host
	if strings.Contains(name, ":") {
		host, port, err := net.SplitHostPort(name)
		if err != nil || port != "8080" {
			deny(403, "local_authority")
			return
		}
		name = host
	}
	if !validName(name) {
		deny(403, "dns_name_required")
		return
	}
	i = g.index(name)
	if i < 0 {
		deny(403, "name_policy")
		return
	}
	rule := g.policy.Rules[i]
	isWS := strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
	if r.Header.Get("Upgrade") != "" && (!isWS || rule.WebSocketSeconds == 0 || r.Method != "GET" || r.ContentLength != 0 || r.Header.Get("Sec-WebSocket-Version") != "13" || !strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")) {
		deny(403, "websocket_policy")
		return
	}
	if !contains(rule.Methods, r.Method) || !pathAllowed(rule, r.URL.Path) || (r.URL.RawQuery != "" && !rule.Query) {
		deny(403, "method_path_policy")
		return
	}
	if r.ContentLength > rule.MaxRequestBytes {
		deny(413, "request_bytes")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, rule.MaxRequestBytes+1))
	if err != nil || int64(len(body)) > rule.MaxRequestBytes {
		deny(413, "request_bytes")
		return
	}
	duration := g.timeout
	if isWS {
		duration = time.Duration(rule.WebSocketSeconds) * time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), duration)
	defer cancel()
	target := &url.URL{Scheme: "https", Host: net.JoinHostPort(name, strconv.Itoa(rule.Port)), Path: r.URL.Path, RawQuery: r.URL.RawQuery}
	out, err := http.NewRequestWithContext(ctx, r.Method, target.String(), bytes.NewReader(body))
	if err != nil {
		deny(400, "request_form")
		return
	}
	out.Host = name
	out.Close = !isWS
	// Fresh request discards forwarding/routing/hop-by-hop headers, credentials
	// for local proxies, trailers, and alternate authority inputs.
	for _, k := range forwarded {
		if rule.DropCredentials && contains(credentials, k) {
			continue
		}
		for _, v := range r.Header.Values(k) {
			out.Header.Add(k, v)
		}
	}
	out.Header.Set("User-Agent", "dsmack-egress/1")
	if rule.Cookies {
		for _, v := range r.Header.Values("Cookie") {
			out.Header.Add("Cookie", v)
		}
	}
	for _, k := range rule.ClientHeaders {
		if vs := r.Header.Values(k); len(vs) > 0 {
			out.Header[http.CanonicalHeaderKey(k)] = append([]string(nil), vs...)
		}
	}
	for k, v := range rule.Headers {
		out.Header.Set(k, v)
	}
	if isWS {
		for _, k := range []string{"Connection", "Upgrade", "Sec-WebSocket-Key", "Sec-WebSocket-Version", "Sec-WebSocket-Protocol"} {
			out.Header.Set(k, r.Header.Get(k))
		}
	}

	up := int64(len(body)+len(r.Method)+len(r.URL.Path)+len(r.URL.RawQuery)+len(name)) + headerBytes(out.Header)
	if up > rule.MaxRequestBytes {
		deny(413, "request_bytes")
		return
	}
	var h hit
	if rule.Account != nil {
		h = classify(rule.Account, r)
	}
	reservedDown, refused, counts := g.reserve(i, up, h)
	if counts != "" {
		w.Header().Set("X-Dsmack-Account", counts)
	}
	if refused == "budget_or_rate" {
		deny(429, refused)
		return
	}
	if refused != "" {
		deny(403, refused)
		return
	}
	// TLS verifies the certificate chain and DNS name before sending HTTP bytes.
	// The transport derives SNI from target.Host. Workloads never supply TLS.
	transport := g.client
	if rule.HTTP2 {
		transport = g.http2()
	}
	resp, err := transport.RoundTrip(out)
	if err != nil {
		g.refundDownload(i, reservedDown, 0)
		g.event(i, "deny", "upstream_tls_or_io", up, 0)
		http.Error(w, "upstream_tls_or_io: "+err.Error(), 502)
		return
	}
	defer resp.Body.Close()
	down := headerBytes(resp.Header)
	if isWS && resp.StatusCode == 101 {
		stream := g.streams.Add(1)
		g.refundDownload(i, reservedDown, down)
		g.record(evidence{Rule: i, Decision: "allow", Reason: "websocket_tls", Upload: up, Download: down, Stream: stream})
		extraUp, extraDown := g.websocket(w, r, resp, duration, i, stream)
		up += extraUp
		down += extraDown
		g.record(evidence{Rule: i, Decision: "complete", Reason: "websocket_tls", Upload: up, Download: down, Stream: stream})
		return
	}
	if resp.StatusCode == 101 || down > rule.MaxResponseBytes {
		g.refundDownload(i, reservedDown, reservedDown)
		g.event(i, "deny", "response_bytes_or_upgrade", up, rule.MaxResponseBytes)
		http.Error(w, "response_bytes_or_upgrade", 502)
		return
	}
	response, err := io.ReadAll(io.LimitReader(resp.Body, rule.MaxResponseBytes-down+1))
	down += int64(len(response))
	if err != nil || down > rule.MaxResponseBytes {
		g.refundDownload(i, reservedDown, reservedDown)
		g.event(i, "deny", "response_bytes_or_io", up, rule.MaxResponseBytes)
		http.Error(w, "response_bytes_or_io", 502)
		return
	}
	g.refundDownload(i, reservedDown, down)
	// Redirects are returned, never followed. Strip control and network hints.
	returned := []string{"Content-Type", "Location", "Retry-After"}
	if rule.Cookies {
		returned = append(returned, "Set-Cookie")
	}
	for _, k := range returned {
		for _, v := range resp.Header.Values(k) {
			w.Header().Add(k, v)
		}
	}
	// Evidence from this connection: the leaf certificate TLS verified and the body as received.
	cert, sum := "", sha256.Sum256(response)
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		leaf := sha256.Sum256(resp.TLS.PeerCertificates[0].Raw)
		cert = hex.EncodeToString(leaf[:])
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(response)))
	w.Header().Set("X-Dsmack-Cert-Sha256", cert)
	w.Header().Set("X-Dsmack-Body-Sha256", hex.EncodeToString(sum[:]))
	w.Header().Set("X-Dsmack-Body-Bytes", strconv.Itoa(len(response)))
	g.record(evidence{Rule: i, Decision: "allow", Reason: "validated_tls", Upload: up, Download: down,
		Status: resp.StatusCode, CertSHA256: cert, BodySHA256: hex.EncodeToString(sum[:]), BodyBytes: len(response)})
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(response)
}

// meter charges one WebSocket direction's bytes to the rule's budget as they
// flow, so concurrent requests share what remains. It stops at the budget.
type meter struct {
	g  *gateway
	i  int
	up bool
	w  io.Writer
	n  int64
}

var errStreamBudget = errors.New("stream_budget")

func (m *meter) Write(p []byte) (int, error) {
	m.g.mu.Lock()
	used, limit := &m.g.usage[m.i].download, m.g.policy.Rules[m.i].DownloadBytes
	if m.up {
		used, limit = &m.g.usage[m.i].upload, m.g.policy.Rules[m.i].UploadBytes
	}
	k := min(int64(len(p)), limit-*used)
	*used += k
	m.g.mu.Unlock()
	n, err := m.w.Write(p[:k])
	m.n += int64(n)
	if int64(n) < k {
		m.g.mu.Lock()
		*used -= k - int64(n)
		m.g.mu.Unlock()
	}
	if err == nil && k < int64(len(p)) {
		err = errStreamBudget
	}
	return n, err
}

// WebSocket payload stays opaque. Each direction is metered against the rule's
// remaining byte budgets; the stream closes when either is spent.
func (g *gateway) websocket(w http.ResponseWriter, r *http.Request, resp *http.Response, duration time.Duration, i int, stream int64) (int64, int64) {
	upstream, ok := resp.Body.(io.ReadWriteCloser)
	hj, canHijack := w.(http.Hijacker)
	if !ok || !canHijack {
		http.Error(w, "websocket_upstream", 502)
		return 0, 0
	}
	local, buffer, err := hj.Hijack()
	if err != nil {
		return 0, 0
	}
	defer local.Close()
	defer upstream.Close()
	_ = local.SetDeadline(time.Now().Add(duration))
	_, err = buffer.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	if err != nil {
		return 0, 0
	}
	for _, k := range []string{"Connection", "Upgrade", "Sec-WebSocket-Accept", "Sec-WebSocket-Protocol"} {
		for _, v := range resp.Header.Values(k) {
			if _, err = fmt.Fprintf(buffer, "%s: %s\r\n", k, v); err != nil {
				return 0, 0
			}
		}
	}
	if _, err = fmt.Fprintf(buffer, "X-Dsmack-Stream: %d\r\n", stream); err != nil {
		return 0, 0
	}
	if _, err = buffer.WriteString("\r\n"); err != nil {
		return 0, 0
	}
	if err = buffer.Flush(); err != nil {
		return 0, 0
	}
	up, down := &meter{g: g, i: i, up: true, w: upstream}, &meter{g: g, i: i, w: local}
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, buffer); done <- struct{}{} }()
	go func() { io.Copy(down, upstream); done <- struct{}{} }()
	<-done
	local.Close()
	upstream.Close()
	<-done
	return up.n, down.n
}

// A non-recursive DNS stub: synthesize allowed A records, refuse every other
// name, never forward query bytes or EDNS data to host-controlled DNS.
func (g *gateway) dnsReply(q []byte, ip net.IP) []byte {
	if len(q) < 12 || len(q) > 512 {
		return nil
	}
	if binary.BigEndian.Uint16(q[2:4])&0xf800 != 0 || binary.BigEndian.Uint16(q[4:6]) != 1 {
		return nil
	}
	pos := 12
	labels := []string{}
	for {
		if pos >= len(q) {
			return nil
		}
		n := int(q[pos])
		pos++
		if n == 0 {
			break
		}
		if n > 63 || pos+n > len(q) {
			return nil
		}
		labels = append(labels, string(q[pos:pos+n]))
		pos += n
	}
	if pos+4 > len(q) {
		return nil
	}
	name := strings.ToLower(strings.Join(labels, "."))
	typ := binary.BigEndian.Uint16(q[pos : pos+2])
	class := binary.BigEndian.Uint16(q[pos+2 : pos+4])
	end := pos + 4
	i := g.index(name)
	code := uint16(0)
	if i < 0 || class != 1 {
		code = 5
		g.event(-1, "deny", "dns_name_or_class", 0, 0)
	} else {
		g.event(i, "allow", "dns_local_only", 0, 0)
	}
	a := make([]byte, end)
	copy(a, q[:end])
	binary.BigEndian.PutUint16(a[2:4], 0x8080|code)
	for j := 6; j < 12; j++ {
		a[j] = 0
	}
	if code == 0 && typ == 1 {
		binary.BigEndian.PutUint16(a[6:8], 1)
		a = append(a, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4)
		a = append(a, ip.To4()...)
	}
	return a
}
func (g *gateway) serveDNS(addr string, ip net.IP) error {
	udp, err := net.ListenPacket("udp4", addr)
	if err != nil {
		return err
	}
	tcp, err := net.Listen("tcp4", addr)
	if err != nil {
		udp.Close()
		return err
	}
	go func() {
		b := make([]byte, 513)
		for {
			n, peer, e := udp.ReadFrom(b)
			if e != nil {
				return
			}
			if a := g.dnsReply(b[:n], ip); a != nil {
				_, _ = udp.WriteTo(a, peer)
			}
		}
	}()
	slots := make(chan struct{}, 32)
	go func() {
		for {
			c, e := tcp.Accept()
			if e != nil {
				return
			}
			select {
			case slots <- struct{}{}:
				go func() {
					defer c.Close()
					defer func() { <-slots }()
					_ = c.SetDeadline(time.Now().Add(3 * time.Second))
					var h [2]byte
					if _, e := io.ReadFull(c, h[:]); e != nil {
						return
					}
					n := int(binary.BigEndian.Uint16(h[:]))
					if n > 512 {
						return
					}
					q := make([]byte, n)
					if _, e := io.ReadFull(c, q); e != nil {
						return
					}
					a := g.dnsReply(q, ip)
					if a == nil {
						return
					}
					binary.BigEndian.PutUint16(h[:], uint16(len(a)))
					_, _ = c.Write(append(h[:], a...))
				}()
			default:
				c.Close()
			}
		}
	}()
	return nil
}
func main() {
	policyFile := flag.String("policy", "/policy.json", "measured policy")
	listen := flag.String("http", ":8080", "guest-local HTTP listener")
	dns := flag.String("dns", ":53", "guest-local DNS listener")
	answer := flag.String("answer-ip", "", "private gateway IPv4 address")
	fixedHost := flag.String("websocket-host", "", "fixed TLS hostname for loopback-only WebSocket clients")
	upstreamProxy := flag.String("upstream-proxy", "", "explicit HTTP CONNECT proxy with an IP address")
	timeout := flag.Duration("upstream-timeout", 15*time.Second, "upstream request timeout, at most 180s")
	flag.Parse()
	if *timeout <= 0 || *timeout > 180*time.Second {
		log.Fatal("upstream timeout must be 0..180s")
	}
	b, err := os.ReadFile(*policyFile)
	if err != nil {
		log.Fatal("policy unavailable")
	}
	p, err := loadPolicy(b)
	if err != nil {
		log.Fatal("invalid policy: ", err)
	}
	ip := net.ParseIP(*answer)
	if *dns != "" && ip.To4() == nil {
		log.Fatal("answer-ip requires IPv4")
	}
	g := newGateway(p, log.New(os.Stdout, "", 0))
	g.timeout = *timeout
	g.client.ResponseHeaderTimeout = *timeout
	if *upstreamProxy != "" {
		proxy, parseErr := url.Parse(*upstreamProxy)
		if parseErr != nil || proxy.Scheme != "http" || net.ParseIP(proxy.Hostname()) == nil || proxy.Port() == "" || proxy.User != nil || proxy.Path != "" || proxy.RawQuery != "" || proxy.Fragment != "" {
			log.Fatal("upstream proxy requires an explicit HTTP IP:port origin")
		}
		g.client.Proxy = http.ProxyURL(proxy)
	}
	if *dns != "" {
		if err = g.serveDNS(*dns, ip); err != nil {
			log.Fatal("DNS listen failed")
		}
	}
	var handler http.Handler = g
	if *fixedHost != "" {
		listenHost, _, listenErr := net.SplitHostPort(*listen)
		if !validName(*fixedHost) || g.index(*fixedHost) < 0 || listenErr != nil || !net.ParseIP(listenHost).IsLoopback() {
			log.Fatal("fixed WebSocket host requires an allowed hostname and loopback listener")
		}
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Host != *listen || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
				http.Error(w, "fixed_websocket_route", 403)
				return
			}
			r.Host = *fixedHost
			g.ServeHTTP(w, r)
		})
	}
	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: *timeout + 5*time.Second, MaxHeaderBytes: 16384, ErrorLog: log.New(io.Discard, "", 0)}
	fmt.Fprintln(os.Stderr, "egress gateway ready")
	if err = server.ListenAndServe(); err != nil {
		log.Fatal("HTTP server stopped")
	}
}
