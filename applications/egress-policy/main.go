// A guest-local HTTP gateway. Only this trusted process originates upstream TLS.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
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
	"strconv"
	"strings"
	"sync"
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
	WebSocketSeconds  int      `json:"websocket_seconds,omitempty"`
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
	policy  Policy
	client  *http.Transport
	mu      sync.Mutex
	usage   []usage
	audit   *log.Logger
	timeout time.Duration
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
	return strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "//") && !strings.ContainsAny(s, "%?#\\\r\n") && path.Clean(s) == s
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
	seen := map[string]bool{}
	for _, r := range p.Rules {
		if !(validName(r.Name) || (strings.HasPrefix(r.Name, "*.") && validName(strings.TrimPrefix(r.Name, "*.")))) || seen[r.Name] || r.Port != 443 {
			return p, errors.New("DNS name or one-label wildcard and TLS port 443 required")
		}
		seen[r.Name] = true
		if len(r.Methods) == 0 || len(r.Paths) == 0 {
			return p, errors.New("methods and exact paths required")
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
	return &gateway{policy: p, usage: make([]usage, len(p.Rules)), audit: logger, timeout: 15 * time.Second, client: &http.Transport{
		Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
		MaxResponseHeaderBytes: 16384, DisableKeepAlives: true, DisableCompression: true,
		// HTTP/1.1 only. No cross-authority connection coalescing.
		ForceAttemptHTTP2: false,
	}}
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
	b, _ := json.Marshal(struct {
		Rule     int    `json:"rule"`
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
		Upload   int64  `json:"upload"`
		Download int64  `json:"download"`
	}{rule, decision, reason, up, down})
	g.audit.Print(string(b))
}
func (g *gateway) index(name string) int {
	for i, r := range g.policy.Rules {
		if name == r.Name || (strings.HasPrefix(r.Name, "*.") && strings.HasSuffix(name, r.Name[1:]) && !strings.Contains(strings.TrimSuffix(name, r.Name[1:]), ".") && strings.TrimSuffix(name, r.Name[1:]) != "") {
			return i
		}
	}
	return -1
}
func (g *gateway) reserve(i int, up int64, stream bool) (int64, int64, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	r := g.policy.Rules[i]
	u := &g.usage[i]
	now := time.Now()
	if u.last.IsZero() {
		u.tokens = 1
	} else {
		u.tokens += now.Sub(u.last).Seconds() * float64(r.RequestsPerMinute) / 60
		if u.tokens > 1 {
			u.tokens = 1
		}
	}
	u.last = now
	down := r.MaxResponseBytes
	if stream {
		// Opaque upgrades consume the remaining measured stream budgets, rather
		// than the much smaller HTTP body/header limits. Reserve before hijacking.
		up, down = r.UploadBytes-u.upload, r.DownloadBytes-u.download
		if up < r.MaxRequestBytes || down < r.MaxResponseBytes {
			return 0, 0, false
		}
	}
	if u.tokens < 1 || u.requests >= r.Requests || up > r.UploadBytes-u.upload || down > r.DownloadBytes-u.download {
		return 0, 0, false
	}
	u.tokens--
	u.requests++
	u.upload += up
	u.download += down
	return up, down, true
}
func (g *gateway) refundUpload(i int, unused int64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.usage[i].upload -= unused
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

func (g *gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	i := -1
	deny := func(status int, reason string) { g.event(i, "deny", reason, 0, 0); http.Error(w, reason, status) }
	// Reject absolute-form altogether: Go's parser replaces Host from an absolute
	// target, obscuring a conflicting raw Host. There is one authority input here.
	if r.Method == "CONNECT" || r.URL.IsAbs() || r.URL.Host != "" || !strings.HasPrefix(r.RequestURI, "/") {
		deny(403, "origin_form_required")
		return
	}
	if len(r.TransferEncoding) > 0 || len(r.Trailer) > 0 || r.URL.RawQuery != "" || r.URL.ForceQuery || !validPath(r.URL.EscapedPath()) {
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
	if !contains(rule.Methods, r.Method) || !contains(rule.Paths, r.URL.Path) {
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
	target := &url.URL{Scheme: "https", Host: net.JoinHostPort(name, strconv.Itoa(rule.Port)), Path: r.URL.Path}
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
		for _, v := range r.Header.Values(k) {
			out.Header.Add(k, v)
		}
	}
	out.Header.Set("User-Agent", "dsmack-egress/1")
	if isWS {
		for _, k := range []string{"Connection", "Upgrade", "Sec-WebSocket-Key", "Sec-WebSocket-Version", "Sec-WebSocket-Protocol"} {
			out.Header.Set(k, r.Header.Get(k))
		}
	}

	up := int64(len(body)+len(r.Method)+len(r.URL.Path)+len(name)) + headerBytes(out.Header)
	if up > rule.MaxRequestBytes {
		deny(413, "request_bytes")
		return
	}
	reservedUp, reservedDown, allowed := g.reserve(i, up, isWS)
	if !allowed {
		deny(429, "budget_or_rate")
		return
	}
	defer func() { g.refundUpload(i, reservedUp-up) }()
	// TLS verifies the certificate chain and DNS name before sending HTTP bytes.
	// The transport derives SNI from target.Host. Workloads never supply TLS.
	resp, err := g.client.RoundTrip(out)
	if err != nil {
		g.refundDownload(i, reservedDown, 0)
		g.event(i, "deny", "upstream_tls_or_io", up, 0)
		http.Error(w, "upstream_tls_or_io", 502)
		return
	}
	defer resp.Body.Close()
	down := headerBytes(resp.Header)
	if isWS && resp.StatusCode == 101 {
		g.event(i, "allow", "websocket_tls", up, down)
		extraUp, extraDown := g.websocket(w, r, resp, duration, reservedUp-up, reservedDown-down)
		up += extraUp
		down += extraDown
		g.refundDownload(i, reservedDown, down)
		g.event(i, "complete", "websocket_tls", up, down)
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
	for _, k := range []string{"Content-Type", "Location", "Retry-After"} {
		for _, v := range resp.Header.Values(k) {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(response)))
	g.event(i, "allow", "validated_tls", up, down)
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(response)
}

// WebSocket payload stays opaque. Reserve each direction's full byte budget
// before the upgrade; refund unused bytes after both copy loops have stopped.
func (g *gateway) websocket(w http.ResponseWriter, r *http.Request, resp *http.Response, duration time.Duration, upCap, downCap int64) (int64, int64) {
	upstream, ok := resp.Body.(io.ReadWriteCloser)
	hj, canHijack := w.(http.Hijacker)
	if !ok || !canHijack || upCap < 0 || downCap < 0 {
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
	if _, err = buffer.WriteString("\r\n"); err != nil {
		return 0, 0
	}
	if err = buffer.Flush(); err != nil {
		return 0, 0
	}
	type count struct {
		up bool
		n  int64
	}
	done := make(chan count, 2)
	go func() { n, _ := io.CopyN(upstream, buffer, upCap); done <- count{true, n} }()
	go func() { n, _ := io.CopyN(local, upstream, downCap); done <- count{false, n} }()
	first := <-done
	local.Close()
	upstream.Close()
	second := <-done
	var up, down int64
	for _, c := range []count{first, second} {
		if c.up {
			up = c.n
		} else {
			down = c.n
		}
	}
	return up, down
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
