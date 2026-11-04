package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func sessionPolicy() Policy {
	acct := func() *Account {
		return &Account{Group: "shop.test", SessionCookies: []string{"uid"}, MaxSessions: 1, LoginPaths: []string{"/login"},
			SignupPaths: []string{"/signup", "/join/*"}, PostPaths: []string{"/post/*"}, MaxPostsPerHour: 2}
	}
	rule := func(name string) Rule {
		return Rule{Name: name, Port: 443, Methods: []string{"GET", "POST"}, PathPrefixes: []string{"/"}, Query: true,
			Cookies: true, ClientHeaders: []string{"user-agent", "Origin"}, Account: acct(),
			MaxRequestBytes: 4096, MaxResponseBytes: 4096, UploadBytes: 1 << 20, DownloadBytes: 1 << 20, Requests: 100, RequestsPerMinute: 60000}
	}
	return Policy{Rules: []Rule{rule("shop.test"), rule("*.shop.test")}}
}

func TestCookiesAndClientHeaders(t *testing.T) {
	var got http.Header
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		http.SetCookie(w, &http.Cookie{Name: "uid", Value: "a"})
		w.Header().Add("Set-Cookie", "csrf=x")
	})
	g, _ := withFixture(t, sessionPolicy(), "shop.test", handler)
	r := call(g, "GET", "/", "shop.test", "", http.Header{"Cookie": {"uid=a; theme=dark"}, "User-Agent": {"Mozilla/5.0 buyer"},
		"Origin": {"https://shop.test"}, "Referer": {"https://shop.test/x"}, "X-Forwarded-For": {"10.0.0.1"}})
	if r.Code != 200 || got.Get("Cookie") != "uid=a; theme=dark" || got.Get("User-Agent") != "Mozilla/5.0 buyer" || got.Get("Origin") != "https://shop.test" {
		t.Fatalf("status %d upstream headers %v", r.Code, got)
	}
	if got.Get("Referer") != "" || got.Get("X-Forwarded-For") != "" {
		t.Errorf("unlisted client header forwarded: %v", got)
	}
	if sc := r.Header().Values("Set-Cookie"); len(sc) != 2 || sc[0] != "uid=a" || sc[1] != "csrf=x" {
		t.Errorf("Set-Cookie %v", sc)
	}
	if r = call(g, "GET", "/", "shop.test", "", http.Header{}); r.Code != 200 || got.Get("User-Agent") != "dsmack-egress/1" {
		t.Errorf("no client User-Agent: %d %q", r.Code, got.Get("User-Agent"))
	}

	g, _ = withFixture(t, fetchPolicy(), "shop.test", handler)
	r = call(g, "GET", "/exact", "shop.test", "", http.Header{"Cookie": {"uid=a"}, "User-Agent": {"Mozilla/5.0 buyer"}})
	if r.Code != 200 || got.Get("Cookie") != "" || got.Get("User-Agent") != "Mozilla/5.0 resip" || len(r.Header().Values("Set-Cookie")) != 0 {
		t.Errorf("rule without cookies: status %d upstream %v response %v", r.Code, got, r.Header())
	}

	for _, h := range []string{"Cookie", "host", "Authorization", "X-Api-Key", "Content-Type", "Accept-Encoding", "X-Forwarded-For", "Proxy-Authorization", "Sec-WebSocket-Key", "Transfer-Encoding", "Bad Header", ""} {
		p := sessionPolicy()
		p.Rules[0].ClientHeaders = []string{h}
		if _, err := loadPolicy(mustJSON(t, p)); err == nil {
			t.Errorf("accepted client header %q", h)
		}
	}
	p := sessionPolicy()
	p.Rules[0].Headers = map[string]string{"User-Agent": "fixed"}
	if _, err := loadPolicy(mustJSON(t, p)); err == nil {
		t.Error("accepted User-Agent as both fixed and client header")
	}
}

func TestAccountCountersAndCaps(t *testing.T) {
	hits := 0
	g, _ := withFixture(t, sessionPolicy(), "shop.test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	cookie := func(v string) http.Header { return http.Header{"Cookie": {"uid=" + v + "; theme=dark"}} }
	for _, c := range []struct {
		method, target, host string
		headers              http.Header
		status               int
		account              string
	}{
		{"GET", "/", "shop.test", nil, 200, "sessions=0 logins=0 signups=0 posts_last_hour=0"},
		{"POST", "/login", "shop.test", cookie("a"), 200, "sessions=1 logins=1 signups=0 posts_last_hour=0"},
		{"GET", "/feed", "shop.test", cookie("a"), 200, "sessions=1 logins=1 signups=0 posts_last_hour=0"},
		{"GET", "/feed", "shop.test", cookie("b"), 403, "sessions=1 logins=1 signups=0 posts_last_hour=0"},
		{"GET", "/feed", "www.shop.test", cookie("b"), 403, "sessions=1 logins=1 signups=0 posts_last_hour=0"},
		{"GET", "/signup", "shop.test", nil, 200, "sessions=1 logins=1 signups=0 posts_last_hour=0"},
		{"POST", "/signup", "shop.test", nil, 403, "sessions=1 logins=1 signups=0 posts_last_hour=0"},
		{"POST", "/join/now", "shop.test", nil, 403, "sessions=1 logins=1 signups=0 posts_last_hour=0"},
		{"POST", "/post/1", "shop.test", cookie("a"), 200, "sessions=1 logins=1 signups=0 posts_last_hour=1"},
		{"POST", "/post/2", "shop.test", cookie("a"), 200, "sessions=1 logins=1 signups=0 posts_last_hour=2"},
		{"GET", "/post/3", "shop.test", cookie("a"), 200, "sessions=1 logins=1 signups=0 posts_last_hour=2"},
		{"POST", "/post/3", "shop.test", cookie("a"), 403, "sessions=1 logins=1 signups=0 posts_last_hour=2"},
	} {
		r := call(g, c.method, c.target, c.host, "", c.headers)
		if r.Code != c.status || r.Header().Get("X-Dsmack-Account") != c.account {
			t.Errorf("%s %s%s: %d %q %q", c.method, c.host, c.target, r.Code, r.Header().Get("X-Dsmack-Account"), r.Body.String())
		}
	}
	for target, reason := range map[string]string{"/feed": "account_session_cap", "/signup": "account_signup_policy", "/post/3": "account_post_rate"} {
		h := cookie("a")
		if target == "/feed" {
			h = cookie("b")
		}
		if r := call(g, "POST", target, "shop.test", "", h); strings.TrimSpace(r.Body.String()) != reason {
			t.Errorf("%s: %q", target, r.Body.String())
		}
	}
	if hits != 7 || g.usage[0].requests != 7 {
		t.Errorf("refused requests reached the origin or used budget: hits=%d requests=%d", hits, g.usage[0].requests)
	}
	g.counters["shop.test"].posts[0] = time.Now().Add(-time.Hour)
	if r := call(g, "POST", "/post/3", "shop.test", "", cookie("a")); r.Code != 200 {
		t.Errorf("post window did not slide: %d", r.Code)
	}

	p := sessionPolicy()
	p.Rules[0].Account = nil
	g, _ = withFixture(t, p, "shop.test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	for _, v := range []string{"a", "b", "c"} {
		if r := call(g, "POST", "/signup", "shop.test", "", cookie(v)); r.Code != 200 || r.Header().Get("X-Dsmack-Account") != "" {
			t.Errorf("rule without account: %d %v", r.Code, r.Header())
		}
	}

	for name, edit := range map[string]func(*Account){
		"sessions without cap": func(a *Account) { a.MaxSessions = 0 },
		"posts without cap":    func(a *Account) { a.MaxPostsPerHour = 0 },
		"cookie name":          func(a *Account) { a.SessionCookies = []string{"uid=x"} },
		"glob":                 func(a *Account) { a.PostPaths = []string{"post/*"} },
		"bad glob":             func(a *Account) { a.LoginPaths = []string{"/login["} },
		"group mismatch":       func(a *Account) { a.Signup = true },
	} {
		p := sessionPolicy()
		edit(p.Rules[1].Account)
		if _, err := loadPolicy(mustJSON(t, p)); err == nil {
			t.Errorf("accepted %s", name)
		}
	}
	p = sessionPolicy()
	p.Rules[0].Account.Group, p.Rules[1].Account.Group = "", ""
	p.Rules[1].Account.Signup = true
	loaded, err := loadPolicy(mustJSON(t, p))
	if err != nil || loaded.Rules[0].Account.Group != "shop.test" || loaded.Rules[1].Account.Group != "*.shop.test" {
		t.Errorf("default groups: %v", err)
	}
}

func TestHTTP2Origin(t *testing.T) {
	proto := ""
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proto = r.Proto
		http.SetCookie(w, &http.Cookie{Name: "uid", Value: "a"})
		io.WriteString(w, "h2 body")
	})
	p := sessionPolicy()
	p.Rules[0].HTTP2 = true
	g, logs := withFixture(t, p, "shop.test", handler)
	for i := 0; i < 2; i++ {
		r := call(g, "GET", "/a?b=c", "shop.test", "", nil)
		if r.Code != 200 || proto != "HTTP/2.0" || r.Body.String() != "h2 body" || r.Header().Get("X-Dsmack-Body-Bytes") != "7" ||
			r.Header().Get("X-Dsmack-Cert-Sha256") == "" || r.Header().Get("Set-Cookie") != "uid=a" {
			t.Fatalf("status %d proto %s headers %v logs %s", r.Code, proto, r.Header(), logs)
		}
	}
	g, _ = withFixture(t, sessionPolicy(), "shop.test", handler)
	if r := call(g, "GET", "/", "shop.test", "", nil); r.Code != 200 || proto != "HTTP/1.1" {
		t.Errorf("rule without http2 used %s", proto)
	}
}

func TestWebSocketOnSessionRule(t *testing.T) {
	p := sessionPolicy()
	p.Rules[0].HTTP2 = true
	p.Rules[0].WebSocketSeconds = 2
	upgrade := make(chan http.Header, 1)
	g, _ := withFixture(t, p, "shop.test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrade <- r.Header.Clone()
		c, b, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer c.Close()
		b.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: test\r\n\r\n")
		b.Flush()
		io.Copy(c, b)
	}))
	logs := &lockedBuffer{}
	g.audit.SetOutput(logs)
	local := httptest.NewServer(g)
	defer local.Close()
	c, err := net.Dial("tcp", strings.TrimPrefix(local.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	io.WriteString(c, "GET /ws HTTP/1.1\r\nHost: shop.test:8080\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nCookie: uid=a\r\nOrigin: https://shop.test\r\n\r\n")
	b := bufio.NewReader(c)
	resp, err := http.ReadResponse(b, nil)
	if err != nil || resp.StatusCode != 101 || resp.Header.Get("X-Dsmack-Stream") != "1" {
		t.Fatalf("%v %v", resp, err)
	}
	if h := <-upgrade; h.Get("Cookie") != "uid=a" || h.Get("Origin") != "https://shop.test" {
		t.Errorf("upgrade headers %v", h)
	}
	c.Write([]byte("hello"))
	got := make([]byte, 5)
	if _, err = io.ReadFull(b, got); err != nil || string(got) != "hello" {
		t.Fatalf("echo %q %v", got, err)
	}
	c.Close()
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(logs.String(), `"complete"`) {
		if time.Now().After(deadline) {
			t.Fatal("no completion record")
		}
		time.Sleep(10 * time.Millisecond)
	}
	var done evidence
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		json.Unmarshal([]byte(line), &done)
	}
	if done.Decision != "complete" || done.Stream != 1 || done.Upload < 5 || done.Download < 5 {
		t.Errorf("completion %+v", done)
	}
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func mustJSON(t *testing.T, v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
