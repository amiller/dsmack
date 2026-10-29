package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
 "net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func policy() Policy {
	return Policy{Rules: []Rule{{Name: "allowed.test", Port: 443, Methods: []string{"GET", "POST"}, Paths: []string{"/", "/redirect"}, MaxRequestBytes: 512, MaxResponseBytes: 1024, UploadBytes: 2048, DownloadBytes: 4096, Requests: 4, RequestsPerMinute: 60000}}}
}
func fixture(t *testing.T, name string, h http.Handler) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	s := httptest.NewUnstartedServer(h)
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s, roots
}
func withFixture(t *testing.T, p Policy, name string, h http.Handler) (*gateway, *bytes.Buffer) {
	s, roots := fixture(t, name, h)
	var logs bytes.Buffer
	g := newGateway(p, log.New(&logs, "", 0))
	g.client.TLSClientConfig.RootCAs = roots
	g.client.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, s.Listener.Addr().String())
	}
	return g, &logs
}
func call(g *gateway, method, target, host, body string, headers http.Header) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.Host = host
	if headers != nil {
		r.Header = headers
	}
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	return w
}
func TestUpstreamUsesOneAuthenticatedAuthority(t *testing.T) {
	var hits atomic.Int32
	g, logs := withFixture(t, policy(), "allowed.test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.TLS.ServerName != "allowed.test" || r.Host != "allowed.test" {
			t.Errorf("authority mismatch: %s %s", r.TLS.ServerName, r.Host)
		}
		if r.Header.Get("X-Forwarded-Host") != "" || r.Header.Get("Proxy-Authorization") != "" {
			t.Error("routing header escaped")
		}
		io.WriteString(w, "ok")
	}))
	r := call(g, "POST", "/", "allowed.test:8080", "body-secret", http.Header{"Authorization": {"key-secret"}, "X-Forwarded-Host": {"blocked.test"}, "Proxy-Authorization": {"proxy-secret"}})
	if r.Code != 200 || hits.Load() != 1 {
		t.Fatalf("status=%d hits=%d", r.Code, hits.Load())
	}
	for _, secret := range []string{"body-secret", "key-secret", "proxy-secret", "blocked.test", "allowed.test"} {
		if strings.Contains(logs.String(), secret) {
			t.Error("log contained request data")
		}
	}
}
func TestHostControlledRoutingCannotReplaceTLSIdentity(t *testing.T) {
	for _, trusted := range []bool{true, false} {
		t.Run(map[bool]string{true: "wrong_name", false: "untrusted_chain"}[trusted], func(t *testing.T) {
			var hits atomic.Int32
			name := "wrong.test"
			if !trusted {
				name = "allowed.test"
			}
			g, _ := withFixture(t, policy(), name, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
			if !trusted {
				g.client.TLSClientConfig.RootCAs = x509.NewCertPool()
			}
			r := call(g, "GET", "/", "allowed.test", "", nil)
			if r.Code != 502 || hits.Load() != 0 {
				t.Fatalf("status=%d hits=%d", r.Code, hits.Load())
			}
		})
	}
}
func TestFrontingLiteralsAndTunnelsNeverReachUpstream(t *testing.T) {
	var hits atomic.Int32
	g, _ := withFixture(t, policy(), "allowed.test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	cases := []struct {
		method, target, host string
		headers              http.Header
	}{
		{"GET", "/", "blocked.test", nil},
		{"GET", "https://allowed.test/", "blocked.test", nil},
		{"GET", "https://blocked.test/", "allowed.test", nil},
		{"CONNECT", "/", "allowed.test", nil},
		{"GET", "/", "104.18.0.1", nil},
		{"GET", "/", "[2606:4700::1]:8080", nil},
		{"GET", "/", "allowed.test:443", nil},
		{"GET", "/", "secret.allowed.test", nil},
		{"GET", "/", "allowed.test.", nil},
		{"GET", "/", "allowed.test", http.Header{"Upgrade": {"websocket"}}},
		{"GET", "/?secret=abc", "allowed.test", nil},
		{"GET", "/%2e%2e/", "allowed.test", nil},
		{"GET", "/forbidden", "allowed.test", nil},
		{"DELETE", "/", "allowed.test", nil},
	}
	for _, c := range cases {
		if r := call(g, c.method, c.target, c.host, "", c.headers); r.Code != 403 {
			t.Errorf("%+v: %d", c, r.Code)
		}
	}
	if hits.Load() != 0 {
		t.Fatal("denied request reached shared address")
	}
}
func TestRedirectNotFollowedAndRequestBudgetPersists(t *testing.T) {
	p := policy()
	p.Rules[0].Requests = 1
	var hits atomic.Int32
	g, _ := withFixture(t, p, "allowed.test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Location", "https://blocked.test/secret")
		w.WriteHeader(302)
	}))
	if r := call(g, "GET", "/redirect", "allowed.test", "", nil); r.Code != 302 {
		t.Fatal(r.Code)
	}
	g.mu.Lock()
	g.usage[0].last = time.Now().Add(-time.Minute)
	g.mu.Unlock()
	if r := call(g, "GET", "/", "allowed.test", "", nil); r.Code != 429 || hits.Load() != 1 {
		t.Fatalf("status=%d hits=%d", r.Code, hits.Load())
	}
}
func TestByteBudgetsIncludeHeadersAndRejectOversizeResponses(t *testing.T) {
	t.Run("request_header", func(t *testing.T) {
		var hits atomic.Int32
		g, _ := withFixture(t, policy(), "allowed.test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
		r := call(g, "GET", "/", "allowed.test", "", http.Header{"Authorization": {strings.Repeat("x", 513)}})
		if r.Code != 413 || hits.Load() != 0 {
			t.Fatal("oversized header escaped")
		}
	})
	t.Run("response", func(t *testing.T) {
		g, _ := withFixture(t, policy(), "allowed.test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, strings.Repeat("x", 1025)) }))
		if r := call(g, "GET", "/", "allowed.test", "", nil); r.Code != 502 || strings.Contains(r.Body.String(), "xxxx") {
			t.Fatal("oversized response delivered")
		}
	})
	t.Run("upload_total", func(t *testing.T) {
		p := policy()
		p.Rules[0].UploadBytes = 512
		g, _ := withFixture(t, p, "allowed.test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.Copy(io.Discard, r.Body); io.WriteString(w, "ok") }))
		if r := call(g, "POST", "/", "allowed.test", strings.Repeat("x", 300), nil); r.Code != 200 {
			t.Fatal(r.Code)
		}
		g.mu.Lock()
		g.usage[0].last = time.Now().Add(-time.Minute)
		g.mu.Unlock()
		if r := call(g, "POST", "/", "allowed.test", strings.Repeat("x", 300), nil); r.Code != 429 {
			t.Fatal(r.Code)
		}
	})
	t.Run("concurrent_reservation", func(t *testing.T) {
		p := policy()
		p.Rules[0].DownloadBytes = 1024
		g := newGateway(p, log.New(io.Discard, "", 0))
		var accepted atomic.Int32
		var wg sync.WaitGroup
		for j := 0; j < 10; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if g.reserve(0, 100) {
					accepted.Add(1)
				}
			}()
		}
		wg.Wait()
		if accepted.Load() != 1 {
			t.Fatalf("reservations=%d", accepted.Load())
		}
	})
	t.Run("rate", func(t *testing.T) {
		p := policy()
		p.Rules[0].RequestsPerMinute = 1
		g := newGateway(p, log.New(io.Discard, "", 0))
		if !g.reserve(0, 1) || g.reserve(0, 1) {
			t.Fatal("initial burst is one request")
		}
	})
}
func query(name string, typ uint16) []byte {
	q := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, s := range strings.Split(name, ".") {
		q = append(q, byte(len(s)))
		q = append(q, s...)
	}
	q = append(q, 0, byte(typ>>8), byte(typ), 0, 1)
	return q
}
func TestDNSIsExactAndNeverForwardsWorkloadQueries(t *testing.T) {
	g := newGateway(policy(), log.New(io.Discard, "", 0))
	ip := net.ParseIP("192.0.2.2")
	for _, c := range []struct {
		name          string
		typ           uint16
		code, answers uint16
	}{{"allowed.test", 1, 0, 1}, {"ALLOWED.test", 1, 0, 1}, {"allowed.test", 28, 0, 0}, {"blocked.test", 1, 5, 0}, {"secret.allowed.test", 16, 5, 0}} {
		a := g.dnsReply(query(c.name, c.typ), ip)
		if len(a) < 12 || binary.BigEndian.Uint16(a[2:4])&15 != c.code || binary.BigEndian.Uint16(a[6:8]) != c.answers {
			t.Fatalf("%+v: %x", c, a)
		}
	}
	for _, q := range [][]byte{nil, bytes.Repeat([]byte{0}, 600), {0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c}} {
		if g.dnsReply(q, ip) != nil {
			t.Fatal("malformed query accepted")
		}
	}
}

// Prevent an allowed WebSocket from bypassing TLS identity or byte accounting.
func TestWebSocketTLSAndByteBudget(t *testing.T) {
	p := policy()
	p.Rules[0].WebSocketSeconds = 2
	p.Rules[0].MaxRequestBytes = 512
	g, _ := withFixture(t, p, "allowed.test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "allowed.test" || r.TLS.ServerName != "allowed.test" {
			t.Error("WebSocket authority changed")
		}
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
	local := httptest.NewServer(g)
	defer local.Close()
	c, err := net.Dial("tcp", strings.TrimPrefix(local.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	io.WriteString(c, "GET / HTTP/1.1\r\nHost: allowed.test:8080\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
	b := bufio.NewReader(c)
	resp, err := http.ReadResponse(b, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 101 {
		t.Fatal(resp.StatusCode)
	}
	c.Write([]byte("Noise bytes"))
	got := make([]byte, 11)
	if _, err = io.ReadFull(b, got); err != nil || string(got) != "Noise bytes" {
		t.Fatalf("echo: %s %v", got, err)
	}
	c.Write(bytes.Repeat([]byte("x"), 1024))
	io.Copy(io.Discard, b)
	c.Close()
	deadline := time.Now().Add(time.Second)
	for {
		g.mu.Lock()
		up, down := g.usage[0].upload, g.usage[0].download
		g.mu.Unlock()
		if down < 1024 {
			if up != 512 {
				t.Fatalf("upload cap = %d", up)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("gateway failed to release connection budget")
		}
		time.Sleep(time.Millisecond)
	}
}

// A suffix match must not authorize another zone, a nested name, or an IP.
func TestOneLabelWildcard(t *testing.T) {
	p := policy()
	p.Rules[0].Name = "*.trycloudflare.com"
	g := newGateway(p, log.New(io.Discard, "", 0))
	for _, host := range []string{"x.trycloudflare.com"} {
		if g.index(host) != 0 {
			t.Fatal(host)
		}
	}
	for _, host := range []string{"trycloudflare.com", "x.y.trycloudflare.com", "x.trycloudflare.com.evil.test", "eviltrycloudflare.com", "1.1.1.1"} {
		if g.index(host) != -1 {
			t.Fatal(host)
		}
	}
}

// A transport proxy may route a CONNECT tunnel, but must never receive model
// authorization or request bytes before the gateway authenticates provider TLS.
func TestConnectProxyCarriesOnlyProviderTLS(t *testing.T) {
	for _, name := range []string{"allowed.test", "wrong.test"} {
		t.Run(name, func(t *testing.T) {
			var hits atomic.Int32
			upstream, roots := fixture(t, name, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				if r.TLS.ServerName != "allowed.test" || r.Header.Get("Authorization") != "key-secret" {
					t.Error("provider identity or credential")
				}
				io.WriteString(w, "ok")
			}))
			wire := make(chan []byte, 1)
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "CONNECT" || r.Host != "allowed.test:443" {
					t.Error("wrong tunnel target")
					w.WriteHeader(403)
					return
				}
				tunnel, err := net.Dial("tcp", upstream.Listener.Addr().String())
				if err != nil {
					t.Error(err)
					return
				}
				client, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					tunnel.Close()
					t.Error(err)
					return
				}
				io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
				var observed bytes.Buffer
				done := make(chan struct{})
				go func() { io.Copy(tunnel, io.TeeReader(client, &observed)); close(done) }()
				io.Copy(client, tunnel)
				client.Close()
				tunnel.Close()
				<-done
				wire <- observed.Bytes()
			}))
			defer proxy.Close()
			g := newGateway(policy(), log.New(io.Discard, "", 0))
			g.client.TLSClientConfig.RootCAs = roots
			proxyURL, _ := url.Parse(proxy.URL)
			g.client.Proxy = http.ProxyURL(proxyURL)
			r := call(g, "POST", "/", "allowed.test:8080", "body-secret", http.Header{"Authorization": {"key-secret"}})
			expectedStatus, expectedHits := 200, int32(1)
			if name != "allowed.test" {
				expectedStatus, expectedHits = 502, 0
			}
			if r.Code != expectedStatus || hits.Load() != expectedHits {
				t.Fatalf("status=%d hits=%d", r.Code, hits.Load())
			}
			select {
			case raw := <-wire:
				if len(raw) == 0 || bytes.Contains(raw, []byte("key-secret")) || bytes.Contains(raw, []byte("body-secret")) {
					t.Fatal("plaintext crossed CONNECT transport")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("tunnel did not close")
			}
		})
	}
}
