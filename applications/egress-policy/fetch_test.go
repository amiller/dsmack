package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"testing"
)

func fetchPolicy() Policy {
	return Policy{Rules: []Rule{{Name: "shop.test", Port: 443, Methods: []string{"GET"}, Paths: []string{"/exact"},
		PathPrefixes: []string{"/products/"}, PathGlobs: []string{"/c/*/list"}, Query: true, DropCredentials: true,
		Headers:         map[string]string{"user-agent": "Mozilla/5.0 resip", "Accept-Language": "en-US"},
		MaxRequestBytes: 4096, MaxResponseBytes: 1024, UploadBytes: 1 << 16, DownloadBytes: 1 << 16, Requests: 32, RequestsPerMinute: unpaced}}}
}

func TestPathPrefixesGlobsAndQuery(t *testing.T) {
	var seen []string
	g, _ := withFixture(t, fetchPolicy(), "shop.test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.RequestURI())
	}))
	for target, want := range map[string]int{
		"/exact": 200, "/exact?q=1": 200, "/products/": 200, "/products/a/b?page=2&s=x": 200, "/c/shoes/list": 200,
		"/productsx": 403, "/products": 403, "/c/a/b/list": 403, "/other": 403, "/products/../admin": 403,
	} {
		if r := call(g, "GET", target, "shop.test", "", nil); r.Code != want {
			t.Errorf("%s: status %d, want %d", target, r.Code, want)
		}
	}
	if !contains(seen, "/products/a/b?page=2&s=x") {
		t.Errorf("query not forwarded verbatim: %v", seen)
	}
	p := policy()
	g2, _ := withFixture(t, p, "allowed.test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	if r := call(g2, "GET", "/?q=1", "allowed.test", "", nil); r.Code != 403 {
		t.Errorf("query allowed without query:true: %d", r.Code)
	}
}

func TestHeaderPolicyAndCredentialDrop(t *testing.T) {
	g, _ := withFixture(t, fetchPolicy(), "shop.test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "Mozilla/5.0 resip" || r.Header.Get("Accept-Language") != "en-US" {
			t.Errorf("headers %v", r.Header)
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-Api-Key") != "" {
			t.Error("credential header forwarded")
		}
	}))
	if r := call(g, "GET", "/exact", "shop.test", "", http.Header{"Authorization": {"secret"}, "X-Api-Key": {"k"}, "User-Agent": {"client"}}); r.Code != 200 {
		t.Fatal(r.Code)
	}
	for _, h := range []map[string]string{{"Cookie": "a"}, {"Host": "x"}, {"User-Agent": "a\r\nX: y"}} {
		p := fetchPolicy()
		p.Rules[0].Headers = h
		b, _ := json.Marshal(p)
		if _, err := loadPolicy(b); err == nil {
			t.Errorf("accepted header policy %v", h)
		}
	}
}

func TestEvidenceComesFromUpstreamConnection(t *testing.T) {
	s, roots := fixture(t, "shop.test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "page body") }))
	var logs strings.Builder
	g := newGateway(fetchPolicy(), log.New(&logs, "", 0))
	g.client.TLSClientConfig.RootCAs = roots
	g.client.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, s.Listener.Addr().String())
	}
	r := call(g, "GET", "/exact?q=secret-query", "shop.test", "", nil)
	leaf, body := sha256.Sum256(s.TLS.Certificates[0].Certificate[0]), sha256.Sum256([]byte("page body"))
	if r.Code != 200 || r.Header().Get("X-Dsmack-Cert-Sha256") != hex.EncodeToString(leaf[:]) ||
		r.Header().Get("X-Dsmack-Body-Sha256") != hex.EncodeToString(body[:]) || r.Header().Get("X-Dsmack-Body-Bytes") != "9" {
		t.Fatalf("status %d headers %v", r.Code, r.Header())
	}
	var e evidence
	if err := json.Unmarshal([]byte(strings.TrimSpace(logs.String())), &e); err != nil {
		t.Fatal(err)
	}
	if e.CertSHA256 != hex.EncodeToString(leaf[:]) || e.BodySHA256 != hex.EncodeToString(body[:]) || e.BodyBytes != 9 || e.Status != 200 {
		t.Errorf("audit %+v", e)
	}
	if strings.Contains(logs.String(), "secret-query") || strings.Contains(logs.String(), "shop.test") {
		t.Error("audit log contains request data")
	}
}
