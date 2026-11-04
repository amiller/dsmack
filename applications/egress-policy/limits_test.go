package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBurst(t *testing.T) {
	p := policy()
	p.Rules[0].RequestsPerMinute = 1
	p.Rules[0].Requests = 10
	p.Rules[0].DownloadBytes = 1 << 20
	p.Rules[0].Burst = 3
	loaded, err := loadPolicy(mustJSON(t, p))
	if err != nil || loaded.Rules[0].Burst != 3 {
		t.Fatal(loaded.Rules[0].Burst, err)
	}
	g := newGateway(loaded, log.New(io.Discard, "", 0))
	for j := 0; j < 3; j++ {
		if _, refused, _ := g.reserve(0, 1, hit{}); refused != "" {
			t.Fatalf("request %d refused: %s", j, refused)
		}
	}
	if _, refused, _ := g.reserve(0, 1, hit{}); refused != "budget_or_rate" {
		t.Fatal("burst of 3 allowed a fourth request")
	}
	g.mu.Lock()
	g.usage[0].last = time.Now().Add(-time.Hour)
	g.mu.Unlock()
	for j := 0; j < 3; j++ {
		if _, refused, _ := g.reserve(0, 1, hit{}); refused != "" {
			t.Fatalf("refilled request %d refused: %s", j, refused)
		}
	}
	if _, refused, _ := g.reserve(0, 1, hit{}); refused != "budget_or_rate" {
		t.Fatal("bucket refilled past its burst")
	}
	for _, b := range []int{-1, 11} {
		p.Rules[0].Burst = b
		if _, err := loadPolicy(mustJSON(t, p)); err == nil {
			t.Fatalf("burst %d accepted", b)
		}
	}
}

func TestWebSocketMetersBudgetWithConcurrentRequests(t *testing.T) {
	p := policy()
	p.Rules[0].Paths = []string{"/", "/ws"}
	p.Rules[0].WebSocketSeconds = 5
	p.Rules[0].UploadBytes = 64 << 10
	p.Rules[0].DownloadBytes = 64 << 10
	p.Rules[0].Requests = 1000
	g, _ := withFixture(t, p, "allowed.test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ws" {
			io.WriteString(w, strings.Repeat("y", 900))
			return
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
	logs := &lockedBuffer{}
	g.audit.SetOutput(logs)
	local := httptest.NewServer(g)
	defer local.Close()
	c, err := net.Dial("tcp", strings.TrimPrefix(local.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(c, "GET /ws HTTP/1.1\r\nHost: allowed.test:8080\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
	b := bufio.NewReader(c)
	resp, err := http.ReadResponse(b, nil)
	if err != nil || resp.StatusCode != 101 {
		t.Fatal(resp, err)
	}
	get := func() int { return call(g, "GET", "/", "allowed.test", "", nil).Code }
	var wg sync.WaitGroup
	codes := make(chan int, 10)
	for j := 0; j < 10; j++ {
		wg.Add(1)
		go func() { defer wg.Done(); codes <- get() }()
	}
	wg.Wait()
	close(codes)
	for code := range codes {
		if code != 200 {
			t.Fatalf("request beside an open WebSocket got %d", code)
		}
	}

	// Push twice the budget through the stream while requests keep running.
	echoed := make(chan int, 1)
	go func() { n, _ := io.Copy(io.Discard, b); echoed <- int(n) }()
	go func() {
		for j := 0; j < 32; j++ {
			if _, err := c.Write(bytes.Repeat([]byte("x"), 4<<10)); err != nil {
				return
			}
		}
	}()
	for j := 0; j < 4; j++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for get() == 200 {
			}
		}()
	}
	wg.Wait()
	if n := <-echoed; n >= 128<<10 {
		t.Fatalf("stream carried %d bytes past the budget", n)
	}
	if code := get(); code != 429 {
		t.Fatalf("spent budget answered %d", code)
	}

	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(logs.String(), `"complete"`) {
		if time.Now().After(deadline) {
			t.Fatal("no completion record")
		}
		time.Sleep(10 * time.Millisecond)
	}
	var up, down int64
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var e evidence
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		if e.Reason == "validated_tls" || e.Decision == "complete" {
			up += e.Upload
			down += e.Download
		}
	}
	g.mu.Lock()
	u := g.usage[0]
	g.mu.Unlock()
	if u.upload > p.Rules[0].UploadBytes || u.download > p.Rules[0].DownloadBytes {
		t.Fatalf("usage %d/%d over budget", u.upload, u.download)
	}
	if u.upload != up || u.download != down {
		t.Fatalf("usage %d/%d, audit %d/%d", u.upload, u.download, up, down)
	}
}
