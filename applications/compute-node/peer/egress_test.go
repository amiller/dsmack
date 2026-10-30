package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

func TestBrokerGatewayKeepsAuthorityAndOriginForm(t *testing.T) {
	var calls atomic.Int32
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		if r.Host != "broker.invalid" || r.RequestURI != "/relay-broker/nodes" || r.URL.IsAbs() || r.TLS != nil ||
			r.Method != "POST" || string(body) != `{"node":"public"}` || r.Header.Get("Authorization") != "Bearer fixture" {
			t.Errorf("gateway lost broker authority, origin form, method or payload")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"registered":true}`))
	}))
	defer gateway.Close()
	t.Setenv("BROKER_GATEWAY", gateway.URL)
	t.Setenv("BROKER_IP", "192.0.2.1")
	t.Setenv("HTTPS_PROXY", "http://192.0.2.2:1")
	t.Setenv("HTTP_PROXY", "http://192.0.2.2:1")
	client, err := brokerClient("https://broker.invalid/relay-broker")
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest("POST", "https://broker.invalid/relay-broker/nodes", strings.NewReader(`{"node":"public"}`))
	request.Header.Set("Authorization", "Bearer fixture")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	for _, address := range []string{"https://other.invalid/relay-broker/nodes", "https://broker.invalid:444/relay-broker/nodes", "http://broker.invalid/relay-broker/nodes"} {
		if _, err := client.Get(address); err == nil {
			t.Fatal("unmeasured broker authority accepted", address)
		}
	}
	request, _ = http.NewRequest("POST", "https://broker.invalid/relay-broker/nodes", nil)
	request.Host = "other.invalid"
	if _, err := client.Do(request); err == nil {
		t.Fatal("conflicting Host accepted")
	}
	if calls.Load() != 1 {
		t.Fatal("rejected requests reached the gateway")
	}
}

func TestTunnelSelectionUsesMeasuredRelayAndNewestLiveLocator(t *testing.T) {
	measured, err := peer.Decode("12D3KooWPXeq29kZzJxDgCA92X16PSiM5Bv1XxAshJ8wJzYv9k6x")
	if err != nil {
		t.Fatal(err)
	}
	hints := []tunnelHint{{URL: "wss://expired.trycloudflare.com/", RelayPeer: measured.String(), ExpiresAt: 10},
		{URL: "wss://other.trycloudflare.com/", RelayPeer: "other-peer", ExpiresAt: 100},
		{URL: "wss://old.trycloudflare.com/", RelayPeer: measured.String(), ExpiresAt: 90},
		{URL: "wss://current.trycloudflare.com/", RelayPeer: measured.String(), ExpiresAt: 100}}
	raw, _ := json.Marshal(hints)
	host, err := selectTunnel(raw, measured, 20)
	if err != nil || host != "current.trycloudflare.com" {
		t.Fatalf("live locator selection: %q %v", host, err)
	}
	if _, err := selectTunnel(raw, measured, 100); err == nil {
		t.Fatal("expired locator accepted")
	}
	hints[3].URL = "wss://nested.current.trycloudflare.com/"
	raw, _ = json.Marshal(hints)
	if _, err := selectTunnel(raw, measured, 20); err == nil {
		t.Fatal("non-single-label tunnel authority accepted")
	}
}

// Metering and renewal can become ready on the same tick. The measured gateway
// accepts one request per refill, so concurrency must not spend the same token.
func TestBrokerGatewayPacesAdjacentReceiptAndRenewalAndCancelsWaiting(t *testing.T) {
	var mu sync.Mutex
	var arrivals []time.Time
	var paths []string
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		now := time.Now()
		accepted := len(arrivals) == 0 || now.Sub(arrivals[len(arrivals)-1]) >= time.Minute/120
		arrivals = append(arrivals, now)
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		if !accepted {
			http.Error(w, "budget_or_rate", http.StatusTooManyRequests)
			return
		}
		io.WriteString(w, `{"accepted":true}`)
	}))
	defer gateway.Close()
	t.Setenv("BROKER_GATEWAY", gateway.URL)
	client, err := brokerClient("https://broker.invalid/relay-broker")
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	for _, path := range []string{"/agent/receipt", "/nodes"} {
		go func(path string) {
			response, err := client.Post("https://broker.invalid/relay-broker"+path, "application/json", strings.NewReader(`{}`))
			if err == nil {
				response.Body.Close()
				if response.StatusCode != http.StatusOK {
					err = fmt.Errorf("broker gateway refused adjacent %s: %d", path, response.StatusCode)
				}
			}
			results <- err
		}(path)
	}
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, "POST", "https://broker.invalid/relay-broker/agent/receipt", strings.NewReader(`{}`))
	if _, err = client.Do(request); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting request ignored cancellation: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(arrivals) != 2 {
		t.Fatal("cancelled request reached the gateway", paths)
	}
	if arrivals[1].Sub(arrivals[0]) < time.Minute/120 {
		t.Fatal("receipt and renewal reused one gateway token")
	}
}
