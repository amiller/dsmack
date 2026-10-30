package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

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
