package p2p

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	ma "github.com/multiformats/go-multiaddr"
)

func TestBrokerCanUseOutboundHTTPRelayForPrivateCircuit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	broker, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"), libp2p.EnableRelay())
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()
	addr, err := broker.Addrs()[0].ValueForProtocol(ma.P_TCP)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	channels := map[string]net.Conn{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "/relay-broker/sandbox/p2p"
		if r.Method == "POST" && r.URL.Path == prefix+"/open" {
			conn, err := net.Dial("tcp", "127.0.0.1:"+addr)
			if err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
			id := strings.Repeat("ab", 32)
			mu.Lock()
			channels[id] = conn
			mu.Unlock()
			io.WriteString(w, `{"id":"`+id+`"}`)
			return
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, prefix+"/"), "/")
		mu.Lock()
		conn := channels[parts[0]]
		mu.Unlock()
		if conn == nil {
			w.WriteHeader(404)
			return
		}
		if r.Method == "DELETE" {
			conn.Close()
			mu.Lock()
			delete(channels, parts[0])
			mu.Unlock()
			w.WriteHeader(204)
			return
		}
		if len(parts) != 2 {
			w.WriteHeader(404)
			return
		}
		if r.Method == "POST" && parts[1] == "send" {
			raw, err := io.ReadAll(io.LimitReader(r.Body, (64<<10)+1))
			if err != nil || len(raw) > 64<<10 {
				w.WriteHeader(400)
				return
			}
			if _, err := conn.Write(raw); err != nil {
				w.WriteHeader(500)
				return
			}
			w.WriteHeader(204)
			return
		}
		if r.Method == "GET" && parts[1] == "recv" {
			conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			raw := make([]byte, 64<<10)
			n, err := conn.Read(raw)
			if n > 0 {
				w.Write(raw[:n])
				return
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				w.WriteHeader(204)
				return
			}
			w.WriteHeader(404)
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()
	operator, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"), libp2p.ForceReachabilityPublic(), libp2p.DisableRelay())
	if err != nil {
		t.Fatal(err)
	}
	defer operator.Close()
	r, err := relay.New(operator, relay.WithInfiniteLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := MaintainBackhaul(ctx, operator, server.URL+"/relay-broker/sandbox/p2p", broker.ID().String()); err != nil {
		t.Fatal(err)
	}
	for broker.Network().Connectedness(operator.ID()) != network.Connected {
		select {
		case <-ctx.Done():
			t.Fatal("outbound relay did not authenticate")
		case <-time.After(10 * time.Millisecond):
		}
	}
	guest, err := libp2p.New(libp2p.NoListenAddrs, libp2p.EnableRelay())
	if err != nil {
		t.Fatal(err)
	}
	defer guest.Close()
	guest.SetStreamHandler("/dsmack/backhaul-check/1", func(s network.Stream) { defer s.Close(); io.Copy(s, s) })
	info := peer.AddrInfo{ID: operator.ID(), Addrs: operator.Addrs()}
	if err := guest.Connect(ctx, info); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Reserve(ctx, guest, info); err != nil {
		t.Fatal(err)
	}
	// The broker cannot route to this address. Its existing authenticated relay
	// connection must carry the circuit reservation and the guest stream.
	circuit := ma.StringCast("/ip4/192.0.2.77/tcp/4033/p2p/" + operator.ID().String() + "/p2p-circuit")
	if err := broker.Connect(ctx, peer.AddrInfo{ID: guest.ID(), Addrs: []ma.Multiaddr{circuit}}); err != nil {
		t.Fatal(err)
	}
	stream, err := broker.NewStream(network.WithAllowLimitedConn(ctx, "test"), guest.ID(), "/dsmack/backhaul-check/1")
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	message := []byte("sealed-job-transport-check")
	if _, err := stream.Write(message); err != nil {
		t.Fatal(err)
	}
	stream.CloseWrite()
	back, err := io.ReadAll(stream)
	if err != nil || !bytes.Equal(back, message) {
		t.Fatalf("circuit echo=%q err=%v", back, err)
	}
}
