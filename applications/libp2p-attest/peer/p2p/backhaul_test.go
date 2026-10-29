package p2p

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	ma "github.com/multiformats/go-multiaddr"
)

func TestBrokerCanUseOutboundWebSocketRelayForPrivateCircuit(t *testing.T) {
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
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/relay-broker/sandbox/p2p" {
			t.Error("wrong shared HTTP route")
			w.WriteHeader(404)
			return
		}
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer ws.Close()
		conn, err := net.Dial("tcp", "127.0.0.1:"+addr)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		go func() {
			defer conn.Close()
			defer ws.Close()
			buffer := make([]byte, 32<<10)
			for {
				n, err := conn.Read(buffer)
				if n > 0 && ws.WriteMessage(websocket.BinaryMessage, buffer[:n]) != nil {
					return
				}
				if err != nil {
					return
				}
			}
		}()
		for {
			kind, reader, err := ws.NextReader()
			if err != nil || kind != websocket.BinaryMessage {
				return
			}
			if _, err := io.Copy(conn, reader); err != nil {
				return
			}
		}
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
	if err := maintainBackhaul(ctx, operator, "ws"+strings.TrimPrefix(server.URL, "http")+"/relay-broker/sandbox/p2p", broker.ID().String()); err != nil {
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
