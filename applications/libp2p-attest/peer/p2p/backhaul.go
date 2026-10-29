package p2p

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"time"

	"github.com/gorilla/websocket"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

// backhaulListener supplies a loopback TCP stream to Go's existing Noise/yamux
// stack. go-libp2p's WS dialer has no URL-path support; this adapter carries the
// same bytes over an ordinary WebSocket at the broker's shared HTTP route.
func backhaulListener(raw string) (net.Listener, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("broker WebSocket origin")
	}
	if u.Scheme != "wss" && !(u.Scheme == "ws" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost")) {
		return nil, fmt.Errorf("broker backhaul requires WSS")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go bridgeWebSocket(conn, raw)
		}
	}()
	return listener, nil
}

func bridgeWebSocket(conn net.Conn, raw string) {
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	ws, _, err := websocket.DefaultDialer.DialContext(ctx, raw, nil)
	cancel()
	if err != nil {
		fmt.Println("broker backhaul WebSocket refused")
		return
	}
	defer ws.Close()
	ws.SetReadLimit(64 << 20)
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-finished:
				return
			case <-ticker.C:
				if ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second)) != nil {
					conn.Close()
					return
				}
			}
		}
	}()
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
}

// maintainBackhaul authenticates the configured broker PeerId over the outbound
// connection. The broker can then open relay streams on that same connection;
// neither side needs an inbound route to the operator's LAN address.
func maintainBackhaul(ctx context.Context, h host.Host, raw, brokerID string) error {
	id, err := peer.Decode(brokerID)
	if err != nil {
		return err
	}
	listener, err := backhaulListener(raw)
	if err != nil {
		return err
	}
	addr, err := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/" + fmt.Sprint(listener.Addr().(*net.TCPAddr).Port))
	if err != nil {
		listener.Close()
		return err
	}
	go func() { <-ctx.Done(); listener.Close() }()
	go func() {
		defer listener.Close()
		for {
			if ctx.Err() != nil {
				return
			}
			if h.Network().Connectedness(id) != network.Connected {
				h.Peerstore().ClearAddrs(id)
				dialCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
				err := h.Connect(dialCtx, peer.AddrInfo{ID: id, Addrs: []ma.Multiaddr{addr}})
				cancel()
				if err != nil {
					fmt.Println("broker backhaul Noise connection refused")
				} else {
					h.ConnManager().Protect(id, "broker-backhaul")
					fmt.Printf("broker backhaul connected %s\n", id)
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
		}
	}()
	return nil
}
