// A loopback-only WebSocket circuit relay for cloudflared.
package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/muxer/yamux"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	"github.com/libp2p/go-libp2p/p2p/transport/websocket"
	ma "github.com/multiformats/go-multiaddr"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: browser-relay <private key file>")
	}
	raw, err := os.ReadFile(os.Args[1])
	if os.IsNotExist(err) {
		key, _, keyErr := crypto.GenerateEd25519Key(rand.Reader)
		if keyErr != nil {
			log.Fatal(keyErr)
		}
		raw, err = crypto.MarshalPrivateKey(key)
		if err != nil {
			log.Fatal(err)
		}
		f, createErr := os.OpenFile(os.Args[1], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if createErr != nil {
			log.Fatal(createErr)
		}
		_, err = f.Write(raw)
		f.Close()
	}
	if err != nil {
		log.Fatal(err)
	}
	key, err := crypto.UnmarshalPrivateKey(raw)
	if err != nil {
		log.Fatal(err)
	}
	h, err := libp2p.New(libp2p.Identity(key), libp2p.NoTransports,
		libp2p.Transport(websocket.New), libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/4019/ws"),
		libp2p.Security(noise.ID, noise.New), libp2p.Muxer(yamux.ID, yamux.DefaultTransport),
		libp2p.ForceReachabilityPublic(), libp2p.DisableRelay())
	if err != nil {
		log.Fatal(err)
	}
	defer h.Close()
	r := relay.DefaultResources()
	r.MaxReservations = 8
	r.MaxCircuits = 4
	service, err := relay.New(h, relay.WithResources(r), relay.WithACL(logACL{}))
	if err != nil {
		log.Fatal(err)
	}
	defer service.Close()
	fmt.Printf("relay_peer=%s listen=%s resources=%+v limit=%+v\n", h.ID(), h.Addrs(), r, r.Limit)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
}

type logACL struct{}

func (logACL) AllowReserve(p peer.ID, a ma.Multiaddr) bool {
	log.Printf("reserve %s from %s", p, a)
	return true
}
func (logACL) AllowConnect(p peer.ID, _ ma.Multiaddr, dst peer.ID) bool {
	log.Printf("connect %s -> %s", p, dst)
	return true
}
