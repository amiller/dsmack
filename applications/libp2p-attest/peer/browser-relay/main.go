// A loopback-only WebSocket circuit relay for cloudflared.
package main

import (
	"context"
	"crypto/rand"
	"flag"
	"dsmack-peer/p2p"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/muxer/yamux"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	"github.com/libp2p/go-libp2p/p2p/transport/websocket"
	ma "github.com/multiformats/go-multiaddr"
)

func main() {
	port := flag.Int("port", 4019, "loopback WebSocket listen port")
	flag.Parse()
	if *port < 1 || *port > 65535 {
		log.Fatal("port must be 1..65535")
	}
	args := flag.Args()
	if len(args) != 1 && len(args) != 3 {
		log.Fatal("usage: browser-relay <private key file> [broker HTTP backhaul URL broker PeerId]")
	}
	raw, err := os.ReadFile(args[0])
	if os.IsNotExist(err) {
		key, _, keyErr := crypto.GenerateEd25519Key(rand.Reader)
		if keyErr != nil {
			log.Fatal(keyErr)
		}
		raw, err = crypto.MarshalPrivateKey(key)
		if err != nil {
			log.Fatal(err)
		}
		f, createErr := os.OpenFile(args[0], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
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
	muxer := *yamux.DefaultTransport
	muxer.ConnectionWriteTimeout = 90 * time.Second // HTTP backhaul drains over a public WAN, not a LAN.
	h, err := libp2p.New(libp2p.Identity(key), libp2p.NoTransports,
		libp2p.Transport(websocket.New), libp2p.Transport(tcp.NewTCPTransport), libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d/ws", *port)),
		libp2p.Security(noise.ID, noise.New), libp2p.Muxer(yamux.ID, &muxer),
		libp2p.ForceReachabilityPublic(), libp2p.DisableRelay())
	if err != nil {
		log.Fatal(err)
	}
	defer h.Close()
	r := relay.DefaultResources()
	// Each slot overlaps two guest generations, all reserving from loopback, and the
	// broker is the source of every attestation hop: size for 8 slots, not 4 guests.
	r.MaxReservations = 16
	r.MaxReservationsPerIP = 16
	r.MaxCircuits = 16
	r.Limit.Data = 1 << 30 // bounded allowance for workspace restore and an encrypted save
	r.Limit.Duration = 65 * time.Minute
	service, err := relay.New(h, relay.WithResources(r), relay.WithACL(logACL{}))
	if err != nil {
		log.Fatal(err)
	}
	defer service.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if len(args) == 3 {
		if err = p2p.MaintainBackhaul(ctx, h, args[1], args[2]); err != nil {
			log.Fatal(err)
		}
	}
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
