package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"golang.org/x/crypto/sha3"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	payments "dsmack-payments"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/libp2p/go-libp2p"
	lc "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

func TestStopAcknowledgementArrivesBeforeHostCloses(t *testing.T) {
	server, e := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	client, e := libp2p.New(libp2p.NoListenAddrs)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	stopped := make(chan struct{})
	server.SetStreamHandler("/test/stop/1", func(stream network.Stream) {
		defer stream.Close()
		acknowledgeStop(stream, func() { close(stopped); server.Close() })
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if e = client.Connect(ctx, peer.AddrInfo{ID: server.ID(), Addrs: server.Addrs()}); e != nil {
		t.Fatal(e)
	}
	stream, e := client.NewStream(ctx, server.ID(), "/test/stop/1")
	if e != nil {
		t.Fatal(e)
	}
	stream.SetDeadline(time.Now().Add(3 * time.Second))
	// A queued libp2p write is lost if the host closes before the reader consumes it.
	time.Sleep(100 * time.Millisecond)
	var reply map[string]string
	if e = readFrame(stream, 4096, &reply); e != nil || reply["status"] != "stopping" {
		t.Fatal(reply, e)
	}
	select {
	case <-stopped:
		t.Fatal("host stopped before peer received the acknowledgement")
	default:
	}
	stream.Close()
	client.Close()
	select {
	case <-stopped:
	case <-ctx.Done():
		t.Fatal("operator stop did not finish")
	}
}
