package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

func testPeer(t *testing.T) peer.ID {
	t.Helper()
	key, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := peer.IDFromPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func signedGrant(g grantBody, key ed25519.PrivateKey) []byte {
	var fields map[string]any
	json.Unmarshal(canonical(g), &fields)
	fields["sig"] = hex.EncodeToString(ed25519.Sign(key, canonical(g)))
	return canonical(fields)
}
func TestGrantSignaturePeersExpiryAndFraming(t *testing.T) {
	key, secret, _ := ed25519.GenerateKey(rand.Reader)
	relay, client := testPeer(t), testPeer(t)
	now := time.Now()
	g := grantBody{100, client.String(), now.Unix() + 60, "0123456789abcdef0123456789abcdef", relay.String(), "", 1}
	raw := signedGrant(g, secret)
	if _, err := verifyGrant(raw, key, relay, client, now); err != nil {
		t.Fatal(err)
	}
	upper := g
	upper.GrantID = "ABCDEF0123456789ABCDEF0123456789"
	if _, err := verifyGrant(signedGrant(upper, secret), key, relay, client, now); err != nil {
		t.Fatal("32 hex characters must accept either case", err)
	}
	otherKey, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := verifyGrant(raw, otherKey, relay, client, now); err == nil {
		t.Fatal("another broker key accepted")
	}
	for _, tc := range []struct {
		name          string
		raw           []byte
		relay, client peer.ID
		now           time.Time
	}{
		{"wrong client", raw, relay, testPeer(t), now}, {"wrong relay", raw, testPeer(t), client, now},
		{"expired", raw, relay, client, time.Unix(g.ExpiresAt, 0)},
		{"tampered budget", bytes.Replace(raw, []byte(`"bytes":100`), []byte(`"bytes":101`), 1), relay, client, now},
		{"duplicate key", append([]byte(`{"v":1,`), raw[1:]...), relay, client, now},
		{"alternate JSON string escape", bytes.Replace(raw, []byte(`"client_peer":"1`), []byte(`"client_peer":"\u0031`), 1), relay, client, now},
		{"noncanonical whitespace", append(raw, '\n'), relay, client, now},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := verifyGrant(tc.raw, key, tc.relay, tc.client, tc.now); err == nil {
				t.Fatal("invalid grant accepted")
			}
		})
	}
	for _, bad := range []grantBody{
		{0, g.ClientPeer, g.ExpiresAt, g.GrantID, g.RelayPeer, "", 1},
		{100, g.ClientPeer, g.ExpiresAt, "bad", g.RelayPeer, "", 1},
		{100, g.ClientPeer, g.ExpiresAt, g.GrantID, g.RelayPeer, "", 2},
	} {
		if _, err := verifyGrant(signedGrant(bad, secret), key, relay, client, now); err == nil {
			t.Fatal("invalid grant terms accepted")
		}
	}
	var framed bytes.Buffer
	if err := writeGrant(&framed, raw); err != nil {
		t.Fatal(err)
	}
	back, err := readGrant(&framed)
	if err != nil || !bytes.Equal(back, raw) {
		t.Fatal("frame roundtrip", err)
	}
	for _, n := range []uint32{0, 4097} {
		var b bytes.Buffer
		binary.Write(&b, binary.BigEndian, n)
		if _, err := readGrant(&b); err == nil {
			t.Fatal("invalid frame length")
		}
	}
	var truncated bytes.Buffer
	binary.Write(&truncated, binary.BigEndian, uint32(100))
	truncated.WriteByte(0)
	if _, err := readGrant(&truncated); err == nil {
		t.Fatal("truncated grant accepted")
	}
}

// Concurrent streams and directions must share a single exact cap; a reused id
// cannot buy a fresh counter, and every accepted grant gets a verifiable receipt.
func TestConcurrentAccountingCutoffReuseAndReceipts(t *testing.T) {
	key, secret, _ := ed25519.GenerateKey(rand.Reader)
	relay, client := testPeer(t), testPeer(t)
	g := grantBody{200000, client.String(), time.Now().Unix() + 60, "0123456789abcdef0123456789abcdef", relay.String(), "", 1}
	book := &grantBook{}
	var group sync.WaitGroup
	var outputs [8]bytes.Buffer
	for i := range outputs {
		c, s := tcpPair(t)
		_ = c
		u, err := book.accept(g, s)
		if err != nil {
			t.Fatal(err)
		}
		group.Add(1)
		go func(i int) {
			defer group.Done()
			defer u.detach(s)
			for {
				if _, err := u.forward(&outputs[i], make([]byte, 333)); err != nil {
					return
				}
			}
		}(i)
	}
	group.Wait()
	total := 0
	for i := range outputs {
		total += outputs[i].Len()
	}
	if int64(total) != g.Bytes {
		t.Fatalf("forwarded %d, budget %d", total, g.Bytes)
	}
	_, s := tcpPair(t)
	if _, err := book.accept(g, s); err == nil {
		t.Fatal("exhausted grant reused")
	}
	changed := g
	changed.Bytes++
	if _, err := book.accept(changed, s); err == nil {
		t.Fatal("grant id reset counter")
	}
	receipts := book.receipts(secret, "run", client.String())
	if len(receipts) != 1 {
		t.Fatal(receipts)
	}
	sig, _ := hex.DecodeString(receipts[0]["sig"].(string))
	delete(receipts[0], "sig")
	if !ed25519.Verify(key, canonical(receipts[0]), sig) {
		t.Fatal("receipt signature")
	}
	if receipts[0]["bytes_used"] != g.Bytes {
		t.Fatal("receipt usage", receipts)
	}
	if len(book.receipts(secret, "run", testPeer(t).String())) != 0 {
		t.Fatal("receipt leaked to another client")
	}
}

type shortWriter struct{}

func (shortWriter) Write(b []byte) (int, error) { return min(3, len(b)), io.ErrClosedPipe }
func TestShortWriteRefundAndBidirectionalCutoff(t *testing.T) {
	u := newUsage(grantBody{Bytes: 20, ExpiresAt: time.Now().Unix() + 60})
	if n, _ := u.forward(shortWriter{}, make([]byte, 10)); n != 3 {
		t.Fatal(n)
	}
	var out bytes.Buffer
	u.forward(&out, make([]byte, 100))
	if out.Len() != 17 || u.used != 20 || u.pending != 0 {
		t.Fatal("short write consumed unforwarded bytes", out.Len(), u.used, u.pending)
	}
	client, a := tcpPair(t)
	b, server := tcpPair(t)
	u = newUsage(grantBody{Bytes: 9, ExpiresAt: time.Now().Unix() + 60})
	if err := u.attach(a); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { u.bridge(a, b); done <- nil }()
	client.Write([]byte("four"))
	readBytes(t, server, []byte("four"))
	server.Write([]byte("123456789"))
	got, _ := io.ReadAll(client)
	if string(got) != "12345" {
		t.Fatalf("cutoff bytes %q", got)
	}
	if err := completed(t, done); err != nil {
		t.Fatal(err)
	}
	if u.used != 9 {
		t.Fatal(u.used)
	}
}

// Grants must target the identity actually used by the Noise handshake.
func TestClientHostUsesSavedIdentity(t *testing.T) {
	key, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := crypto.MarshalPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "client.key")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	h := clientHost(path)
	defer h.Close()
	want, err := peer.IDFromPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"), libp2p.Security(noise.ID, noise.New))
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := h.Connect(ctx, peer.AddrInfo{ID: receiver.ID(), Addrs: receiver.Addrs()}); err != nil {
		t.Fatal(err)
	}
	connections := receiver.Network().ConnsToPeer(want)
	if len(connections) == 0 || connections[0].ConnState().Security != noise.ID {
		t.Fatal("saved identity was not authenticated over Noise")
	}
	if h.ID() != want {
		t.Fatalf("client identity %s, want %s", h.ID(), want)
	}
}
