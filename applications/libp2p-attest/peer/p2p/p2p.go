// dsmack-peer: a circuit relay, an attested guest peer, and a verifying dialer (README.md).
package p2p

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	"github.com/libp2p/go-libp2p/p2p/transport/websocket"
	ma "github.com/multiformats/go-multiaddr"
)

const (
	attestProto = "/dsmack/attest/1"
	echoProto   = "/dsmack/echo/1"
	domain      = "dsmack-libp2p-peer/1"
)

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func NewHost(opts ...libp2p.Option) host.Host {
	key, _, err := crypto.GenerateEd25519Key(rand.Reader)
	must(err)
	if os.Getenv("DSMACK_LOCAL_WS") == "1" {
		opts = append(opts, libp2p.NoTransports, libp2p.Transport(websocket.New))
	}
	h, err := libp2p.New(append([]libp2p.Option{libp2p.Identity(key)}, opts...)...)
	must(err)
	return h
}

// ReportData is sha256(domain || PeerId bytes), zero-padded to 64 bytes.
func ReportData(id peer.ID) []byte {
	d := sha256.Sum256(append([]byte(domain), []byte(id)...))
	return append(d[:], make([]byte, 32)...)
}

func Attest(rd []byte) []byte {
	c := http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", "/var/run/dstack.sock")
	}}}
	body, _ := json.Marshal(map[string]string{"report_data": hex.EncodeToString(rd)})
	r, err := c.Post("http://localhost/v1/Attest", "application/json", bytes.NewReader(body))
	must(err)
	defer r.Body.Close()
	var out struct{ Attestation string }
	must(json.NewDecoder(r.Body).Decode(&out))
	if r.StatusCode != 200 {
		log.Fatalf("Attest: HTTP %d", r.StatusCode)
	}
	blob, err := hex.DecodeString(out.Attestation)
	must(err)
	return blob
}

// relayMain serves circuit relay v2 without data or duration limits and logs each reservation.
func relayMain(listen, keyFile string) {
	raw, err := os.ReadFile(keyFile)
	must(err)
	key, err := crypto.UnmarshalPrivateKey(raw)
	must(err)
	h, err := libp2p.New(libp2p.Identity(key), libp2p.ListenAddrStrings(listen), libp2p.ForceReachabilityPublic(), libp2p.DisableRelay())
	must(err)
	_, err = relay.New(h, relay.WithInfiniteLimits(), relay.WithACL(logACL{}))
	must(err)
	fmt.Printf("relay %s/p2p/%s\n", listen, h.ID())
	select {}
}

type logACL struct{}

func (logACL) AllowReserve(p peer.ID, a ma.Multiaddr) bool {
	fmt.Printf("reserve %s from %s\n", p, a)
	return true
}
func (logACL) AllowConnect(src peer.ID, _ ma.Multiaddr, dst peer.ID) bool {
	fmt.Printf("connect %s -> %s\n", src, dst)
	return true
}

// serveMain reserves a relay slot and serves an attestation and echo for seconds.
// With a file it serves those bytes instead of calling /v1/Attest (the impostor).
func serveMain(relayAddr string, seconds int, file string) {
	h := NewHost(libp2p.NoListenAddrs, libp2p.EnableRelay())
	info, err := peer.AddrInfoFromString(relayAddr)
	must(err)
	ctx := context.Background()
	must(h.Connect(ctx, *info))
	_, err = client.Reserve(ctx, h, *info)
	must(err)
	var blob []byte
	if file == "" {
		blob = Attest(ReportData(h.ID()))
		must(os.WriteFile("/workspace/artifacts/attestation", blob, 0o644))
		must(os.WriteFile("/workspace/artifacts/peer-id", []byte(h.ID().String()+"\n"), 0o644))
	} else {
		blob, err = os.ReadFile(file)
		must(err)
	}
	h.SetStreamHandler(attestProto, func(s network.Stream) {
		s.Write(blob)
		s.Close()
		fmt.Printf("served attestation to %s\n", s.Conn().RemotePeer())
	})
	h.SetStreamHandler(echoProto, func(s network.Stream) {
		n, _ := io.Copy(s, io.LimitReader(s, 1<<16))
		s.Close()
		fmt.Printf("echoed %d bytes to %s\n", n, s.Conn().RemotePeer())
	})
	fmt.Printf("peer %s/p2p-circuit/p2p/%s\n", relayAddr, h.ID())
	time.Sleep(time.Duration(seconds) * time.Second)
}

// dialMain fetches the peer's attestation, runs the verifier command on it with the
// authenticated PeerId bytes appended, and opens an echo stream only if it exits 0.
// ConnectAndVerify authenticates the remote PeerId and runs the verifier before data streams open.
func ConnectAndVerify(h host.Host, addr string, verifier []string) (peer.ID, error) {
	target, err := ma.NewMultiaddr(addr)
	must(err)
	info, err := peer.AddrInfoFromP2pAddr(target)
	must(err)
	ctx := network.WithAllowLimitedConn(context.Background(), "dsmack")
	must(h.Connect(ctx, *info))
	s, err := h.NewStream(ctx, info.ID, attestProto)
	must(err)
	blob, err := io.ReadAll(io.LimitReader(s, 1<<16))
	must(err)
	remote := s.Conn().RemotePeer()
	f, err := os.CreateTemp("", "attestation-")
	must(err)
	defer os.Remove(f.Name())
	_, err = f.Write(blob)
	must(err)
	f.Close()
	cmd := exec.Command(verifier[0], append(verifier[1:], f.Name(), hex.EncodeToString([]byte(remote)))...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf("REFUSED %s: verifier %v\n", remote, err)
		return "", err
	}
	s.Close()
	return remote, nil
}

func dialMain(addr string, verifier []string) {
	h := NewHost(libp2p.NoListenAddrs, libp2p.EnableRelay())
	defer h.Close()
	remote, err := ConnectAndVerify(h, addr, verifier)
	must(err)
	ctx := network.WithAllowLimitedConn(context.Background(), "dsmack")
	e, err := h.NewStream(ctx, remote, echoProto)
	must(err)
	msg := []byte("hello attested peer " + time.Now().UTC().Format(time.RFC3339))
	_, err = e.Write(msg)
	must(err)
	must(e.CloseWrite())
	back, err := io.ReadAll(e)
	must(err)
	if !bytes.Equal(back, msg) {
		log.Fatalf("echo mismatch: %q", back)
	}
	fmt.Printf("ECHO %s: %s\n", remote, back)
}

func Main() {
	args := os.Args[1:]
	switch {
	case len(args) == 2 && args[0] == "keygen":
		key, _, err := crypto.GenerateEd25519Key(rand.Reader)
		must(err)
		raw, err := crypto.MarshalPrivateKey(key)
		must(err)
		must(os.WriteFile(args[1], raw, 0o600))
	case len(args) == 3 && args[0] == "relay":
		relayMain(args[1], args[2])
	case (len(args) == 3 || len(args) == 4) && args[0] == "serve":
		seconds, err := strconv.Atoi(args[2])
		must(err)
		file := ""
		if len(args) == 4 {
			file = args[3]
		}
		serveMain(args[1], seconds, file)
	case len(args) >= 3 && args[0] == "dial":
		dialMain(args[1], args[2:])
	default:
		log.Fatal("usage: keygen <file> | relay <listen maddr> <key file> | serve <relay maddr> <seconds> [attestation file] | dial <circuit maddr> <verifier cmd...>")
	}
}
