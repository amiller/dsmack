// Attested SOCKS CONNECT streams, with every TCP and DNS request through an in-memory WireGuard netstack.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"os/signal"
	"sync"
	"syscall"

	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"dsmack-peer/p2p"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
)

const socksProto = "/dsmack/socks/1"

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func post(c *http.Client, url string, in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	r, err := c.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return fmt.Errorf("secret API: HTTP %d", r.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(r.Body, 128<<10)).Decode(out)
}

func getProfile(task, url string) ([]byte, error) {
	rd := sha256.Sum256(append([]byte("dsmack.secret-request/1"), []byte(task)...))
	att := p2p.Attest(append(rd[:], make([]byte, 32)...))
	c := &http.Client{Timeout: 60 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var sealed map[string]string
	if err := post(c, strings.TrimRight(url, "/")+"/release", map[string]string{"task_id": task, "attestation": hex.EncodeToString(att)}, &sealed); err != nil {
		return nil, err
	}
	sealed["task_id"] = task
	guest := &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", "/var/run/dstack.sock")
	}}}
	var out struct{ Secret string }
	if err := post(guest, "http://localhost/v1/GetSecret", sealed, &out); err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(out.Secret)
	if err != nil {
		return nil, fmt.Errorf("GetSecret encoding")
	}
	return raw, nil
}

func serve(relay string, seconds int, task, url, brokerHex string) {
	broker, err := hex.DecodeString(brokerHex)
	must(err)
	if len(broker) != ed25519.PublicKeySize {
		log.Fatal("broker public key must be 32 bytes")
	}
	receiptKey, signer, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	raw, err := getProfile(task, url)
	must(err)
	stack, closeWG, err := uplink(raw)
	must(err)
	defer closeWG()
	h := p2p.NewHost(libp2p.NoListenAddrs, libp2p.EnableRelay(), libp2p.Security(noise.ID, noise.New))
	defer h.Close()
	info, err := peer.AddrInfoFromString(relay)
	must(err)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	must(h.Connect(ctx, *info))
	_, err = client.Reserve(ctx, h, *info)
	must(err)
	rd := p2p.ReportData(h.ID())
	copy(rd[32:], receiptKey)
	att := p2p.Attest(rd)
	var infoResponse struct {
		Run string `json:"instance_id"`
	}
	guest := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", "/var/run/dstack.sock")
	}}}
	must(post(guest, "http://localhost/v1/Info", map[string]any{}, &infoResponse))
	run, err := hex.DecodeString(infoResponse.Run)
	must(err)
	if len(run) != 32 {
		log.Fatal("invalid guest run")
	}
	envelope := canonical(map[string]string{"attestation": hex.EncodeToString(att), "receipt_key": hex.EncodeToString(receiptKey)})
	book := &grantBook{}
	var active sync.WaitGroup
	var admission sync.Mutex
	stopping := false
	must(os.WriteFile("/workspace/artifacts/attestation", att, 0o644))
	must(os.WriteFile("/workspace/artifacts/peer-id", []byte(h.ID().String()+"\n"), 0o644))
	h.SetStreamHandler("/dsmack/attest/1", func(s network.Stream) {
		defer s.Close()
		s.SetWriteDeadline(time.Now().Add(30 * time.Second))
		s.Write(envelope)
	})
	h.SetStreamHandler("/dsmack/receipt/1", func(s network.Stream) {
		defer s.Close()
		s.SetDeadline(time.Now().Add(30 * time.Second))
		_, err := s.Write(canonical(book.receipts(signer, infoResponse.Run, s.Conn().RemotePeer().String())))
		if err != nil {
			log.Printf("receipt: %v", err)
		}
	})
	h.SetStreamHandler(socksProto, func(s network.Stream) {
		admission.Lock()
		if stopping {
			admission.Unlock()
			s.Close()
			return
		}
		active.Add(1)
		admission.Unlock()
		defer active.Done()
		defer s.Close()
		s.SetDeadline(time.Now().Add(30 * time.Second))
		raw, err := readGrant(s)
		if err != nil {
			log.Printf("grant: %v", err)
			return
		}
		g, err := verifyGrant(raw, broker, h.ID(), s.Conn().RemotePeer(), time.Now())
		if err != nil {
			log.Printf("grant: %v", err)
			s.Reset()
			return
		}
		u, err := book.accept(g, s)
		if err != nil {
			log.Printf("grant: %v", err)
			s.Reset()
			return
		}
		defer u.detach(s)
		if err := socksWithBridge(s, stack.DialContext, u.bridge); err != nil {
			log.Printf("SOCKS: %v", err)
		}
	})
	fmt.Printf("peer %s/p2p-circuit/p2p/%s\n", relay, h.ID())
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, os.Interrupt)
	defer signal.Stop(stop)
	select {
	case <-time.After(time.Duration(seconds) * time.Second):
	case <-stop:
	}
	admission.Lock()
	stopping = true
	admission.Unlock()
	h.RemoveStreamHandler(socksProto)
	book.closeStreams()
	h.Close()
	active.Wait()
	must(os.WriteFile("/workspace/artifacts/receipts", canonical(book.receipts(signer, infoResponse.Run, "")), 0o644))
	must(os.WriteFile("/workspace/artifacts/receipt-key", []byte(hex.EncodeToString(receiptKey)), 0o644))
}

func recipient(addr, listen, keyFile, grantFile string, verifier []string) {
	raw, err := os.ReadFile(grantFile)
	must(err)
	h := clientHost(keyFile)
	defer h.Close()
	remote, err := p2p.ConnectAndVerify(h, addr, verifier)
	must(err)
	host, _, err := net.SplitHostPort(listen)
	must(err)
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		log.Fatal("recipient listener must be a loopback IP")
	}
	l, err := net.Listen("tcp", listen)
	must(err)
	defer l.Close()
	fmt.Printf("verified %s; SOCKS listening %s\n", remote, l.Addr())
	for {
		c, err := l.Accept()
		must(err)
		go func() {
			defer c.Close()
			ctx, cancel := context.WithTimeout(network.WithAllowLimitedConn(context.Background(), "dsmack-egress"), 30*time.Second)
			defer cancel()
			s, err := h.NewStream(ctx, remote, socksProto)
			if err != nil {
				log.Printf("SOCKS stream: %v", err)
				return
			}
			defer s.Close()
			mustErr := writeGrant(s, bytes.TrimSpace(raw))
			if mustErr != nil {
				log.Printf("grant send: %v", mustErr)
				return
			}
			bridge(c.(*net.TCPConn), s)
		}()
	}
}

func main() {
	a := os.Args[1:]
	switch {
	case len(a) == 6 && a[0] == "serve":
		seconds, err := strconv.Atoi(a[2])
		must(err)
		if seconds < 1 {
			log.Fatal("seconds must be positive")
		}
		serve(a[1], seconds, a[3], a[4], a[5])
	case len(a) >= 6 && a[0] == "recipient":
		recipient(a[1], a[2], a[3], a[4], a[5:])
	case len(a) >= 5 && a[0] == "receipt":
		h := clientHost(a[2])
		defer h.Close()
		remote, err := p2p.ConnectAndVerify(h, a[1], a[4:])
		must(err)
		ctx, cancel := context.WithTimeout(network.WithAllowLimitedConn(context.Background(), "receipt"), 30*time.Second)
		defer cancel()
		s, err := h.NewStream(ctx, remote, "/dsmack/receipt/1")
		must(err)
		defer s.Close()
		s.SetDeadline(time.Now().Add(30 * time.Second))
		data, err := io.ReadAll(io.LimitReader(s, 1<<20))
		must(err)
		must(os.WriteFile(a[3], data, 0o644))
	case len(a) == 2 && a[0] == "keygen":
		key, _, err := crypto.GenerateEd25519Key(rand.Reader)
		must(err)
		raw, err := crypto.MarshalPrivateKey(key)
		must(err)
		f, err := os.OpenFile(a[1], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		must(err)
		_, err = f.Write(raw)
		must(err)
		must(f.Close())
	case len(a) == 2 && a[0] == "id":
		h := clientHost(a[1])
		defer h.Close()
		fmt.Println(h.ID())
	default:
		log.Fatal("usage: serve <relay> <seconds> <task> <policy url> <broker key hex> | recipient <circuit> <loopback:port> <client key> <grant file> <verifier cmd...> | receipt <circuit> <client key> <out> <verifier cmd...> | keygen <file> | id <key file>")
	}
}

func clientHost(keyFile string) host.Host {
	raw, err := os.ReadFile(keyFile)
	must(err)
	key, err := crypto.UnmarshalPrivateKey(raw)
	must(err)
	h, err := libp2p.New(libp2p.Identity(key), libp2p.NoListenAddrs, libp2p.EnableRelay(), libp2p.Security(noise.ID, noise.New))
	must(err)
	return h
}
