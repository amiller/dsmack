// Attested SOCKS CONNECT streams, with every TCP and DNS request through an in-memory WireGuard netstack.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

func serve(relay string, seconds int, task, url string) {
	raw, err := getProfile(task, url)
	must(err)
	stack, closeWG, err := uplink(raw)
	must(err)
	defer closeWG()
	h := p2p.NewHost(libp2p.NoListenAddrs, libp2p.EnableRelay())
	defer h.Close()
	info, err := peer.AddrInfoFromString(relay)
	must(err)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	must(h.Connect(ctx, *info))
	_, err = client.Reserve(ctx, h, *info)
	must(err)
	att := p2p.Attest(p2p.ReportData(h.ID()))
	must(os.WriteFile("/workspace/artifacts/attestation", att, 0o644))
	must(os.WriteFile("/workspace/artifacts/peer-id", []byte(h.ID().String()+"\n"), 0o644))
	h.SetStreamHandler("/dsmack/attest/1", func(s network.Stream) {
		defer s.Close()
		s.SetWriteDeadline(time.Now().Add(30 * time.Second))
		s.Write(att)
	})
	h.SetStreamHandler(socksProto, func(s network.Stream) {
		if err := socks(s, stack.DialContext); err != nil {
			log.Printf("SOCKS: %v", err)
		}
	})
	fmt.Printf("peer %s/p2p-circuit/p2p/%s\n", relay, h.ID())
	time.Sleep(time.Duration(seconds) * time.Second)
}

func recipient(addr, listen string, verifier []string) {
	h := p2p.NewHost(libp2p.NoListenAddrs, libp2p.EnableRelay())
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
			bridge(c.(*net.TCPConn), s)
		}()
	}
}

func main() {
	a := os.Args[1:]
	switch {
	case len(a) == 5 && a[0] == "serve":
		seconds, err := strconv.Atoi(a[2])
		must(err)
		if seconds < 1 {
			log.Fatal("seconds must be positive")
		}
		serve(a[1], seconds, a[3], a[4])
	case len(a) >= 4 && a[0] == "recipient":
		recipient(a[1], a[2], a[3:])
	default:
		log.Fatal("usage: serve <relay maddr> <seconds> <task id> <policy url> | recipient <circuit maddr> <loopback:port> <verifier cmd...>")
	}
}
