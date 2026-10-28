package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	payments "dsmack-payments"
	"dsmack-peer/p2p"
	"github.com/libp2p/go-libp2p"
	lc "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	protocolpkg "github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
)

func must(e error) {
	if e != nil {
		log.Fatal(e)
	}
}
func guestClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", "/var/run/dstack.sock")
	}}}
}
func post(c *http.Client, url string, in, out any) error {
	r, e := c.Post(url, "application/json", bytes.NewReader(canon(in)))
	if e != nil {
		return e
	}
	defer r.Body.Close()
	if r.StatusCode < 200 || r.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", r.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(r.Body, 256<<10)).Decode(out)
}
func attest(rd []byte) ([]byte, error) {
	var out struct{ Attestation string }
	e := post(guestClient(), "http://localhost/v1/Attest", map[string]string{"report_data": hex.EncodeToString(rd)}, &out)
	if e != nil {
		return nil, e
	}
	return hex.DecodeString(out.Attestation)
}
func hostFor(file string) host.Host {
	raw, e := os.ReadFile(file)
	must(e)
	key, e := lc.UnmarshalPrivateKey(raw)
	must(e)
	h, e := libp2p.New(libp2p.Identity(key), libp2p.NoListenAddrs, libp2p.EnableRelay(), libp2p.Security(noise.ID, noise.New))
	must(e)
	return h
}

// Broker HTTPS keeps its URL hostname for TLS, while dialing only its measured IP.
// The sentinel's HTTPS_PROXY must never intercept broker registration.
func brokerClient(raw string) (*http.Client, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("broker scheme")
	}
	ip := net.ParseIP(os.Getenv("BROKER_IP"))
	if ip == nil {
		ip = net.ParseIP(u.Hostname())
	}
	if ip == nil {
		return nil, fmt.Errorf("broker requires a measured BROKER_IP")
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	target := net.JoinHostPort(u.Hostname(), port)
	pinned := net.JoinHostPort(ip.String(), port)
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != target {
			return nil, fmt.Errorf("broker destination")
		}
		return (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, network, pinned)
	}}
	return &http.Client{Timeout: 30 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

func serve(relay, brokerURL, brokerHex, cdhash, worker string, seconds int) {
	paid := paidMeter()
	operatorStop := make(chan struct{})
	var stopOnce sync.Once
	key, e := hex.DecodeString(brokerHex)
	must(e)
	if len(key) != 32 {
		log.Fatal("broker key length")
	}
	secret, e := ecdh.P256().GenerateKey(rand.Reader)
	must(e)
	receipt, signer, e := ed25519.GenerateKey(rand.Reader)
	must(e)
	h := p2p.NewHost(libp2p.NoListenAddrs, libp2p.EnableRelay(), libp2p.Security(noise.ID, noise.New))
	defer h.Close()
	var info map[string]any
	must(post(guestClient(), "http://localhost/v1/Info", map[string]any{}, &info))
	rd := append([]byte("dsmack-compute-node/1"), []byte(h.ID())...)
	rd = append(rd, public(secret)...)
	rd = append(rd, receipt...)
	hash := sha256.Sum256(rd)
	att, e := attest(append(hash[:], make([]byte, 32)...))
	must(e)
	var registrationMu sync.Mutex
	registration := map[string]any{"kind": "compute", "relay_peer": h.ID().String(), "relay_maddr": relay + "/p2p-circuit/p2p/" + h.ID().String(), "secret_key": hex.EncodeToString(public(secret)), "receipt_key": hex.EncodeToString(receipt), "manifest_sha256": info["compose_hash"], "os_image_hash": info["os_image_hash"], "cdhash": cdhash, "attestation": hex.EncodeToString(att)}
	run, ok := info["instance_id"].(string)
	if !ok {
		log.Fatal("missing guest instance_id")
	}
	n := &engine{paid: paid, secret: secret, signer: signer, broker: key, node: h.ID().String(), run: run, until: time.Now().Add(time.Duration(seconds) * time.Second), worker: worker, resultPath: "/workspace/artifacts/last-result", seen: map[string]bool{}, used: map[string]int64{}, attest: attest}
	h.SetStreamHandler("/dsmack/attest/1", func(s network.Stream) {
		defer s.Close()
		s.SetDeadline(time.Now().Add(20 * time.Second))
		registrationMu.Lock()
		raw := canon(registration)
		registrationMu.Unlock()
		s.Write(raw)
	})
	h.SetStreamHandler("/dsmack/job/1", func(s network.Stream) { defer s.Close(); n.handle(s, s.Conn().RemotePeer().String()) })
	ri, e := peer.AddrInfoFromString(relay)
	must(e)
	reserve := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if e := h.Connect(ctx, *ri); e != nil {
			return e
		}
		_, e := client.Reserve(ctx, h, *ri)
		return e
	}
	must(reserve())
	c, e := brokerClient(brokerURL)
	must(e)
	renew := func() error {
		var out map[string]any
		return post(c, strings.TrimRight(brokerURL, "/")+"/nodes", registration, &out)
	}
	must(os.WriteFile("/workspace/artifacts/registration", canon(registration), 0644))
	must(os.WriteFile("/workspace/artifacts/last-result", canon(map[string]string{"status": "idle"}), 0644))
	must(os.WriteFile("/workspace/artifacts/egress", []byte("{}"), 0644))
	if paid != nil {
		h.SetStreamHandler("/dsmack/payments-stop/1", func(s network.Stream) {
			defer s.Close()
			s.SetDeadline(time.Now().Add(20 * time.Second))
			var request struct {
				Signature string `json:"signature"`
				Expires   int64  `json:"expires"`
			}
			if readFrame(s, 4096, &request) != nil || paid.VerifyStop(request.Signature, request.Expires) != nil {
				return
			}
			n.mu.Lock()
			busy := n.busy
			n.mu.Unlock()
			if busy {
				writeFrame(s, map[string]string{"status": "busy"})
				return
			}
			acknowledgeStop(s, func() { stopOnce.Do(func() { close(operatorStop) }) })
		})
		must(os.WriteFile("/workspace/artifacts/payment-receipts", []byte(""), 0644))
		n.publish = func(r payments.SignedReceipt) error {
			var out map[string]any
			return post(c, strings.TrimRight(brokerURL, "/")+"/payments/receipts", r, &out)
		}
		legacy := append(hash[:], make([]byte, 32)...)
		baseRegistration := map[string]any{}
		for k, v := range registration {
			baseRegistration[k] = v
		}
		h.SetStreamHandler("/dsmack/payments-attest/1", func(s network.Stream) {
			defer s.Close()
			s.SetDeadline(time.Now().Add(20 * time.Second))
			var request struct {
				Challenge string `json:"challenge"`
			}
			if readFrame(s, 4096, &request) != nil {
				return
			}
			rd, err := paidReport(paid, baseRegistration, legacy, request.Challenge)
			if err != nil {
				return
			}
			att, err := attest(rd)
			if err != nil {
				return
			}
			copy := map[string]any{}
			registrationMu.Lock()
			for k, v := range registration {
				copy[k] = v
			}
			registrationMu.Unlock()
			payment := paid.Registration
			payment.Challenge = request.Challenge
			copy["payments"] = payment
			copy["attestation"] = hex.EncodeToString(att)
			s.Write(canon(copy))
		})
		renew = func() error {
			response, err := c.Get(strings.TrimRight(brokerURL, "/") + "/payments/challenge")
			if err != nil {
				return err
			}
			defer response.Body.Close()
			if response.StatusCode != 200 {
				return fmt.Errorf("payment challenge: HTTP %d", response.StatusCode)
			}
			var challenge struct {
				Challenge string `json:"challenge"`
			}
			if err = json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&challenge); err != nil {
				return err
			}
			rd, err := paidReport(paid, baseRegistration, legacy, challenge.Challenge)
			if err != nil {
				return err
			}
			att, err := attest(rd)
			if err != nil {
				return err
			}
			payment := paid.Registration
			payment.Challenge = challenge.Challenge
			registrationMu.Lock()
			registration["payments"] = payment
			registration["attestation"] = hex.EncodeToString(att)
			snapshot := map[string]any{}
			for k, v := range registration {
				snapshot[k] = v
			}
			registrationMu.Unlock()
			if err = os.WriteFile("/workspace/artifacts/registration", canon(snapshot), 0644); err != nil {
				return err
			}
			var out map[string]any
			return post(c, strings.TrimRight(brokerURL, "/")+"/nodes", snapshot, &out)
		}
	}
	// Paid runs expose their attested admission for the owner before registration.
	// An unregistered run cannot receive a grant; retries permit owner admission.
	if paid == nil {
		must(renew())
	} else if err := renew(); err != nil {
		fmt.Fprintln(os.Stderr, "awaiting paid admission:", err)
	}
	fmt.Println("compute node registered", h.ID())
	tick := time.NewTicker(25 * time.Second)
	defer tick.Stop()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, os.Interrupt)
	defer signal.Stop(stop)
	timer := time.NewTimer(time.Until(n.until))
	defer timer.Stop()
	for {
		select {
		case <-tick.C:
			must(reserve())
			if paid == nil {
				must(renew())
			} else if err := renew(); err != nil {
				fmt.Fprintln(os.Stderr, "paid registration:", err)
			}
		case <-timer.C:
			return
		case <-operatorStop:
			return
		case <-stop:
			return
		}
	}
}
func main() {
	a := os.Args[1:]
	switch {
	case len(a) == 7 && a[0] == "serve":
		seconds, e := strconv.Atoi(a[2])
		must(e)
		if seconds < 1 || seconds > 86400 {
			log.Fatal("duration")
		}
		serve(a[1], a[3], a[4], a[5], a[6], seconds)
	case len(a) == 2 && a[0] == "keygen":
		k, _, e := lc.GenerateEd25519Key(rand.Reader)
		must(e)
		raw, e := lc.MarshalPrivateKey(k)
		must(e)
		f, e := os.OpenFile(a[1], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		must(e)
		_, e = f.Write(raw)
		must(e)
		must(f.Close())
	case len(a) == 2 && a[0] == "id":
		h := hostFor(a[1])
		defer h.Close()
		fmt.Println(h.ID())
	case len(a) == 2 && a[0] == "sign":
		raw, e := os.ReadFile(a[1])
		must(e)
		key, e := lc.UnmarshalPrivateKey(raw)
		must(e)
		var fields map[string]any
		must(json.NewDecoder(io.LimitReader(os.Stdin, 4096)).Decode(&fields))
		sig, e := key.Sign(canon(fields))
		must(e)
		fields["sig"] = hex.EncodeToString(sig)
		os.Stdout.Write(canon(fields))
	case len(a) == 3 && (a[0] == "exchange" || a[0] == "discover" || a[0] == "paid-discover" || a[0] == "stop"):
		h := hostFor(a[2])
		defer h.Close()
		info, e := peer.AddrInfoFromString(a[1])
		must(e)
		ctx, cancel := context.WithTimeout(network.WithAllowLimitedConn(context.Background(), "compute"), 30*time.Second)
		defer cancel()
		must(h.Connect(ctx, *info))
		protocol := "/dsmack/job/1"
		if a[0] == "stop" {
			protocol = "/dsmack/payments-stop/1"
		}
		if a[0] == "paid-discover" {
			protocol = "/dsmack/payments-attest/1"
		}
		if a[0] == "discover" {
			protocol = "/dsmack/attest/1"
		}
		s, e := h.NewStream(ctx, info.ID, protocolpkg.ID(protocol))
		must(e)
		defer s.Close()
		if a[0] == "stop" {
			var request map[string]any
			must(json.NewDecoder(io.LimitReader(os.Stdin, 4096)).Decode(&request))
			must(writeFrame(s, request))
			var reply map[string]any
			must(readFrame(s, 4096, &reply))
			os.Stdout.Write(canon(reply))
			return
		}
		if a[0] == "discover" || a[0] == "paid-discover" {
			if a[0] == "paid-discover" {
				var q map[string]string
				must(json.NewDecoder(io.LimitReader(os.Stdin, 4096)).Decode(&q))
				must(writeFrame(s, q))
			}
			s.SetDeadline(time.Now().Add(20 * time.Second))
			_, e = io.Copy(os.Stdout, io.LimitReader(s, 150001))
			must(e)
			return
		}
		done := make(chan struct{})
		go func() { io.Copy(s, os.Stdin); s.CloseWrite(); close(done) }()
		_, e = io.Copy(os.Stdout, s)
		must(e)
	default:
		log.Fatal("usage: serve RELAY SECONDS BROKER_URL BROKER_KEY CDHASH WORKER | keygen FILE | id FILE | sign FILE | exchange CIRCUIT KEY | discover CIRCUIT KEY")
	}
}
