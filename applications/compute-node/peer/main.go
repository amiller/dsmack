package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"dsmack-peer/p2p"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
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
		socket := os.Getenv("DSTACK_SOCKET")
		if socket == "" {
			socket = "/var/run/dstack.sock"
		}
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}}
}

type brokerHTTPError struct {
	Status     int
	Path, Body string
	ReadError  error
}

func (e *brokerHTTPError) Error() string {
	return fmt.Sprintf("POST %s: HTTP %d body=%q read=%v", e.Path, e.Status, e.Body, e.ReadError)
}
func transientRegistration(err error) bool {
	var response *brokerHTTPError
	if errors.As(err, &response) {
		return response.Status >= 500 || response.Status == 408 || response.Status == 429
	}
	var network net.Error
	return errors.As(err, &network)
}
func post(c *http.Client, url string, in, out any) error {
	r, e := c.Post(url, "application/json", bytes.NewReader(canon(in)))
	if e != nil {
		return e
	}
	defer r.Body.Close()
	if r.StatusCode < 200 || r.StatusCode >= 300 {
		raw, readErr := io.ReadAll(io.LimitReader(r.Body, 4096))
		return &brokerHTTPError{r.StatusCode, r.Request.URL.Path, string(raw), readErr}
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

// Broker registration uses only the measured guest-local TLS gateway.
func brokerClient(raw string) (*http.Client, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	return gatewayBrokerClient(u, os.Getenv("BROKER_GATEWAY"))
}

// Draining guests retain their relay circuits while their fixed paid binding expires.
func renewAdmission(until time.Time, renew func() error) error {
	if !time.Now().Before(until) {
		return nil
	}
	return renew()
}

func serve(relay, brokerURL, brokerHex, cdhash, worker string, seconds int) (serveErr error) {
	if os.Geteuid() != 0 {
		return fmt.Errorf("agent bootstrap requires root")
	}
	socket := os.Getenv("DSTACK_SOCKET")
	if socket != "/root/dstack.sock" {
		return fmt.Errorf("agent attestation socket requires its root-private mount")
	}
	private, err := os.Stat(filepath.Dir(socket))
	if err != nil {
		return err
	}
	owner, ok := private.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 || private.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("attestation socket parent must be root-private")
	}
	for _, path := range []string{"/workspace/artifacts", "/workspace/state"} {
		if err := os.MkdirAll(path, 0700); err != nil {
			return err
		}
		if err := os.Chown(path, 0, 0); err != nil {
			return err
		}
		if err := os.Chmod(path, 0700); err != nil {
			return err
		}
	}
	paid := paidMeter()
	operatorStop := make(chan struct{})
	var stopOnce sync.Once
	key, e := hex.DecodeString(brokerHex)
	if e != nil {
		return e
	}
	if len(key) != 32 {
		return fmt.Errorf("broker key length")
	}
	reportRenewal := func(stage string, err error) { fmt.Fprintln(os.Stderr, stage, err) }
	publicRelay := relay
	var gatewayErrors <-chan error
	if index := os.Getenv("TUNNEL_INDEX"); index != "" {
		gateways, advertised, err := startNodeGateways(relay, brokerURL, index)
		if err != nil {
			return err
		}
		defer func() {
			if serveErr != nil {
				fmt.Fprintf(gateways.log, "%s\n", canon(map[string]string{"event": "node_gateway_error", "error": serveErr.Error()}))
			}
			gateways.close()
		}()
		reportRenewal = func(stage string, err error) {
			fmt.Fprintln(os.Stderr, stage, err)
			fmt.Fprintf(gateways.log, "%s\n", canon(map[string]string{"event": "registration_renewal_error", "stage": stage, "error": err.Error()}))
		}
		gatewayErrors = gateways.failed
		publicRelay = advertised
	}
	if err := os.MkdirAll("/run/dsmack", 0711); err != nil {
		return err
	}
	if err := os.Chown("/run/dsmack", 0, 0); err != nil {
		return err
	}
	if err := os.Chmod("/run/dsmack", 0711); err != nil {
		return err
	}
	toolLog, err := os.OpenFile("/workspace/artifacts/tool-server.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer toolLog.Close()
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		return err
	}
	defer readyRead.Close()
	defer readyWrite.Close()
	toolServer := exec.Command("node", worker)
	toolServer.ExtraFiles = []*os.File{readyWrite}
	toolServer.Env = append(os.Environ(), "AGENT_READY_FD=3")
	toolServer.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	toolServer.Stdout, toolServer.Stderr = toolLog, toolLog
	if err := toolServer.Start(); err != nil {
		return err
	}
	readyWrite.Close()
	toolReady := make(chan error, 1)
	go func() {
		line, err := bufio.NewReader(readyRead).ReadString('\n')
		if err == nil && line != "ready\n" {
			err = fmt.Errorf("unexpected tool ready marker")
		}
		toolReady <- err
	}()
	toolExited := make(chan error, 1)
	go func() { toolExited <- toolServer.Wait() }()
	defer func() {
		syscall.Kill(-toolServer.Process.Pid, syscall.SIGTERM)
		select {
		case <-toolExited:
		case <-time.After(5 * time.Second):
			syscall.Kill(-toolServer.Process.Pid, syscall.SIGKILL)
		}
	}()
	select {
	case err := <-toolReady:
		if err != nil {
			return fmt.Errorf("tool server readiness: %w", err)
		}
	case err := <-toolExited:
		return fmt.Errorf("tool server exited: %v", err)
	case <-time.After(20 * time.Second):
		return fmt.Errorf("tool server did not initialize before deadline")
	}
	secret, e := ecdh.P256().GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	receipt, signer, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	h := p2p.NewHost(libp2p.NoListenAddrs, libp2p.EnableRelay(), libp2p.Security(noise.ID, noise.New))
	var agentStreams sync.WaitGroup
	defer func() { h.Close(); agentStreams.Wait() }()
	var info map[string]any
	if err := post(guestClient(), "http://localhost/v1/Info", map[string]any{}, &info); err != nil {
		return err
	}
	rd := append([]byte("dsmack-compute-node/1"), []byte(h.ID())...)
	rd = append(rd, public(secret)...)
	rd = append(rd, receipt...)
	hash := sha256.Sum256(rd)
	att, e := attest(append(hash[:], make([]byte, 32)...))
	if e != nil {
		return e
	}
	var registrationMu sync.Mutex
	registration := map[string]any{"kind": "compute", "relay_peer": h.ID().String(), "relay_maddr": publicRelay + "/p2p-circuit/p2p/" + h.ID().String(), "secret_key": hex.EncodeToString(public(secret)), "receipt_key": hex.EncodeToString(receipt), "manifest_sha256": info["compose_hash"], "os_image_hash": info["os_image_hash"], "cdhash": cdhash, "attestation": hex.EncodeToString(att)}
	n := &engine{secret: secret, signer: signer, broker: key, node: h.ID().String(), until: time.Now().Add(time.Duration(seconds) * time.Second), resultPath: "/workspace/artifacts/last-result", seen: map[string]bool{}}
	if value := os.Getenv("ADMIT_SECONDS"); value != "" {
		admit, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		if admit < 1 || admit > seconds {
			return fmt.Errorf("ADMIT_SECONDS must be within serving lifetime")
		}
		n.admissionUntil = time.Now().Add(time.Duration(admit) * time.Second)
	}
	if n.admissionUntil.IsZero() {
		n.admissionUntil = n.until
	}
	registration["admit_until"] = n.admissionUntil.Unix()
	h.SetStreamHandler("/dsmack/attest/1", func(s network.Stream) {
		defer s.Close()
		s.SetDeadline(time.Now().Add(20 * time.Second))
		registrationMu.Lock()
		raw := canon(registration)
		registrationMu.Unlock()
		s.Write(raw)
	})
	c, e := brokerClient(brokerURL)
	if e != nil {
		return e
	}
	h.SetStreamHandler(agentProtocol, func(s network.Stream) {
		agentStreams.Add(1)
		defer agentStreams.Done()
		n.handleMCP(s, brokerURL, c, func() { stopOnce.Do(func() { close(operatorStop) }) })
	})
	ri, e := peer.AddrInfoFromString(relay)
	if e != nil {
		return e
	}
	reserve := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if e := h.Connect(ctx, *ri); e != nil {
			return e
		}
		_, e := client.Reserve(ctx, h, *ri)
		return e
	}
	if err := reserve(); err != nil {
		return err
	}
	renew := func() error {
		var out map[string]any
		snapshot := map[string]any{}
		for k, v := range registration {
			snapshot[k] = v
		}
		snapshot["telemetry"] = n.telemetry()
		return post(c, strings.TrimRight(brokerURL, "/")+"/nodes", snapshot, &out)
	}
	if err := os.WriteFile("/workspace/artifacts/registration", canon(registration), 0644); err != nil {
		return err
	}
	for _, file := range []struct {
		path string
		data []byte
	}{{"workspace-seal.bin", nil}, {"workspace-seal.json", []byte("null")}} {
		if err := os.WriteFile("/workspace/artifacts/"+file.path, file.data, 0600); err != nil {
			return err
		}
	}
	if err := os.WriteFile("/workspace/artifacts/last-result", canon(map[string]string{"status": "idle"}), 0644); err != nil {
		return err
	}
	if err := os.WriteFile("/workspace/artifacts/egress", []byte("{}"), 0644); err != nil {
		return err
	}
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
		if err := os.WriteFile("/workspace/artifacts/payment-receipts", []byte(""), 0644); err != nil {
			return err
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
			snapshot["telemetry"] = n.telemetry()
			if err = os.WriteFile("/workspace/artifacts/registration", canon(snapshot), 0644); err != nil {
				return err
			}
			var out map[string]any
			return post(c, strings.TrimRight(brokerURL, "/")+"/nodes", snapshot, &out)
		}
	}
	register := renew
	renew = func() error { return renewAdmission(n.admissionUntil, register) }
	// Paid runs expose their attested admission for the owner before registration.
	// An unregistered run cannot receive a grant; retries permit owner admission.
	if paid == nil {
		if err := renew(); err != nil {
			return err
		}
	} else if err := renew(); err != nil {
		fmt.Fprintln(os.Stderr, "awaiting paid admission:", err)
	}
	fmt.Println("compute node registered", h.ID())
	tick := time.NewTicker(25 * time.Second)
	defer tick.Stop()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, os.Interrupt)
	defer signal.Stop(stop)
	renewalFailures := 0
	timer := time.NewTimer(time.Until(n.until))
	defer timer.Stop()
	for {
		select {
		case err := <-toolExited:
			return fmt.Errorf("tool server exited: %v", err)
		case err := <-gatewayErrors:
			return err
		case <-tick.C:
			if err := reserve(); err != nil {
				return err
			}
			if paid == nil {
				if err := renew(); err != nil {
					renewalFailures++
					reportRenewal(fmt.Sprintf("broker lease renewal %d/3", renewalFailures), err)
					if !transientRegistration(err) || renewalFailures >= 3 {
						return err
					}
				} else {
					renewalFailures = 0
				}
			} else if err := renew(); err != nil {
				fmt.Fprintln(os.Stderr, "paid registration:", err)
			}
		case <-timer.C:
			return nil
		case <-operatorStop:
			return nil
		case <-stop:
			return nil
		}
	}
}
func main() {
	a := os.Args[1:]
	if len(a) != 7 || a[0] != "serve" {
		log.Fatal("usage: serve RELAY SECONDS BROKER_URL BROKER_KEY CDHASH TOOL_SERVER")
	}
	seconds, e := strconv.Atoi(a[2])
	must(e)
	if seconds < 1 || seconds > 86400 {
		log.Fatal("duration")
	}
	must(serve(a[1], a[3], a[4], a[5], a[6], seconds))
}
