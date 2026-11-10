package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// A broker outage shorter than checkpointGrace leaves the stay up; one that outlasts it ends the
// stay with the broker's error recorded.
func TestAgentCheckpointRidesOutBrokerOutage(t *testing.T) {
	every, grace := checkpointEvery, checkpointGrace
	checkpointEvery, checkpointGrace = 50*time.Millisecond, time.Second
	defer func() { checkpointEvery, checkpointGrace = every, grace }()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, receiptKey, _ := ed25519.GenerateKey(rand.Reader)
	meter := testReceiptMeter(t)
	server, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := libp2p.New(libp2p.NoListenAddrs)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	directory := t.TempDir()
	socket := filepath.Join(directory, "mcp.sock")
	t.Setenv("AGENT_MCP_SOCKET", socket)
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			go io.Copy(io.Discard, conn)
		}
	}()
	var down atomic.Bool
	var failed, served atomic.Int64
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var receipt map[string]any
		json.NewDecoder(r.Body).Decode(&receipt)
		checkAgentReceipt(t, receipt, meter)
		if down.Load() {
			failed.Add(1)
			http.Error(w, "upstream_tls_or_io: test outage", http.StatusBadGateway)
			return
		}
		served.Add(1)
		io.WriteString(w, `{"stop":false,"activeBudgetSeconds":20}`)
	}))
	defer broker.Close()
	n := &engine{paid: meter, broker: pub, signer: receiptKey, node: server.ID().String(), until: time.Now().Add(time.Minute), seen: map[string]bool{}, resultPath: filepath.Join(directory, "last-result")}
	retired := make(chan time.Time, 1)
	server.SetStreamHandler(agentProtocol, func(s network.Stream) {
		n.handleMCPIdle(s, broker.URL, broker.Client(), func() { retired <- time.Now() }, time.Minute)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Connect(ctx, peer.AddrInfo{ID: server.ID(), Addrs: server.Addrs()}); err != nil {
		t.Fatal(err)
	}
	grant := grantFor(priv)
	delete(grant, "sig")
	grant["relay_peer"], grant["client_peer"] = server.ID().String(), client.ID().String()
	grant["sig"] = hex.EncodeToString(ed25519.Sign(priv, canon(grant)))
	stream, err := client.NewStream(ctx, server.ID(), agentProtocol)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	writeFrame(stream, admission{JobID: grant["grant_id"].(string), Grant: grant})
	var ready map[string]string
	if err := readFrame(stream, 4096, &ready); err != nil || ready["status"] != "ready" {
		t.Fatal(ready, err)
	}

	down.Store(true)
	time.Sleep(600 * time.Millisecond)
	down.Store(false)
	before := served.Load()
	time.Sleep(400 * time.Millisecond)
	select {
	case <-retired:
		t.Fatal("a 600 ms broker outage ended the stay", n.telemetry())
	default:
	}
	if failed.Load() < 5 || served.Load() <= before {
		t.Fatal("checkpoints did not fail during the outage and resume after it", failed.Load(), served.Load(), before)
	}

	down.Store(true)
	began := time.Now()
	select {
	case at := <-retired:
		if elapsed := at.Sub(began); elapsed < time.Second || elapsed > 2*time.Second {
			t.Fatal("stay ended outside the grace bound", elapsed)
		}
	case <-ctx.Done():
		t.Fatal("a lasting broker outage did not end the stay")
	}
	status := n.telemetry()
	if status["closed_reason"] != "credit" || !strings.Contains(status["last_error"].(string), "502") {
		t.Fatal("lasting outage must end the stay with the broker's error", status)
	}
}
