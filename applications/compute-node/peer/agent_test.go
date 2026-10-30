package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

func TestAgentMCPAdmissionIdentityIdleAndSignedMetering(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	receiptPub, receiptKey, _ := ed25519.GenerateKey(rand.Reader)
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
	artifacts := t.TempDir()
	var mu sync.Mutex
	var receipts []map[string]any
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		sig, _ := hex.DecodeString(body["sig"].(string))
		delete(body, "sig")
		if r.URL.Path != "/agent/receipt" || !ed25519.Verify(receiptPub, canon(body), sig) {
			t.Error("guest receipt signature or route")
		}
		mu.Lock()
		receipts = append(receipts, body)
		mu.Unlock()
		io.WriteString(w, `{"stop":false}`)
	}))
	defer broker.Close()
	n := &engine{broker: pub, signer: receiptKey, node: server.ID().String(), until: time.Now().Add(time.Minute), seen: map[string]bool{}, resultPath: filepath.Join(artifacts, "last-result")}
	retired := make(chan struct{}, 1)
	server.SetStreamHandler(agentProtocol, func(s network.Stream) {
		n.handleMCPIdle(s, broker.URL, broker.Client(), func() { retired <- struct{}{} }, 20*time.Millisecond)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Connect(ctx, peer.AddrInfo{ID: server.ID(), Addrs: server.Addrs()}); err != nil {
		t.Fatal(err)
	}
	grant := grantFor(priv)
	delete(grant, "sig")
	grant["relay_peer"], grant["client_peer"] = server.ID().String(), "another-browser"
	grant["sig"] = hex.EncodeToString(ed25519.Sign(priv, canon(grant)))
	stream, err := client.NewStream(ctx, server.ID(), agentProtocol)
	if err != nil {
		t.Fatal(err)
	}
	writeFrame(stream, admission{JobID: grant["grant_id"].(string), Grant: grant})
	var response map[string]string
	if readFrame(stream, 4096, &response) != nil || response["error"] != "grant" {
		t.Fatal("foreign Noise identity admitted", response)
	}
	if n.telemetry()["last_error"] != "grant" || n.telemetry()["jobs_served"] != 0 {
		t.Fatal("refused session must report its error without counting as served")
	}
	stream.Close()
	socket := filepath.Join(t.TempDir(), "mcp.sock")
	t.Setenv("AGENT_MCP_SOCKET", socket)
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	received := make(chan string, 1)
	go func() {
		conn, e := listener.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		line, _ := reader.ReadString('\n')
		received <- line
		io.WriteString(conn, `{"jsonrpc":"2.0","id":1,"result":{}}`+"\n")
		io.Copy(io.Discard, conn)
	}()
	delete(grant, "sig")
	grant["client_peer"] = client.ID().String()
	grant["sig"] = hex.EncodeToString(ed25519.Sign(priv, canon(grant)))
	stream, err = client.NewStream(ctx, server.ID(), agentProtocol)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	writeFrame(stream, admission{JobID: grant["grant_id"].(string), Grant: grant})
	if readFrame(stream, 4096, &response) != nil || response["status"] != "ready" {
		t.Fatal(response)
	}
	status := n.telemetry()
	if status["busy"] != true || status["jobs_served"] != 1 {
		t.Fatal("active MCP session missing from slot telemetry", status)
	}
	signature, _ := hex.DecodeString(status["signature"].(string))
	delete(status, "signature")
	if !ed25519.Verify(receiptPub, append([]byte("dsmack-node-status/1\n"), canon(status)...), signature) {
		t.Fatal("slot telemetry did not use the attested receipt key")
	}
	request := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n"
	stream.Write([]byte(request))
	if got := <-received; got != request {
		t.Fatal("MCP framing changed", got)
	}
	line, e := bufio.NewReader(stream).ReadString('\n')
	if e != nil || line != "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n" {
		t.Fatal("MCP output changed", line, e)
	}
	select {
	case <-retired:
	case <-ctx.Done():
		t.Fatal("idle guest was not released")
	}
	if status := n.telemetry(); status["busy"] != false || status["jobs_served"] != 1 {
		t.Fatal("retired MCP session telemetry", status)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(receipts) < 2 || receipts[len(receipts)-1]["final"] != true {
		t.Fatal("missing final metering receipt", receipts)
	}
	if receipts[len(receipts)-1]["guestSeconds"].(float64) < 1 {
		t.Fatal("guest time was not charged")
	}
	raw, err := os.ReadFile(filepath.Join(artifacts, "agent-receipts"))
	if err != nil || len(raw) == 0 {
		t.Fatal("signed receipt originals missing", err)
	}
}
