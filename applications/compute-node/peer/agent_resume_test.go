package main

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

func realResumeMCP(t *testing.T) (string, string) {
	t.Helper()
	module := os.Getenv("DSMACK_AGENT_MCP_MODULE")
	if module == "" {
		t.Skip("set DSMACK_AGENT_MCP_MODULE to the production Node MCP module")
	}
	directory := t.TempDir()
	root := filepath.Join(directory, "workspace")
	socket := filepath.Join(directory, "mcp.sock")
	if err := os.MkdirAll(filepath.Join(root, "artifacts"), 0700); err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(filepath.Join(directory, "node.log"))
	if err != nil {
		t.Fatal(err)
	}
	script := `import {pathToFileURL} from 'node:url';const {listen}=await import(pathToFileURL(process.argv[2]).href);const s=await listen({root:process.argv[3],socket:process.argv[4]});process.on('SIGTERM',()=>s.close(()=>process.exit(0)));`
	command := exec.Command("node", "--input-type=module", "-e", script, "resume-fixture", module, root, socket)
	command.Stdout = log
	command.Stderr = log
	if err = command.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() { command.Wait(); close(exited) }()
	t.Cleanup(func() {
		command.Process.Kill()
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			t.Error("owned Node MCP fixture did not stop")
		}
		log.Close()
	})
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err = os.Stat(socket); err == nil {
			break
		}
		select {
		case <-exited:
			raw, _ := os.ReadFile(log.Name())
			t.Fatalf("Node MCP exited: %s", raw)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("Node MCP readiness")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return root, socket
}

func TestAgentResumeRetainsStayAndCancelsLostToolWithoutReplay(t *testing.T) {
	root, socket := realResumeMCP(t)
	t.Setenv("AGENT_MCP_SOCKET", socket)
	pub, signer, _ := ed25519.GenerateKey(rand.Reader)
	receiptPub, receiptKey, _ := ed25519.GenerateKey(rand.Reader)
	meter := testReceiptMeter(t)
	secret, _ := ecdh.P256().GenerateKey(rand.Reader)
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
	var owner atomic.Bool
	var mu sync.Mutex
	var receipts []map[string]any
	var uploaded []byte
	var pinned map[string]any
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		sigText, _ := body["sig"].(string)
		sig, _ := hex.DecodeString(sigText)
		delete(body, "sig")
		if r.URL.Path == "/agent/receipt" {
			body = checkAgentReceipt(t, body, meter)
		} else if !ed25519.Verify(receiptPub, canon(body), sig) {
			t.Error("receipt signature")
		}
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/agent/receipt":
			receipts = append(receipts, body)
			json.NewEncoder(w).Encode(map[string]any{"stop": owner.Load(), "reason": "owner", "activeBudgetSeconds": 20})
		case "/workspaces/begin":
			pinned = map[string]any{}
			for _, field := range []string{"workspaceId", "version", "previousHash", "hash", "size"} {
				pinned[field] = body[field]
			}
			json.NewEncoder(w).Encode(map[string]any{"uploadId": "resume-upload", "offset": 0})
		case "/workspaces/chunk":
			data, err := base64.StdEncoding.DecodeString(body["data"].(string))
			if err != nil || int(body["offset"].(float64)) != len(uploaded) {
				t.Error("encrypted autosave chunk", err)
			}
			uploaded = append(uploaded, data...)
			json.NewEncoder(w).Encode(map[string]any{"offset": len(uploaded)})
		case "/workspaces/commit":
			pinned["cid"] = "b" + strings.Repeat("a", 30)
			pinned["mac"] = "fixture-mac"
			json.NewEncoder(w).Encode(map[string]any{"head": pinned})
		default:
			t.Error("unexpected route", r.URL.Path)
			http.Error(w, "route", 404)
		}
	}))
	defer broker.Close()
	n := &engine{paid: meter, secret: secret, broker: pub, signer: receiptKey, node: server.ID().String(), until: time.Now().Add(30 * time.Second), admissionUntil: time.Now().Add(25 * time.Second), seen: map[string]bool{}, resultPath: filepath.Join(root, "artifacts", "last-result")}
	retired := make(chan struct{})
	var retireOnce sync.Once
	server.SetStreamHandler(agentProtocol, func(s network.Stream) {
		n.handleMCPIdle(s, broker.URL, broker.Client(), func() { retireOnce.Do(func() { close(retired) }) }, 10*time.Second)
	})
	t.Cleanup(func() {
		owner.Store(true)
		select {
		case <-retired:
		case <-time.After(8 * time.Second):
			t.Error("retained fixture stay did not finish")
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if err = client.Connect(ctx, peer.AddrInfo{ID: server.ID(), Addrs: server.Addrs()}); err != nil {
		t.Fatal(err)
	}
	grant := grantFor(signer)
	delete(grant, "sig")
	grant["relay_peer"] = server.ID().String()
	grant["client_peer"] = client.ID().String()
	grant["sig"] = hex.EncodeToString(ed25519.Sign(signer, canon(grant)))
	admit := func(g map[string]any, resume bool) (network.Stream, map[string]any) {
		t.Helper()
		s, err := client.NewStream(ctx, server.ID(), agentProtocol)
		if err != nil {
			t.Fatal(err)
		}
		if err = writeFrame(s, admission{JobID: grant["grant_id"].(string), Grant: g, Resume: resume}); err != nil {
			t.Fatal(err)
		}
		var ready map[string]any
		if err = readFrame(s, 4096, &ready); err != nil {
			t.Fatal(err)
		}
		return s, ready
	}
	stream, ready := admit(grant, false)
	if ready["status"] != "ready" {
		t.Fatal(ready)
	}
	blocked, reply := admit(grant, true)
	blocked.Close()
	if reply["status"] != "refused" {
		t.Fatal("overlapping attachment accepted", reply)
	}
	browser := &workspaceMCP{conn: stream, reader: bufio.NewReader(stream)}
	if err = browser.rpc("server/discover", map[string]any{}, nil); err != nil {
		t.Fatal(err)
	}
	sealed := workspaceEnvelope(t, secret, grant["grant_id"].(string)+"/workspace", canon(map[string]any{"workspaceId": "resume-conversation", "key": fmt.Sprintf("%064x", 71), "head": nil}))
	if err = browser.control(map[string]any{"operation": "bind", "sealed": sealed}, nil); err != nil {
		t.Fatal(err)
	}
	lost := make(chan error, 1)
	go func() {
		lost <- browser.rpc("tools/call", map[string]any{"name": "bash", "arguments": map[string]any{"command": "printf 'once\\n' >> count.txt; sleep 3; printf 'LATE_MUST_NOT_RUN\\n' >> count.txt", "timeout": 5}}, nil)
	}()
	file := filepath.Join(root, "count.txt")
	deadline := time.Now().Add(5 * time.Second)
	for {
		if data, _ := os.ReadFile(file); strings.Contains(string(data), "once") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("real Bash never started")
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(1100 * time.Millisecond)
	stream.Reset()
	select {
	case err = <-lost:
		if err == nil {
			t.Fatal("lost result reported success")
		}
	case <-ctx.Done():
		t.Fatal("lost request did not fail")
	}
	deadline = time.Now().Add(2 * time.Second)
	var stay *agentStay
	for {
		n.mu.Lock()
		stay = n.agent
		n.mu.Unlock()
		stay.mu.Lock()
		detached := !stay.attached
		stay.mu.Unlock()
		if detached {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("old attachment did not detach")
		}
		time.Sleep(10 * time.Millisecond)
	}
	before := stay.meter.used(time.Now())
	if before < 2 {
		t.Fatal("active time missing before detach", before)
	}
	time.Sleep(2500 * time.Millisecond)
	if data, _ := os.ReadFile(file); string(data) != "once\n" {
		t.Fatalf("cancelled Bash produced a late effect or replay: %q", data)
	}
	if got := stay.meter.used(time.Now()); got != before {
		t.Fatal("disconnected idle accrued guest seconds", before, got)
	}
	foreign, err := libp2p.New(libp2p.NoListenAddrs)
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()
	if err = foreign.Connect(ctx, peer.AddrInfo{ID: server.ID(), Addrs: server.Addrs()}); err != nil {
		t.Fatal(err)
	}
	stolen, err := foreign.NewStream(ctx, server.ID(), agentProtocol)
	if err != nil {
		t.Fatal(err)
	}
	writeFrame(stolen, admission{JobID: grant["grant_id"].(string), Grant: grant, Resume: true})
	var denied map[string]any
	if err = readFrame(stolen, 4096, &denied); err != nil || denied["error"] != "grant" {
		t.Fatal("foreign Noise peer resumed a stolen grant", denied, err)
	}
	stolen.Close()
	changed := map[string]any{}
	for k, v := range grant {
		changed[k] = v
	}
	delete(changed, "sig")
	changed["seconds"] = float64(19)
	changed["sig"] = hex.EncodeToString(ed25519.Sign(signer, canon(changed)))
	rejected, reply := admit(changed, true)
	rejected.Close()
	if reply["status"] != "refused" {
		t.Fatal("different signed grant resumed retained stay", reply)
	}
	stream, ready = admit(grant, true)
	if ready["status"] != "ready" || ready["resumed"] != true {
		t.Fatal("same stay did not reattach", ready)
	}
	resumed := &workspaceMCP{conn: stream, reader: bufio.NewReader(stream)}
	if err = resumed.rpc("server/discover", map[string]any{}, nil); err != nil {
		t.Fatal(err)
	}
	var result struct {
		IsError bool `json:"isError"`
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err = resumed.rpc("tools/call", map[string]any{"name": "bash", "arguments": map[string]any{"command": "sleep 1.1; cat count.txt; printf 'NEW_CALL_OK\\n'", "timeout": 5}}, &result); err != nil || result.IsError {
		t.Fatal("new call after reattach", err, result)
	}
	if len(result.Content) == 0 || !strings.Contains(result.Content[0].Text, "once\nNEW_CALL_OK") {
		t.Fatal("workspace did not survive reattachment", result)
	}
	if stay.meter.used(time.Now()) <= before {
		t.Fatal("reattached call reset or failed to extend existing meter")
	}
	if n.telemetry()["jobs_served"] != 1 {
		t.Fatal("reattachment allocated another stay")
	}
	stay.workspace.mu.Lock()
	workspaceID := stay.workspace.id
	stay.workspace.mu.Unlock()
	if workspaceID != "resume-conversation" {
		t.Fatal("workspace binding was not retained")
	}
	owner.Store(true)
	select {
	case <-retired:
	case <-ctx.Done():
		t.Fatal("owner did not finish retained stay")
	}
	stale, reply := admit(grant, true)
	stale.Close()
	if reply["status"] != "refused" {
		t.Fatal("finalized stay replay accepted", reply)
	}
	freshGrant := map[string]any{}
	for k, v := range grant {
		freshGrant[k] = v
	}
	delete(freshGrant, "sig")
	freshGrant["grant_id"] = "fedcba9876543210fedcba9876543210"
	freshGrant["sig"] = hex.EncodeToString(ed25519.Sign(signer, canon(freshGrant)))
	next, err := client.NewStream(ctx, server.ID(), agentProtocol)
	if err != nil {
		t.Fatal(err)
	}
	writeFrame(next, admission{JobID: freshGrant["grant_id"].(string), Grant: freshGrant})
	if err = readFrame(next, 4096, &denied); err != nil || denied["status"] != "refused" {
		t.Fatal("retired guest admitted a later owner", denied, err)
	}
	next.Close()
	mu.Lock()
	defer mu.Unlock()
	finals := 0
	for _, body := range receipts {
		if body["finalReceipt"] == true {
			finals++
			if n.closedReason != "owner" || body["used"] == "0" {
				t.Fatal("final retained usage", body)
			}
		}
	}
	if finals != 1 {
		t.Fatal("final receipt emitted more than once", finals)
	}
	if pinned == nil || pinned["workspaceId"] != "resume-conversation" || pinned["version"] != float64(1) || len(uploaded) == 0 {
		t.Fatal("retained workspace did not autosave exactly once", pinned)
	}
	digest := sha256.Sum256(uploaded)
	if hex.EncodeToString(digest[:]) != pinned["hash"] {
		t.Fatal("autosave ciphertext hash")
	}
}

func TestAgentEmptyDetachDoesNotExtendIdleDeadline(t *testing.T) {
	start := time.Unix(1000, 0)
	meter := newAgentMeter(start, 20)
	meter.allow(20)
	meter.freeze(start.Add(4 * time.Minute))
	at, reason := meter.deadline(start.Add(4*time.Minute), start.Add(time.Hour), start.Add(time.Hour), 5*time.Minute)
	if reason != "idle" || !at.Equal(start.Add(5*time.Minute)) {
		t.Fatal("empty detach extended idle", at, reason)
	}
}

func TestDetachedAgentStillEndsAtIdleOrDrain(t *testing.T) {
	for _, reason := range []string{"idle", "drain"} {
		t.Run(reason, func(t *testing.T) {
			pub, key, _ := ed25519.GenerateKey(rand.Reader)
			_, signer, _ := ed25519.GenerateKey(rand.Reader)
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
				conn, err := listener.Accept()
				if err == nil {
					io.Copy(io.Discard, conn)
					conn.Close()
				}
			}()
			var mu sync.Mutex
			var final map[string]any
			broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]any
				json.NewDecoder(r.Body).Decode(&body)
				body = checkAgentReceipt(t, body, meter)
				if body["finalReceipt"] == true {
					mu.Lock()
					final = body
					mu.Unlock()
				}
				io.WriteString(w, `{"stop":false,"activeBudgetSeconds":20}`)
			}))
			defer broker.Close()
			n := &engine{paid: meter, broker: pub, signer: signer, node: server.ID().String(), until: time.Now().Add(10 * time.Second), seen: map[string]bool{}, resultPath: filepath.Join(directory, "last-result")}
			idle := 250 * time.Millisecond
			if reason == "drain" {
				idle = 5 * time.Second
				n.admissionUntil = time.Now().Add(250 * time.Millisecond)
			}
			retired := make(chan struct{})
			server.SetStreamHandler(agentProtocol, func(s network.Stream) {
				n.handleMCPIdle(s, broker.URL, broker.Client(), func() { close(retired) }, idle)
			})
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err = client.Connect(ctx, peer.AddrInfo{ID: server.ID(), Addrs: server.Addrs()}); err != nil {
				t.Fatal(err)
			}
			grant := grantFor(key)
			delete(grant, "sig")
			grant["relay_peer"] = server.ID().String()
			grant["client_peer"] = client.ID().String()
			grant["sig"] = hex.EncodeToString(ed25519.Sign(key, canon(grant)))
			stream, err := client.NewStream(ctx, server.ID(), agentProtocol)
			if err != nil {
				t.Fatal(err)
			}
			writeFrame(stream, admission{JobID: grant["grant_id"].(string), Grant: grant})
			var ready map[string]any
			if err = readFrame(stream, 4096, &ready); err != nil || ready["status"] != "ready" {
				t.Fatal(ready, err)
			}
			stream.Reset()
			select {
			case <-retired:
			case <-ctx.Done():
				t.Fatal("detached stay did not end", reason)
			}
			mu.Lock()
			defer mu.Unlock()
			if final == nil || n.closedReason != reason || final["used"] != "0" {
				t.Fatal("detached final reason/billing", final)
			}
		})
	}
}
