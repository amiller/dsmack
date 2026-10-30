package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
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
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"golang.org/x/crypto/hkdf"
)

func workspaceEnvelope(t *testing.T, recipient *ecdh.PrivateKey, label string, raw []byte) workspaceBox {
	t.Helper()
	ephemeral, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := ephemeral.ECDH(recipient.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	info := append([]byte("dsmack.secret-release/1"), public(ephemeral)...)
	info = append(info, public(recipient)...)
	info = append(info, []byte(label)...)
	key := make([]byte, 32)
	io.ReadFull(hkdf.New(sha256.New, shared, make([]byte, 32), info), key)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	iv := make([]byte, 12)
	rand.Read(iv)
	return workspaceBox{EPK: hex.EncodeToString(public(ephemeral)), IV: hex.EncodeToString(iv), CT: hex.EncodeToString(aead.Seal(nil, iv, raw, nil))}
}
func TestWorkspaceBindOnlyDecryptsForAdmittedGuestStay(t *testing.T) {
	secret, _ := ecdh.P256().GenerateKey(rand.Reader)
	n := &engine{secret: secret}
	w := &workspaceSession{}
	key := fmt.Sprintf("%064x", 7)
	binding := canon(map[string]any{"workspaceId": "conversation-1", "key": key, "head": nil})
	sealed := workspaceEnvelope(t, secret, "stay-1/workspace", binding)
	request := canon(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": workspaceTool, "arguments": map[string]any{"operation": "bind", "sealed": sealed}}})
	if bytes.Contains(request, []byte(key)) {
		t.Fatal("workspace key appears on browser wire")
	}
	if _, err := w.request(n, "other-stay", request); err == nil {
		t.Fatal("cross-stay envelope accepted")
	}
	forwarded, err := w.request(n, "stay-1", request)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(forwarded, []byte(key)) || bytes.Contains(forwarded, []byte("sealed")) {
		t.Fatal("private Unix request must contain only clear binding")
	}
	if w.id != "" {
		t.Fatal("binding activated before Node acknowledgement")
	}
	w.observe([]byte(`{"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"workspaceId":"conversation-1"}}}`))
	if w.id != "conversation-1" {
		t.Fatal("successful binding not retained")
	}
	raw := canon(map[string]any{"id": 2, "method": "tools/call", "params": map[string]any{"name": workspaceTool, "arguments": map[string]any{"operation": "bind", "workspaceId": "conversation-1", "key": key}}})
	if _, err = w.request(n, "stay-1", raw); err == nil {
		t.Fatal("browser supplied clear workspace key")
	}
}

// This exercises the real authenticated stream and its shutdown defers. The
// Node fixture keeps workspace state across the browser and internal sockets.
// A lost chunk acknowledgement must resume the same pending cipher before the
// final metering receipt and retirement, without ever sending a key to HTTP.
func TestWorkspaceAutosaveAfterBrowserDisconnectResumesBeforeFinalReceipt(t *testing.T) {
	testWorkspaceShutdown(t, false)
}
func TestWorkspaceUploadFailureRetainsOnlyCiphertextBeforeRetirement(t *testing.T) {
	testWorkspaceShutdown(t, true)
}
func testWorkspaceShutdown(t *testing.T, unavailable bool) {
	signingPub, signingKey, _ := ed25519.GenerateKey(rand.Reader)
	receiptPub, receiptKey, _ := ed25519.GenerateKey(rand.Reader)
	secret, _ := ecdh.P256().GenerateKey(rand.Reader)
	key := fmt.Sprintf("%064x", 19)
	directory := t.TempDir()
	socket := filepath.Join(directory, "mcp.sock")
	t.Setenv("AGENT_MCP_SOCKET", socket)
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	cipherBytes := bytes.Repeat([]byte{0x9a}, workspaceChunk+97)
	hash := sha256.Sum256(cipherBytes)
	head := map[string]any{"workspaceId": "conversation-1", "version": 1, "previousHash": fmt.Sprintf("%064x", 0), "hash": hex.EncodeToString(hash[:]), "size": len(cipherBytes)}
	var mu sync.Mutex
	bound, committed, failedChunk, finalSeen := false, false, false, false
	uploaded := []byte{}
	connections := 0
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				scanner := bufio.NewScanner(conn)
				scanner.Buffer(make([]byte, 4096), 1<<20)
				for scanner.Scan() {
					var req struct {
						ID     any    `json:"id"`
						Method string `json:"method"`
						Params struct {
							Name      string         `json:"name"`
							Arguments map[string]any `json:"arguments"`
						} `json:"params"`
					}
					if json.Unmarshal(scanner.Bytes(), &req) != nil {
						return
					}
					if req.ID == nil {
						continue
					}
					var result any = map[string]any{}
					mu.Lock()
					if req.Method == "initialize" {
						connections++
					} else {
						args := req.Params.Arguments
						var value any
						switch args["operation"] {
						case "bind":
							if args["key"] != key {
								t.Error("wrong private binding key")
							}
							bound = true
							value = map[string]any{"workspaceId": "conversation-1", "head": nil, "restored": true}
						case "seal":
							if !bound {
								t.Error("autosave lost singleton binding")
							}
							value = head
						case "read":
							offset := int(args["offset"].(float64))
							length := int(args["length"].(float64))
							end := min(len(cipherBytes), offset+length)
							value = map[string]any{"offset": offset, "data": base64.StdEncoding.EncodeToString(cipherBytes[offset:end]), "eof": end == len(cipherBytes)}
						case "commit":
							committed = true
							value = map[string]any{"head": args["head"], "committed": true}
						default:
							t.Errorf("unexpected internal operation %v", args["operation"])
						}
						result = map[string]any{"structuredContent": value}
					}
					mu.Unlock()
					if _, err = conn.Write(append(canon(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result}), '\n')); err != nil {
						return
					}
				}
			}()
		}
	}()
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if bytes.Contains(raw, []byte(key)) {
			t.Error("workspace key escaped through HTTP")
		}
		var body map[string]any
		json.Unmarshal(raw, &body)
		sig, _ := hex.DecodeString(body["sig"].(string))
		delete(body, "sig")
		if !ed25519.Verify(receiptPub, canon(body), sig) {
			t.Error("unsigned workspace/receipt request")
		}
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == "/agent/receipt" {
			if body["final"] == true {
				if !committed && !unavailable {
					t.Error("final receipt before durable workspace commit")
				}
				finalSeen = true
			}
			io.WriteString(w, `{"stop":false,"activeBudgetSeconds":20}`)
			return
		}
		if finalSeen {
			t.Error("workspace upload after final receipt")
		}
		if body["workspaceId"] != "conversation-1" || body["sessionId"] == nil || body["node_peer"] == nil {
			t.Error("workspace auth binding")
		}
		var result any
		switch r.URL.Path {
		case "/workspaces/begin":
			if unavailable {
				w.WriteHeader(503)
				io.WriteString(w, `{"error":"offline"}`)
				return
			}
			if body["action"] != "workspace-begin" || body["hash"] != head["hash"] {
				t.Error("wrong begin binding")
			}
			result = map[string]any{"uploadId": "pending", "offset": len(uploaded)}
		case "/workspaces/chunk":
			offset := int(body["offset"].(float64))
			data, _ := base64.StdEncoding.DecodeString(body["data"].(string))
			if offset != len(uploaded) || len(data) > workspaceChunk {
				t.Error("chunk resume offset/limit")
			}
			uploaded = append(uploaded, data...)
			if !failedChunk {
				failedChunk = true
				w.WriteHeader(503)
				io.WriteString(w, `{"error":"lost acknowledgement"}`)
				return
			}
			result = map[string]any{"offset": len(uploaded)}
		case "/workspaces/commit":
			if !bytes.Equal(uploaded, cipherBytes) {
				t.Error("uploaded cipher differs")
			}
			saved := map[string]any{}
			for k, v := range head {
				saved[k] = v
			}
			saved["cid"] = "ipfs-test-cid"
			saved["mac"] = "mac-test"
			result = map[string]any{"head": saved}
		default:
			t.Errorf("unexpected route %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(result)
	}))
	defer broker.Close()
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
	n := &engine{secret: secret, broker: signingPub, signer: receiptKey, node: server.ID().String(), until: time.Now().Add(time.Minute), seen: map[string]bool{}, resultPath: filepath.Join(directory, "last-result")}
	retired := make(chan struct{}, 1)
	server.SetStreamHandler(agentProtocol, func(s network.Stream) {
		n.handleMCPIdle(s, broker.URL, broker.Client(), func() {
			mu.Lock()
			if (!committed && !unavailable) || !finalSeen {
				t.Error("retirement before saved final state")
			}
			mu.Unlock()
			retired <- struct{}{}
		}, 20*time.Millisecond)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err = client.Connect(ctx, peer.AddrInfo{ID: server.ID(), Addrs: server.Addrs()}); err != nil {
		t.Fatal(err)
	}
	grant := grantFor(signingKey)
	delete(grant, "sig")
	grant["relay_peer"], grant["client_peer"] = server.ID().String(), client.ID().String()
	grant["sig"] = hex.EncodeToString(ed25519.Sign(signingKey, canon(grant)))
	stream, err := client.NewStream(ctx, server.ID(), agentProtocol)
	if err != nil {
		t.Fatal(err)
	}
	writeFrame(stream, admission{JobID: grant["grant_id"].(string), Grant: grant})
	var ready map[string]string
	if err = readFrame(stream, 4096, &ready); err != nil || ready["status"] != "ready" {
		t.Fatal(ready, err)
	}
	sealed := workspaceEnvelope(t, secret, grant["grant_id"].(string)+"/workspace", canon(map[string]any{"workspaceId": "conversation-1", "key": key, "head": nil}))
	request := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": workspaceTool, "arguments": map[string]any{"operation": "bind", "sealed": sealed}}}
	stream.Write(append(canon(request), '\n'))
	if _, err = bufio.NewReader(stream).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	stream.Close()
	select {
	case <-retired:
	case <-ctx.Done():
		t.Fatal("workspace was not saved and retired", n.telemetry())
	}
	mu.Lock()
	defer mu.Unlock()
	if unavailable {
		if committed || connections != 3 {
			t.Fatal("failed uploads must leave pending seal", committed, connections)
		}
		saved, err := os.ReadFile(filepath.Join(directory, "workspace-seal.bin"))
		if err != nil || !bytes.Equal(saved, cipherBytes) {
			t.Fatal("sole encrypted snapshot lost", err)
		}
		meta, err := os.ReadFile(filepath.Join(directory, "workspace-seal.json"))
		if err != nil || bytes.Contains(meta, []byte(key)) {
			t.Fatal("fallback lost or contains key", err)
		}
		var record map[string]any
		if json.Unmarshal(meta, &record) != nil {
			t.Fatal("invalid fallback head")
		}
		sig, _ := hex.DecodeString(record["sig"].(string))
		delete(record, "sig")
		if !ed25519.Verify(receiptPub, canon(record), sig) {
			t.Fatal("unsigned fallback")
		}
		if n.telemetry()["last_error"] == nil {
			t.Fatal("upload failure invisible in guest telemetry")
		}
		return
	}
	if !failedChunk || !committed || connections != 2 {
		t.Fatal("resumable internal autosave not exercised", failedChunk, committed, connections)
	}
	raw, err := os.ReadFile(filepath.Join(directory, "workspace-seal.json"))
	if err != nil || string(raw) != "null" {
		t.Fatal("committed fallback must be cleared", err, string(raw))
	}
}
