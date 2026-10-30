package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
)

const agentProtocol = "/dsmack/agent-mcp/1.0.0"
const agentIdle = 5 * time.Minute

// Authentication reuses the existing broker grant/admission handshake. Once the
// ready frame is sent, the stream is exclusively MCP stdio-framed JSON-RPC.
func (n *engine) handleMCP(s network.Stream, brokerURL string, client *http.Client, retire func()) {
	n.handleMCPIdle(s, brokerURL, client, retire, agentIdle)
}

func (n *engine) handleMCPIdle(s network.Stream, brokerURL string, client *http.Client, retire func(), idleTimeout time.Duration) {
	defer s.Close()
	s.SetDeadline(time.Now().Add(20 * time.Second))
	var a admission
	refuse := func(code string, details ...string) {
		n.recordError(strings.Join(append([]string{code}, details...), ": "))
		writeFrame(s, map[string]string{"status": "refused", "error": code})
	}
	if readFrame(s, 4096, &a) != nil {
		refuse("grant")
		return
	}
	t, err := checkGrant(a.Grant, n.broker, n.node, s.Conn().RemotePeer().String(), time.Now().Unix())
	if err != nil || a.JobID != t.id {
		refuse("grant")
		return
	}
	n.mu.Lock()
	if n.busy || n.seen[a.JobID] || (!n.admissionUntil.IsZero() && !time.Now().Before(n.admissionUntil)) {
		n.mu.Unlock()
		refuse("busy")
		return
	}
	left := min(t.seconds, t.expires-time.Now().Unix(), int64(time.Until(n.until).Seconds()))
	if left < 1 {
		n.mu.Unlock()
		refuse("grant")
		return
	}
	n.busy = true
	n.jobsServed++
	n.seen[a.JobID] = true
	n.mu.Unlock()
	// A conversation owns this whole guest. Retiring it prevents later owners
	// from observing files left in its workspace.
	defer retire()
	defer func() { n.mu.Lock(); n.busy = false; n.mu.Unlock() }()
	start := time.Now()
	used := func() int64 { return min(left, max(0, int64(math.Ceil(time.Since(start).Seconds())))) }
	var receiptMu sync.Mutex
	finalized := false
	receipt := func(final bool) (bool, error) {
		receiptMu.Lock()
		defer receiptMu.Unlock()
		if finalized {
			return true, nil
		}
		if final {
			finalized = true
		}
		body := map[string]any{"sessionId": t.id, "node_peer": n.node, "guestSeconds": used(), "final": final}
		body["sig"] = hex.EncodeToString(ed25519.Sign(n.signer, canon(body)))
		// Retain the signed original before submitting, including when the broker
		// is unavailable during shutdown. It can be replayed idempotently.
		resultPath := n.resultPath
		if resultPath == "" {
			resultPath = "/workspace/artifacts/last-result"
		}
		if file, err := os.OpenFile(filepath.Join(filepath.Dir(resultPath), "agent-receipts"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600); err == nil {
			_, err = file.Write(append(canon(body), '\n'))
			if err == nil {
				err = file.Sync()
			}
			file.Close()
			if err != nil {
				return true, err
			}
		} else {
			return true, err
		}
		var result struct {
			Stop bool `json:"stop"`
		}
		var err error
		attempts := 1
		if final {
			attempts = 3
		}
		for i := 0; i < attempts; i++ {
			err = post(client, strings.TrimRight(brokerURL, "/")+"/agent/receipt", body, &result)
			if err == nil {
				break
			}
		}

		return result.Stop, err
	}
	defer func() {
		if _, err := receipt(true); err != nil {
			n.recordError("agent final receipt: " + err.Error())
			fmt.Fprintln(os.Stderr, "agent final receipt:", err)
		}
	}()
	// Persist trusted start before accepting any MCP call. Credit and ownership
	// failures close the session before the Node tool server can execute a tool.
	if stop, err := receipt(false); err != nil || stop {
		detail := "broker requested stop"
		if err != nil {
			detail = err.Error()
		}
		refuse("metering", detail)
		return
	}
	socket := os.Getenv("AGENT_MCP_SOCKET")
	if socket == "" {
		socket = "/run/dsmack/agent-mcp.sock"
	}
	conn, err := net.DialTimeout("unix", socket, 5*time.Second)
	if err != nil {
		refuse("tool_server_unavailable", err.Error())
		return
	}
	defer conn.Close()
	workspace := &workspaceSession{}
	// Save while the grant is still non-final; retirement and its final signed
	// receipt happen only after this deferred ciphertext transfer finishes.
	defer func() {
		var err error
		for attempt := 0; attempt < 3; attempt++ {
			err = workspace.save(n, socket, brokerURL, t.id, client)
			if err == nil {
				return
			}
			if time.Until(n.until) <= time.Second {
				break
			}
			time.Sleep(250 * time.Millisecond)
		}
		n.recordError("workspace autosave failed: " + err.Error())
		fmt.Fprintln(os.Stderr, "workspace autosave failed:", err)
	}()
	var outputMu sync.Mutex
	send := func(line []byte) error {
		outputMu.Lock()
		defer outputMu.Unlock()
		_, err := s.Write(append(append([]byte(nil), line...), '\n'))
		return err
	}
	if writeFrame(s, map[string]string{"status": "ready"}) != nil {
		return
	}
	s.SetDeadline(start.Add(time.Duration(left) * time.Second))
	var activityMu sync.Mutex
	lastActivity := time.Now()
	done := make(chan struct{})
	leaseEnded := make(chan struct{})
	defer close(done)
	go func() {
		defer close(leaseEnded)
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		checkpoint := time.Now()
		for {
			select {
			case <-done:
				return
			case <-tick.C:
				activityMu.Lock()
				idle := time.Since(lastActivity) >= idleTimeout
				activityMu.Unlock()
				if idle || time.Since(start) >= time.Duration(left)*time.Second {
					s.SetDeadline(time.Now())
					conn.Close()
					return
				}
				if time.Since(checkpoint) < 5*time.Second {
					continue
				}
				checkpoint = time.Now()
				if stop, err := receipt(false); err != nil || stop {
					if err != nil {
						n.recordError("agent receipt checkpoint: " + err.Error())
						fmt.Fprintln(os.Stderr, "agent receipt checkpoint:", err)
					}
					s.SetDeadline(time.Now())
					conn.Close()
					return
				}
			}
		}
	}()
	// Only tools/call activity extends the lease. Resource/status polling cannot
	// hold an idle guest forever. All MCP bytes stay inside the attested peer.
	incomingDone := make(chan struct{})
	go func() {
		defer close(incomingDone)
		scanner := bufio.NewScanner(s)
		scanner.Buffer(make([]byte, 64<<10), 4<<20)
		for scanner.Scan() {
			line := scanner.Bytes()
			var message struct {
				Method string `json:"method"`
			}
			if json.Unmarshal(line, &message) != nil {
				n.recordError("agent MCP invalid JSON")
				break
			}
			if message.Method == "tools/call" {
				activityMu.Lock()
				lastActivity = time.Now()
				activityMu.Unlock()
			}
			forwarded, err := workspace.request(n, t.id, line)
			if err != nil {
				var request struct {
					ID json.RawMessage `json:"id"`
				}
				json.Unmarshal(line, &request)
				if send(canon(map[string]any{"jsonrpc": "2.0", "id": request.ID, "error": map[string]any{"code": -32602, "message": err.Error()}})) != nil {
					break
				}
				continue
			}
			if _, err := conn.Write(append(append([]byte(nil), forwarded...), '\n')); err != nil {
				break
			}
		}
		conn.Close()
	}()
	responses := bufio.NewScanner(conn)
	responses.Buffer(make([]byte, 64<<10), 8<<20)
	for responses.Scan() {
		line := responses.Bytes()
		workspace.observe(line)
		if send(line) != nil {
			break
		}
	}
	conn.Close()
	s.SetDeadline(time.Now())
	<-incomingDone
	// A dropped browser stream does not end a conversation lease. Keep
	// metering until the idle deadline or a signed owner end request.
	<-leaseEnded
}
