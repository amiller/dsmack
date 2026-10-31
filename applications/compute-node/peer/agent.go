package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	meter := newAgentMeter(start, t.seconds)
	used := func() int64 { return meter.used(time.Now()) }
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
		if final {
			n.mu.Lock()
			reason := n.closedReason
			n.mu.Unlock()
			if reason != "" {
				body["closedReason"] = reason
			}
		}
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
			Stop                bool   `json:"stop"`
			Reason              string `json:"reason"`
			ActiveBudgetSeconds *int64 `json:"activeBudgetSeconds"`
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

		if err == nil {
			if result.ActiveBudgetSeconds == nil {
				err = fmt.Errorf("broker omitted active guest budget")
			} else {
				err = meter.allow(*result.ActiveBudgetSeconds)
			}
		}
		if result.Stop && result.Reason != "" {
			n.mu.Lock()
			n.closedReason = result.Reason
			n.mu.Unlock()
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
	var inputMu sync.Mutex
	writeInput := func(line []byte) error {
		inputMu.Lock()
		defer inputMu.Unlock()
		_, err := conn.Write(append(append([]byte(nil), line...), '\n'))
		return err
	}
	cancelActive := func() {
		for _, id := range meter.freeze(time.Now()) {
			writeInput(canon(map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]any{"requestId": id, "reason": "guest stay ended"}}))
		}
	}
	done := make(chan struct{})
	leaseEnded := make(chan struct{})
	defer close(done)
	var endOnce sync.Once
	shutdown := func(reason string) {
		endOnce.Do(func() {
			n.mu.Lock()
			if n.closedReason == "" {
				n.closedReason = reason
			}
			n.mu.Unlock()
			cancelActive()
			s.SetDeadline(time.Now())
			conn.Close()
			close(leaseEnded)
		})
	}
	// This timer remains independent of HTTP checkpoints: a stalled broker must
	// never let a running command exceed the last authenticated credit window.
	go func() {
		wall := start.Add(time.Duration(left) * time.Second)
		for {
			deadline, _ := meter.deadline(time.Now(), wall, n.admissionUntil, idleTimeout)
			timer := time.NewTimer(max(0, time.Until(deadline)))
			select {
			case <-done:
				timer.Stop()
				return
			case <-meter.changed:
				timer.Stop()
			case <-timer.C:
				// An acknowledgement can extend credit as a timer fires.
				// Re-read the current state before cancelling a tool.
				actual, currentReason := meter.deadline(time.Now(), wall, n.admissionUntil, idleTimeout)
				if !actual.After(time.Now()) {
					shutdown(currentReason)
					return
				}
			}
		}
	}()
	go func() {
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-leaseEnded:
				return
			case <-tick.C:
				if stop, err := receipt(false); err != nil || stop {
					if err != nil {
						n.recordError("agent receipt checkpoint: " + err.Error())
					}
					shutdown("credit")
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
				ID     json.RawMessage `json:"id"`
				Method string          `json:"method"`
				Params struct {
					Name string `json:"name"`
				} `json:"params"`
			}
			if json.Unmarshal(line, &message) != nil {
				n.recordError("agent MCP invalid JSON")
				break
			}
			normal := message.Method == "tools/call" && message.Params.Name != workspaceTool
			if normal {
				if err := meter.begin(message.ID, time.Now(), n.admissionUntil); err != nil {
					send(canon(map[string]any{"jsonrpc": "2.0", "id": message.ID, "error": map[string]any{"code": -32000, "message": err.Error()}}))
					continue
				}
			}
			forwarded, err := workspace.request(n, t.id, line)
			if err != nil {
				if normal {
					meter.finish(message.ID, time.Now())
				}
				var request struct {
					ID json.RawMessage `json:"id"`
				}
				json.Unmarshal(line, &request)
				if send(canon(map[string]any{"jsonrpc": "2.0", "id": request.ID, "error": map[string]any{"code": -32602, "message": err.Error()}})) != nil {
					break
				}
				continue
			}
			if err := writeInput(forwarded); err != nil {
				break
			}
		}
		cancelActive()
		conn.Close()
	}()
	responses := bufio.NewScanner(conn)
	responses.Buffer(make([]byte, 64<<10), 8<<20)
	for responses.Scan() {
		line := responses.Bytes()
		var response struct {
			ID     json.RawMessage `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		if json.Unmarshal(line, &response) == nil && (len(response.Result) > 0 || len(response.Error) > 0) {
			meter.finish(response.ID, time.Now())
		}
		workspace.observe(line)
		if send(line) != nil {
			break
		}
	}
	conn.Close()
	s.SetDeadline(time.Now())
	<-incomingDone
	// A dropped browser stream retains the workspace until idle or owner end.
	// Cancelled tools stop the active meter immediately; this wait is unbilled.
	<-leaseEnded
}
