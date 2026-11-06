package main

import (
	"bufio"
	"bytes"
	payments "dsmack-payments"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
)

const agentProtocol = "/dsmack/agent-mcp/1.0.0"
const agentIdle = 5 * time.Minute

// The grant owns a stay; network streams are replaceable attachments to it.
type agentStay struct {
	meter     *agentMeter
	workspace *workspaceSession
	mu        sync.Mutex
	grant     []byte
	peer      string
	attached  bool
	closed    bool
	current   *agentAttachment
	serve     func(network.Stream, bool) bool
}
type agentAttachment struct {
	stop func()
	done chan struct{}
}

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
	if a.Resume {
		stay := n.agent
		n.mu.Unlock()
		if stay == nil {
			refuse("resume")
			return
		}
		stay.mu.Lock()
		valid := !stay.closed && !stay.attached && bytes.Equal(stay.grant, canon(a.Grant)) && stay.peer == s.Conn().RemotePeer().String() && time.Now().Before(n.until) && (n.admissionUntil.IsZero() || time.Now().Before(n.admissionUntil))
		if valid {
			stay.attached = true
		}
		stay.mu.Unlock()
		if !valid {
			refuse("resume")
			return
		}
		stay.serve(s, true)
		return
	}
	if n.agent != nil || n.busy || n.seen[a.JobID] || (!n.admissionUntil.IsZero() && !time.Now().Before(n.admissionUntil)) {
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
		if n.paid == nil {
			return true, fmt.Errorf("attested secp256k1 receipt meter required")
		}
		purchase, _ := new(big.Int).SetString(t.id, 16)
		body, err := n.paid.Receipt(payments.Grant{PurchaseID: purchase.String(), Unit: 1,
			Amount: strconv.FormatInt(t.seconds, 10), ServiceUntil: t.expires}, used(), final)
		if err != nil {
			return true, err
		}
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
	stay := &agentStay{meter: meter, workspace: workspace, grant: canon(a.Grant), peer: s.Conn().RemotePeer().String(), attached: true}
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
			stay.mu.Lock()
			stay.closed = true
			current := stay.current
			stay.mu.Unlock()
			if current != nil {
				current.stop()
				<-current.done
			} else {
				meter.freeze(time.Now())
			}
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
	// Each attachment gets its own Unix MCP session, without rebinding or
	// restoring the singleton workspace. A lost request is cancelled, never replayed.
	stay.serve = func(stream network.Stream, resumed bool) bool {
		attachment := &agentAttachment{done: make(chan struct{})}
		defer func() {
			stay.mu.Lock()
			if stay.current == attachment {
				stay.current = nil
			}
			stay.attached = false
			stay.mu.Unlock()
			close(attachment.done)
		}()
		conn, err := net.DialTimeout("unix", socket, 5*time.Second)
		if err != nil {
			writeFrame(stream, map[string]string{"status": "refused", "error": "tool_server_unavailable"})
			return false
		}
		defer conn.Close()
		var inputMu, outputMu sync.Mutex
		writeInput := func(line []byte) error {
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, err := conn.Write(append(append([]byte(nil), line...), '\n'))
			return err
		}
		var stopOnce sync.Once
		attachment.stop = func() {
			stopOnce.Do(func() {
				inputMu.Lock()
				for _, id := range meter.freeze(time.Now()) {
					writeInput(canon(map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]any{"requestId": id, "reason": "guest attachment ended"}}))
				}
				conn.Close()
				stream.SetDeadline(time.Now())
				stream.Reset()
				inputMu.Unlock()
			})
		}
		stay.mu.Lock()
		if stay.closed {
			stay.mu.Unlock()
			return false
		}
		stay.current = attachment
		stay.mu.Unlock()
		defer attachment.stop()
		ready := map[string]any{"status": "ready"}
		if resumed {
			ready["resumed"] = true
		}
		if writeFrame(stream, ready) != nil {
			return false
		}
		stream.SetDeadline(start.Add(time.Duration(left) * time.Second))
		send := func(line []byte) error {
			outputMu.Lock()
			defer outputMu.Unlock()
			_, err := stream.Write(append(append([]byte(nil), line...), '\n'))
			return err
		}
		incomingDone := make(chan struct{})
		go func() {
			defer close(incomingDone)
			scanner := bufio.NewScanner(stream)
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
				inputMu.Lock()
				stay.mu.Lock()
				closed := stay.closed
				stay.mu.Unlock()
				if closed {
					inputMu.Unlock()
					break
				}
				normal := message.Method == "tools/call" && message.Params.Name != workspaceTool
				if normal {
					if err := meter.begin(message.ID, time.Now(), n.admissionUntil); err != nil {
						inputMu.Unlock()
						if send(canon(map[string]any{"jsonrpc": "2.0", "id": message.ID, "error": map[string]any{"code": -32000, "message": err.Error()}})) != nil {
							break
						}
						continue
					}
				}
				forwarded, err := workspace.request(n, t.id, line)
				if err != nil {
					if normal {
						meter.finish(message.ID, time.Now())
					}
					inputMu.Unlock()
					if send(canon(map[string]any{"jsonrpc": "2.0", "id": message.ID, "error": map[string]any{"code": -32602, "message": err.Error()}})) != nil {
						break
					}
					continue
				}
				err = writeInput(forwarded)
				inputMu.Unlock()
				if err != nil {
					break
				}
			}
			attachment.stop()
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
		attachment.stop()
		<-incomingDone
		return true
	}
	n.mu.Lock()
	n.agent = stay
	n.mu.Unlock()
	if !stay.serve(s, false) {
		shutdown("owner")
	}
	// A detached stay retains its meter, workspace and signed grant until its
	// ordinary idle, drain, credit or owner deadline, independently of reattachment.
	<-leaseEnded
}
