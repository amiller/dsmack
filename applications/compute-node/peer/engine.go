package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sync"
	"time"
)

func canon(v any) []byte {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		panic(err)
	}
	return bytes.TrimSuffix(b.Bytes(), []byte{'\n'})
}
func readFrame(r io.Reader, max uint32, out any) error {
	var n uint32
	if e := binary.Read(r, binary.BigEndian, &n); e != nil {
		return e
	}
	if n == 0 || n > max {
		return fmt.Errorf("frame size")
	}
	b := make([]byte, n)
	if _, e := io.ReadFull(r, b); e != nil {
		return e
	}
	return json.Unmarshal(b, out)
}
func writeFrame(w io.Writer, v any) error {
	b := canon(v)
	if e := binary.Write(w, binary.BigEndian, uint32(len(b))); e != nil {
		return e
	}
	_, e := io.Copy(w, bytes.NewReader(b))
	return e
}
func validID(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 16 && hex.EncodeToString(b) == s
}

type admission struct {
	JobID string         `json:"job_id"`
	Grant map[string]any `json:"grant"`
}

type terms struct {
	id               string
	seconds, expires int64
}

func checkGrant(g map[string]any, key ed25519.PublicKey, node, client string, now int64) (terms, error) {
	fail := func() (terms, error) { return terms{}, fmt.Errorf("grant") }
	sig, ok := g["sig"].(string)
	if !ok {
		return fail()
	}
	signature, e := hex.DecodeString(sig)
	if e != nil {
		return fail()
	}
	body := make(map[string]any)
	for k, v := range g {
		if k != "sig" {
			body[k] = v
		}
	}
	if len(body) != 7 || !ed25519.Verify(key, canon(body), signature) {
		return fail()
	}
	id, _ := body["grant_id"].(string)
	seconds, sok := body["seconds"].(float64)
	expiry, eok := body["expires_at"].(float64)
	if body["v"] != float64(1) || body["unit"] != "seconds" || body["relay_peer"] != node || body["client_peer"] != client || !validID(id) || !sok || !eok || seconds < 1 || seconds > 1800 || math.Trunc(seconds) != seconds || math.Trunc(expiry) != expiry || expiry <= float64(now) {
		return fail()
	}
	return terms{id: id, seconds: int64(seconds), expires: int64(expiry)}, nil
}

type engine struct {
	secret         *ecdh.PrivateKey
	signer         ed25519.PrivateKey
	broker         ed25519.PublicKey
	node           string
	until          time.Time
	admissionUntil time.Time
	resultPath     string
	mu             sync.Mutex
	seen           map[string]bool
	busy           bool
	jobsServed     int
	lastError      string
}

func (n *engine) telemetry() map[string]any {
	n.mu.Lock()
	defer n.mu.Unlock()
	var lastError any
	if n.lastError != "" {
		lastError = n.lastError
	}
	status := map[string]any{"relay_peer": n.node, "updated_at": time.Now().Unix(),
		"busy": n.busy, "jobs_served": n.jobsServed, "last_error": lastError}
	message := append([]byte("dsmack-node-status/1\n"), canon(status)...)
	status["signature"] = hex.EncodeToString(ed25519.Sign(n.signer, message))
	return status
}

func (n *engine) recordError(message string) {
	n.mu.Lock()
	n.lastError = message
	n.mu.Unlock()
}
