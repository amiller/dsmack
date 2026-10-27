package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// Field order is the shared sorted-key, UTF-8 JSON signing format.
type grantBody struct {
	Bytes      int64  `json:"bytes"`
	ClientPeer string `json:"client_peer"`
	ExpiresAt  int64  `json:"expires_at"`
	GrantID    string `json:"grant_id"`
	RelayPeer  string `json:"relay_peer"`
	V          int    `json:"v"`
}
type grant struct {
	grantBody
	Sig string `json:"sig"`
}

func canonical(v any) []byte { b, err := json.Marshal(v); must(err); return b }

func verifyGrant(raw []byte, key ed25519.PublicKey, relay, client peer.ID, now time.Time) (grantBody, error) {
	var g grant
	if err := json.Unmarshal(raw, &g); err != nil {
		return g.grantBody, fmt.Errorf("grant JSON: %w", err)
	}
	// Re-encode decoded fields, so alternate escapes, unknown/duplicate fields
	// and whitespace cannot bypass the shared canonical JSON format.
	fields := map[string]any{"bytes": g.Bytes, "client_peer": g.ClientPeer, "expires_at": g.ExpiresAt, "grant_id": g.GrantID, "relay_peer": g.RelayPeer, "sig": g.Sig, "v": g.V}
	if !bytes.Equal(raw, canonical(fields)) {
		return g.grantBody, fmt.Errorf("grant must be canonical JSON with seven fields")
	}
	id, err := hex.DecodeString(g.GrantID)
	if err != nil || len(id) != 16 || g.V != 1 || g.Bytes <= 0 {
		return g.grantBody, fmt.Errorf("invalid grant version, id or budget")
	}
	sig, err := hex.DecodeString(g.Sig)
	if err != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, canonical(g.grantBody), sig) {
		return g.grantBody, fmt.Errorf("invalid broker signature")
	}
	if g.RelayPeer != relay.String() || g.ClientPeer != client.String() {
		return g.grantBody, fmt.Errorf("grant peer mismatch")
	}
	if g.ExpiresAt <= now.Unix() {
		return g.grantBody, fmt.Errorf("grant expired")
	}
	return g.grantBody, nil
}

// Frames are a four-byte big-endian length followed by canonical JSON (at most 4 KiB).
func readGrant(r io.Reader) ([]byte, error) {
	var size uint32
	if err := binary.Read(r, binary.BigEndian, &size); err != nil {
		return nil, err
	}
	if size == 0 || size > 4096 {
		return nil, fmt.Errorf("grant length outside 1..4096")
	}
	b := make([]byte, size)
	_, err := io.ReadFull(r, b)
	return b, err
}
func writeGrant(w io.Writer, b []byte) error {
	if len(b) == 0 || len(b) > 4096 {
		return fmt.Errorf("grant length outside 1..4096")
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(b))); err != nil {
		return err
	}
	_, err := io.Copy(w, bytes.NewReader(b))
	return err
}

type usage struct {
	grantBody
	mu            sync.Mutex
	cond          *sync.Cond
	used, pending int64
	closed        bool
	streams       map[stream]struct{}
}

func newUsage(g grantBody) *usage {
	u := &usage{grantBody: g, streams: make(map[stream]struct{})}
	u.cond = sync.NewCond(&u.mu)
	return u
}
func (u *usage) attach(s stream) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed || u.used >= u.Bytes || time.Now().Unix() >= u.ExpiresAt {
		return fmt.Errorf("grant exhausted or expired")
	}
	u.streams[s] = struct{}{}
	return nil
}
func (u *usage) detach(s stream) { u.mu.Lock(); delete(u.streams, s); u.mu.Unlock() }

// Reserve before forwarding, then settle actual successful writes. Concurrent
// streams cannot overspend, and short writes release unused reservations.
func (u *usage) forward(dst io.Writer, b []byte) (int, error) {
	u.mu.Lock()
	for !u.closed && u.used+u.pending == u.Bytes && u.used < u.Bytes {
		u.cond.Wait()
	}
	if u.closed || u.used == u.Bytes || time.Now().Unix() >= u.ExpiresAt {
		u.mu.Unlock()
		return 0, io.EOF
	}
	allowed := min(int64(len(b)), u.Bytes-u.used-u.pending)
	u.pending += allowed
	u.mu.Unlock()
	n, err := dst.Write(b[:allowed])
	u.mu.Lock()
	u.pending -= allowed
	u.used += int64(n)
	u.cond.Broadcast()
	var closeStreams []stream
	if u.used == u.Bytes {
		for s := range u.streams {
			closeStreams = append(closeStreams, s)
		}
	}
	u.mu.Unlock()
	for _, s := range closeStreams {
		s.Close()
	}
	if err == nil && n < len(b) {
		err = io.ErrShortWrite
	}
	return n, err
}
func (u *usage) copy(dst stream, src stream) {
	buf := make([]byte, 16<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, e := u.forward(dst, buf[:n]); e != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
	dst.CloseWrite()
}
func (u *usage) bridge(a, b stream) {
	// Both the authenticated stream and the uplink must wake at exhaustion/expiry.
	if err := u.attach(b); err != nil {
		b.Close()
		return
	}
	defer u.detach(b)
	deadline := time.Unix(u.ExpiresAt, 0)
	a.SetDeadline(deadline)
	b.SetDeadline(deadline)
	done := make(chan struct{})
	go func() { u.copy(a, b); close(done) }()
	u.copy(b, a)
	<-done
}

type grantBook struct {
	mu     sync.Mutex
	grants map[string]*usage
}

func (b *grantBook) accept(g grantBody, s stream) (*usage, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.grants == nil {
		b.grants = make(map[string]*usage)
	}
	u := b.grants[g.GrantID]
	if u == nil {
		u = newUsage(g)
		b.grants[g.GrantID] = u
	} else if u.grantBody != g {
		return nil, fmt.Errorf("grant id reused with different terms")
	}
	return u, u.attach(s)
}

type receiptBody struct {
	BytesUsed  int64  `json:"bytes_used"`
	ClientPeer string `json:"client_peer"`
	GrantID    string `json:"grant_id"`
	RelayPeer  string `json:"relay_peer"`
	Run        string `json:"run"`
}

func (b *grantBook) receipts(key ed25519.PrivateKey, run, client string) []map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]map[string]any, 0)
	for _, u := range b.grants {
		if client != "" && u.ClientPeer != client {
			continue
		}
		u.mu.Lock()
		r := receiptBody{u.used, u.ClientPeer, u.GrantID, u.RelayPeer, run}
		u.mu.Unlock()
		out = append(out, map[string]any{"bytes_used": r.BytesUsed, "client_peer": r.ClientPeer, "grant_id": r.GrantID, "relay_peer": r.RelayPeer, "run": r.Run, "sig": hex.EncodeToString(ed25519.Sign(key, canonical(r)))})
	}
	return out
}

func (b *grantBook) closeStreams() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, u := range b.grants {
		u.mu.Lock()
		u.closed = true
		u.cond.Broadcast()
		var all []stream
		for s := range u.streams {
			all = append(all, s)
		}
		u.mu.Unlock()
		for _, s := range all {
			s.Close()
		}
	}
}
