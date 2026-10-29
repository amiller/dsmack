package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	payments "dsmack-payments"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
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
func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
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
type job struct {
	JobID      string          `json:"job_id"`
	GrantID    string          `json:"grant_id"`
	Credential json.RawMessage `json:"credential"`
	Repo       string          `json:"repo_tar"`
	Prompt     string          `json:"prompt"`
	OutputPub  string          `json:"output_pub"`
}
type terms struct {
	id               string
	seconds, expires int64
	paid             *payments.Grant
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
	paid       *payments.Meter
	publish    func(payments.SignedReceipt) error
	secret     *ecdh.PrivateKey
	signer     ed25519.PrivateKey
	broker     ed25519.PublicKey
	node, run  string
	until      time.Time
	worker     string
	resultPath string
	mu         sync.Mutex
	seen       map[string]bool
	used       map[string]int64
	busy       bool
	attest     func([]byte) ([]byte, error)
}

func (n *engine) reserve(a admission, client string) (terms, int64, string) {
	var t terms
	var e error
	if n.paid != nil {
		var g payments.Grant
		g, e = n.paid.Verify(canon(a.Grant), client, 1, time.Now().Unix())
		if e == nil {
			seconds, _ := strconv.ParseInt(g.Amount, 10, 64)
			t = terms{id: g.PurchaseID, seconds: seconds, expires: g.ServiceUntil, paid: &g}
		}
	} else {
		t, e = checkGrant(a.Grant, n.broker, n.node, client, time.Now().Unix())
	}
	if e != nil || !validID(a.JobID) {
		return t, 0, "grant"
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.seen[a.JobID] {
		return t, 0, "replay"
	}
	if n.busy {
		return t, 0, "busy"
	}
	left := min(t.seconds-n.used[t.id], t.expires-time.Now().Unix(), int64(time.Until(n.until).Seconds()))
	if left < 1 {
		return t, 0, "grant"
	}
	n.seen[a.JobID] = true
	n.busy = true
	return t, left, ""
}
func (n *engine) handle(s interface {
	io.ReadWriter
	SetDeadline(time.Time) error
}, client string) {
	var paid *paidJob
	refuse := func(code string) {
		frame := map[string]any{"status": "refused", "error": code}
		if paid != nil {
			r, e := paid.finish()
			frame["payment_receipt"] = r
			if e != nil {
				frame["receipt_error"] = e.Error()
			}
			s.SetDeadline(time.Now().Add(10 * time.Second))
		}
		writeFrame(s, frame)
	}
	s.SetDeadline(time.Now().Add(20 * time.Second))
	var a admission
	if e := readFrame(s, 4096, &a); e != nil {
		refuse("grant")
		return
	}
	t, left, code := n.reserve(a, client)
	if code != "" {
		refuse(code)
		return
	}
	start := time.Now()
	deadline := start.Add(time.Duration(left) * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	if t.paid != nil {
		paid = &paidJob{meter: n.paid, grant: *t.paid, start: start, left: left, publish: n.publish, stop: func() { cancel(); s.SetDeadline(time.Now()) }}
		if n.resultPath != "" {
			paid.path = filepath.Join(filepath.Dir(n.resultPath), "payment-receipts")
		}
		paid.begin()
	}
	var used int64
	defer func() {
		if paid != nil && paid.final == nil {
			_, e := paid.finish()
			if e != nil {
				fmt.Fprintln(os.Stderr, "paid final receipt:", e)
			}
		}
		os.Remove("/run/dsmack/credential")
		os.RemoveAll("/run/dsmack/job-" + a.JobID)
		n.mu.Lock()
		if used == 0 {
			used = max(1, min(left, int64(math.Ceil(time.Since(start).Seconds()))))
		}
		n.used[t.id] += used
		n.busy = false
		n.mu.Unlock()
	}()
	s.SetDeadline(deadline)
	if e := writeFrame(s, map[string]string{"status": "ready"}); e != nil {
		return
	}
	var b box
	if e := readFrame(s, 48<<20, &b); e != nil {
		refuse("bundle")
		return
	}
	raw, e := openBox(n.secret, a.JobID, b)
	if e != nil {
		refuse("bundle")
		return
	}
	var j job
	if e = json.Unmarshal(raw, &j); e != nil || j.JobID != a.JobID || j.GrantID != t.id || len(j.Prompt) > 1<<20 {
		refuse("bundle")
		return
	}
	outPub, e := hex.DecodeString(j.OutputPub)
	if e != nil || len(outPub) != 64 {
		refuse("bundle")
		return
	}
	if _, e = ecdh.P256().NewPublicKey(append([]byte{4}, outPub...)); e != nil {
		refuse("bundle")
		return
	}
	s.SetDeadline(deadline.Add(10 * time.Second))
	cmd := exec.CommandContext(ctx, "python3", "-B", n.worker)
	cmd.Stdin = bytes.NewReader(raw)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if n.paid != nil {
			return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}
	cmd.WaitDelay = 3 * time.Second
	// Never attach child stdout/stderr to the console or result disk.
	var result limitedBuffer
	result.max = 24 << 20
	cmd.Stdout = &result
	if e = cmd.Run(); e != nil {
		refuse("execution")
		return
	}
	var encoded map[string]string
	if e = json.Unmarshal(result.Bytes(), &encoded); e != nil || len(encoded) != 3 {
		refuse("execution")
		return
	}
	outputs := map[string]box{}
	hashes := map[string]string{}
	for _, name := range []string{"patch", "transcript", "verdict"} {
		v, ok := encoded[name]
		plain, err := base64.StdEncoding.DecodeString(v)
		if !ok || err != nil {
			refuse("execution")
			return
		}
		sealed, err := seal(outPub, j.JobID+"/"+name, plain)
		if err != nil {
			refuse("execution")
			return
		}
		outputs[name] = sealed
		hashes[name] = digest(plain)
	}
	used = max(1, min(left, int64(math.Ceil(time.Since(start).Seconds()))))
	if paid != nil {
		final, e := paid.finish()
		if final == nil {
			refuse("receipt")
			return
		}
		used, _ = strconv.ParseInt(final.Receipt.Used, 10, 64)
		if e != nil {
			fmt.Fprintln(os.Stderr, "paid final delivery:", e)
		}
	}
	statement := map[string]any{"job_id": j.JobID, "bundle_sha256": digest(canon(b)), "outputs": hashes, "grant_id": t.id, "seconds_used": used}
	report := sha256.Sum256(canon(statement))
	att, e := n.attest(append(report[:], make([]byte, 32)...))
	if e != nil {
		refuse("attestation")
		return
	}
	receipt := map[string]any{"client_peer": client, "node_peer": n.node, "run": n.run, "report_sha256": hex.EncodeToString(report[:]), "grant_id": t.id, "job_id": j.JobID, "seconds_used": used}
	receipt["sig"] = hex.EncodeToString(ed25519.Sign(n.signer, canon(receipt)))
	resultFrame := map[string]any{"status": "complete", "outputs": outputs, "statement": statement, "attestation": hex.EncodeToString(att), "receipt": receipt}
	if paid != nil {
		r, e := paid.finish()
		resultFrame["payment_receipt"] = r
		if e != nil {
			resultFrame["receipt_error"] = e.Error()
		}
	}
	if n.resultPath != "" {
		if e := os.WriteFile(n.resultPath, canon(resultFrame), 0644); e != nil {
			refuse("execution")
			return
		}
	}
	writeFrame(s, resultFrame)
}

type limitedBuffer struct {
	bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.max {
		return 0, fmt.Errorf("output limit")
	}
	return b.Buffer.Write(p)
}
