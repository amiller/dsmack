package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"golang.org/x/crypto/sha3"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	payments "dsmack-payments"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/libp2p/go-libp2p"
	lc "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

func TestPaidCutoffEmitsFinalReceiptAndStopsProcessGroup(t *testing.T) {
	testPaidJob(t, true, false)
}
func TestPaidJobRefundsUnusedSeconds(t *testing.T)        { testPaidJob(t, false, false) }
func TestReceiptStorageFailureStopsPaidWork(t *testing.T) { testPaidJob(t, true, true) }
func testPaidJob(t *testing.T, cutoff, storageFailure bool) {
	coordinator, _ := secp.GeneratePrivateKey()
	// Address is obtained by recovering the EIP-712 signature below, using the
	// same curve convention exercised against Solidity by the guest fixture test.
	buyer, _, _ := lc.GenerateEd25519Key(rand.Reader)
	id, _ := peer.IDFromPrivateKey(buyer)
	buyerPub, _ := buyer.GetPublic().Raw()
	const zero = "0x0000000000000000000000000000000000000000000000000000000000000000"
	// Keccak public-key address: reuse libp2p's secp implementation is unnecessary.
	pubHash := keccakForTest(coordinator.PubKey().SerializeUncompressed()[1:])
	m, e := payments.New(payments.Config{Node: "0x0101010101010101010101010101010101010101010101010101010101010101", Escrow: "0x1000000000000000000000000000000000000001", Operator: "0x2000000000000000000000000000000000000002", GrantSigner: "0x" + hex.EncodeToString(pubHash[12:]), EnrollmentKeyID: zero, BuildID: zero, DestinationPolicyHash: zero, RunExpires: time.Now().Unix() + 3600})
	if e != nil {
		t.Fatal(e)
	}
	amount := "5"
	if cutoff {
		amount = "2"
	}
	g := payments.Grant{PurchaseID: "1", Node: m.Node, RunID: m.RunID, BuyerKey: "0x" + hex.EncodeToString(buyerPub), Unit: 1, Amount: amount, IssuedAt: time.Now().Unix(), ServiceUntil: time.Now().Unix() + 60, DestinationPolicyHash: zero}
	digest, _ := g.Digest(m.Escrow)
	sig := ecdsa.SignCompact(coordinator, digest, false)
	envelope := payments.Envelope{Grant: g, Signature: "0x" + hex.EncodeToString(append(sig[1:], sig[0]))}
	var grant map[string]any
	json.Unmarshal(canon(envelope), &grant)
	secret, _ := ecdh.P256().GenerateKey(rand.Reader)
	output, _ := ecdh.P256().GenerateKey(rand.Reader)
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	tmp := t.TempDir()
	marker := filepath.Join(tmp, "ran-past-budget")
	worker := filepath.Join(tmp, "worker.py")
	source := "import sys,json,base64\njson.load(sys.stdin)\njson.dump({k:base64.b64encode(k.encode()).decode() for k in ['patch','transcript','verdict']},sys.stdout)\n"
	if cutoff {
		source = "import time,pathlib\ntime.sleep(4)\npathlib.Path(" + string(canon(marker)) + ").write_text('bad')\n"
	}
	os.WriteFile(worker, []byte(source), 0600)
	var mu sync.Mutex
	var receipts []payments.SignedReceipt
	n := &engine{paid: m, secret: secret, signer: ed, node: "node", run: "run", until: time.Now().Add(time.Hour), worker: worker, resultPath: filepath.Join(tmp, "result"), seen: map[string]bool{}, used: map[string]int64{}, attest: func([]byte) ([]byte, error) { return []byte("attestation"), nil }, publish: func(r payments.SignedReceipt) error {
		mu.Lock()
		defer mu.Unlock()
		receipts = append(receipts, r)
		if storageFailure {
			return errors.New("storage unavailable")
		}
		return nil
	}}
	jobID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	j := job{JobID: jobID, GrantID: "1", OutputPub: hex.EncodeToString(public(output))}
	sealed, _ := seal(public(secret), jobID, canon(j))
	server, client := net.Pipe()
	defer client.Close()
	client.SetDeadline(time.Now().Add(10 * time.Second))
	done := make(chan struct{})
	go func() { defer close(done); defer server.Close(); n.handle(server, id.String()) }()
	writeFrame(client, admission{JobID: jobID, Grant: grant})
	var frame map[string]any
	if e = readFrame(client, 4096, &frame); e != nil || frame["status"] != "ready" {
		t.Fatal(frame, e)
	}
	writeFrame(client, sealed)
	readErr := readFrame(client, 48<<20, &frame)
	<-done
	mu.Lock()
	defer mu.Unlock()
	if len(receipts) == 0 || !receipts[len(receipts)-1].Receipt.FinalReceipt {
		t.Fatal("no final receipt")
	}
	finalEnvelope := receipts[len(receipts)-1]
	final := finalEnvelope.Receipt
	if evidence := os.Getenv("PAYMENTS_EVIDENCE"); evidence != "" && !storageFailure {
		name := "compute-unused.json"
		if cutoff {
			name = "compute-cutoff.json"
		}
		digest, _ := final.Digest(m.Escrow)
		raw := canon(map[string]any{"escrow": m.Escrow, "registration": m.Registration, "grant": envelope, "receipt": finalEnvelope, "receiptDigest": "0x" + hex.EncodeToString(digest)})
		if err := os.WriteFile(filepath.Join(evidence, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if readErr != nil {
		t.Fatal(readErr)
	}
	if cutoff && !storageFailure && (frame["error"] != "execution" || final.Used != "2") {
		t.Fatal(frame, final)
	}
	if storageFailure && frame["payment_receipt"] == nil {
		t.Fatal("buyer lost cutoff receipt when broker storage failed")
	}
	if !cutoff && (frame["status"] != "complete" || final.Used != "1") {
		t.Fatal(frame, final)
	}
	if _, e = os.Stat(marker); !os.IsNotExist(e) {
		t.Fatal("worker exceeded paid deadline")
	}
	if _, e = m.Verify(canon(envelope), id.String(), 1, time.Now().Unix()); e == nil {
		t.Fatal("closed paid job replayed")
	}
	if _, e = os.Stat(filepath.Join(tmp, "payment-receipts")); e != nil {
		t.Fatal("receipt original not retained", e)
	}
}

func keccakForTest(b []byte) []byte { h := sha3.NewLegacyKeccak256(); h.Write(b); return h.Sum(nil) }

func TestFinalReceiptIncludesTimeWaitingForCheckpointAck(t *testing.T) {
	const zero = "0x0000000000000000000000000000000000000000000000000000000000000000"
	m, e := payments.New(payments.Config{Node: "0x0101010101010101010101010101010101010101010101010101010101010101", Escrow: "0x1000000000000000000000000000000000000001", Operator: "0x2000000000000000000000000000000000000002", GrantSigner: "0x2000000000000000000000000000000000000002", EnrollmentKeyID: zero, BuildID: zero, DestinationPolicyHash: zero, RunExpires: time.Now().Unix() + 3600})
	if e != nil {
		t.Fatal(e)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	p := &paidJob{meter: m, grant: payments.Grant{PurchaseID: "1", Amount: "10", ServiceUntil: time.Now().Unix() + 60}, start: time.Now().Add(-1500 * time.Millisecond), left: 10, publish: func(r payments.SignedReceipt) error {
		if !r.Receipt.FinalReceipt {
			once.Do(func() { close(started) })
			<-release
		}
		return nil
	}}
	p.begin()
	<-started
	done := make(chan *payments.SignedReceipt)
	go func() {
		r, err := p.finish()
		if err != nil {
			t.Error(err)
		}
		done <- r
	}()
	time.Sleep(1100 * time.Millisecond)
	close(release)
	final := <-done
	if final == nil {
		t.Fatal("missing final receipt")
	}
	used, err := strconv.ParseInt(final.Receipt.Used, 10, 64)
	if err != nil || used < 4 {
		t.Fatal("receipt excluded paid wall time while a checkpoint was pending", used, err)
	}
}

func TestStopAcknowledgementArrivesBeforeHostCloses(t *testing.T) {
	server, e := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	client, e := libp2p.New(libp2p.NoListenAddrs)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	stopped := make(chan struct{})
	server.SetStreamHandler("/test/stop/1", func(stream network.Stream) {
		defer stream.Close()
		acknowledgeStop(stream, func() { close(stopped); server.Close() })
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if e = client.Connect(ctx, peer.AddrInfo{ID: server.ID(), Addrs: server.Addrs()}); e != nil {
		t.Fatal(e)
	}
	stream, e := client.NewStream(ctx, server.ID(), "/test/stop/1")
	if e != nil {
		t.Fatal(e)
	}
	stream.SetDeadline(time.Now().Add(3 * time.Second))
	// A queued libp2p write is lost if the host closes before the reader consumes it.
	time.Sleep(100 * time.Millisecond)
	var reply map[string]string
	if e = readFrame(stream, 4096, &reply); e != nil || reply["status"] != "stopping" {
		t.Fatal(reply, e)
	}
	select {
	case <-stopped:
		t.Fatal("host stopped before peer received the acknowledgement")
	default:
	}
	stream.Close()
	client.Close()
	select {
	case <-stopped:
	case <-ctx.Done():
		t.Fatal("operator stop did not finish")
	}
}
