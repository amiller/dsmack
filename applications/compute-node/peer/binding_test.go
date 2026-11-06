package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	payments "dsmack-payments"
	"dsmack-peer/p2p"
	"github.com/libp2p/go-libp2p/core/peer"
)

func TestPaidBindingIncludesBothReceiptKeysAndFreshChallenge(t *testing.T) {
	raw, err := os.ReadFile("../../relay-broker/fixtures/bind.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Compute struct {
			Peer    string `json:"relay_peer"`
			Seal    string `json:"secret_key"`
			Receipt string `json:"receipt_key"`
		}
	}
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	id, err := peer.Decode(f.Compute.Peer)
	if err != nil {
		t.Fatal(err)
	}
	seal, _ := hex.DecodeString(f.Compute.Seal)
	receipt, _ := hex.DecodeString(f.Compute.Receipt)
	const zero32 = "0x0000000000000000000000000000000000000000000000000000000000000000"
	const addr = "0x1000000000000000000000000000000000000001"
	m, err := payments.New(payments.Config{Node: zero32, Escrow: addr, Operator: addr, GrantSigner: addr, EnrollmentKeyID: zero32, BuildID: zero32, DestinationPolicyHash: zero32, RunSeconds: 600})
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{1}, 32)
	rd, err := paidReport(m, id, seal, receipt, hex.EncodeToString(nonce))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rd, p2p.ReportData(id, seal, append(append([]byte{}, receipt...), m.ReceiptPublicKey()...), nonce)) {
		t.Fatal("paid binding key order differs")
	}
	if bytes.Equal(rd, p2p.ReportData(id, seal, receipt, nonce)) {
		t.Fatal("paid signer was omitted")
	}
	if bytes.Equal(rd, p2p.ReportData(id, seal, append(append([]byte{}, receipt...), m.ReceiptPublicKey()...), nil)) {
		t.Fatal("freshness was omitted")
	}
	if _, err = paidReport(m, id, seal, receipt, "00"); err == nil {
		t.Fatal("short challenge accepted")
	}
	if out := os.Getenv("PAYMENTS_EVIDENCE"); out != "" {
		evidence, _ := json.Marshal(map[string]any{"peer": f.Compute.Peer, "seal": f.Compute.Seal, "receipt": f.Compute.Receipt, "payments": m.Registration, "challenge": hex.EncodeToString(nonce), "report_data": hex.EncodeToString(rd)})
		if err = os.WriteFile(out+"/binding-interop.json", evidence, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
