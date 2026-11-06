package payments

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// A real guest attestation (relay-broker/fixtures/bind.json): the run binds to the key that signed it.
func TestRunBindsAttestingKey(t *testing.T) {
	var f struct {
		Enrollment struct{ Kid string }
		Paid       struct{ Attestation string }
	}
	raw, e := os.ReadFile("../../relay-broker/fixtures/bind.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(raw, &f); e != nil {
		t.Fatal(e)
	}
	blob, _ := hex.DecodeString(f.Paid.Attestation)
	kid, e := AttestedKeyID(blob)
	if e != nil || hex.EncodeToString(kid) != f.Enrollment.Kid {
		t.Fatalf("key id %x, %v", kid, e)
	}
	zero := hexed(make([]byte, 32))
	m, e := New(Config{Node: zero, Escrow: "0x1000000000000000000000000000000000000001", Operator: "0x2000000000000000000000000000000000000002", GrantSigner: "0x3000000000000000000000000000000000000003", BuildID: zero, DestinationPolicyHash: zero, RunSeconds: 60}, kid)
	if e != nil {
		t.Fatal(e)
	}
	nonce, _ := raw32(m.RunNonce)
	if m.RunID != hexed(hash(join(kid, nonce))) {
		t.Fatal("runId is not keccak(attested kid, runNonce)")
	}
	if _, e = AttestedKeyID(append(blob, 0)); e == nil {
		t.Fatal("trailing bytes accepted")
	}
	if _, e = AttestedKeyID(blob[:len(blob)-1]); e == nil {
		t.Fatal("truncated attestation accepted")
	}
	if _, e = New(m.Config, kid[:31]); e == nil {
		t.Fatal("short key id accepted")
	}
}

func raw32(s string) ([]byte, error) { return raw(s, 32) }
