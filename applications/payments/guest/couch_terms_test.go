package payments

import (
	"encoding/json"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"strings"
	"testing"
)

func TestCouchClaimBillsAcceptedLaycAndCapsUsage(t *testing.T) {
	key, _ := secp.GeneratePrivateKey()
	m := &Meter{Registration: Registration{Config: Config{Operator: "0x2222222222222222222222222222222222222222"}, ReceiptSigner: address(key.PubKey())}, key: key}
	body := map[string]any{"kind": "layover-terms/1", "mode": "couch", "chain_id": 84532, "escrow": GuestEscrow,
		"token": "0x9e851bf5e3b613aaa09853a07d1132f49c90b515", "operator": m.Operator, "minutes": 5, "rate_layc_per_second": 15, "minimum_seconds": 60, "cap": "4500"}
	encode := func() CouchTerms {
		b, _ := json.Marshal(body)
		return CouchTerms{"0x1111111111111111111111111111111111111111", hexed(hash(b)), string(b)}
	}
	terms := encode()
	for _, tc := range []struct {
		used int64
		owed string
	}{{0, "0"}, {1, "900"}, {60, "900"}, {61, "915"}, {300, "4500"}} {
		claim, err := m.CouchClaim(terms, 300, tc.used)
		if err != nil || claim.CumulativeOwed != tc.owed {
			t.Fatalf("used %d: %v %s", tc.used, err, claim.CumulativeOwed)
		}
	}
	if _, err := m.CouchClaim(terms, 300, 301); err == nil {
		t.Fatal("over-budget guest claim")
	}
	terms.TermsHash = "0x" + strings.Repeat("33", 32)
	if err := m.ValidateCouchTerms(terms, 300); err == nil {
		t.Fatal("terms hash mismatch accepted")
	}
	body["operator"] = "0x4444444444444444444444444444444444444444"
	if err := m.ValidateCouchTerms(encode(), 300); err == nil {
		t.Fatal("another operator accepted")
	}
	body["operator"] = m.Operator
	body["cap"] = "4501"
	if err := m.ValidateCouchTerms(encode(), 300); err == nil {
		t.Fatal("cap disagrees with accepted rate")
	}
}
