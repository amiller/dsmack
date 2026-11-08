package payments

import (
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"strings"
	"testing"
)

func TestGuestClaimBuyerAndTermsBinding(t *testing.T) {
	key, _ := secp.GeneratePrivateKey()
	m := &Meter{Registration: Registration{Config: Config{Operator: "0x2222222222222222222222222222222222222222"}, ReceiptSigner: address(key.PubKey())}, key: key}
	buyer := "0x1111111111111111111111111111111111111111"
	terms := "0x" + strings.Repeat("33", 32)
	c, err := m.SignGuestClaim(buyer, terms, "900")
	if err != nil {
		t.Fatal(err)
	}
	d, _ := GuestClaimDigest(buyer, m.Operator, terms, "900")
	got, err := recover(d, c.Signature)
	if err != nil || got != m.Registration.ReceiptSigner {
		t.Fatalf("guest signer: %s %v", got, err)
	}
	for _, v := range []struct{ buyer, terms, amount string }{
		{"0x4444444444444444444444444444444444444444", terms, "900"},
		{buyer, "0x" + strings.Repeat("44", 32), "900"},
		{buyer, terms, "901"},
	} {
		d, _ := GuestClaimDigest(v.buyer, m.Operator, v.terms, v.amount)
		got, _ := recover(d, c.Signature)
		if got == m.Registration.ReceiptSigner {
			t.Fatal("claim accepted for different buyer, terms or amount")
		}
	}
	if _, err = m.SignGuestClaim(buyer, terms, "899"); err == nil {
		t.Fatal("cumulative claim regressed")
	}
	if _, err = m.SignGuestClaim(buyer, terms, "900"); err != nil {
		t.Fatal("identical checkpoint must be retryable", err)
	}
	rd := m.GuestKeyReport()
	if len(rd) != 64 || hexed(rd[12:32]) != m.Registration.ReceiptSigner || hexed(rd[44:]) != m.Operator {
		t.Fatal("registerGuestKey report data")
	}
}
