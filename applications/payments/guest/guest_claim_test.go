package payments

import (
	"encoding/json"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"os/exec"
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

// An independent EIP-712 implementation prevents a signer/verifier pair from
// agreeing on the wrong contract domain or ABI encoding.
func TestGuestClaimEthersInteroperability(t *testing.T) {
	key, _ := secp.GeneratePrivateKey()
	m := &Meter{Registration: Registration{Config: Config{Operator: "0x2222222222222222222222222222222222222222"}, ReceiptSigner: address(key.PubKey())}, key: key}
	buyer := "0x1111111111111111111111111111111111111111"
	terms := "0x" + strings.Repeat("33", 32)
	claim, err := m.SignGuestClaim(buyer, terms, "900")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := GuestClaimDigest(buyer, m.Operator, terms, "900")
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{"claim": claim, "digest": hexed(digest)})
	script := `import {readFileSync} from 'node:fs';
 import {TypedDataEncoder,verifyTypedData,zeroPadValue} from '../../compute-node/browser/vendor/ethers-6.17.0.mjs';
 const {claim:c,digest}=JSON.parse(readFileSync(0,'utf8'));
 const d={name:'LayoverGuestEscrow',version:'1',chainId:84532,verifyingContract:c.escrow,salt:zeroPadValue(c.buyer,32)};
 const types={Claim:[{name:'operator',type:'address'},{name:'termsHash',type:'bytes32'},{name:'cumulativeOwed',type:'uint256'}]};
 const value={operator:c.operator,termsHash:c.terms_hash,cumulativeOwed:c.cumulative_owed};
 if(TypedDataEncoder.hash(d,types,value)!==digest || verifyTypedData(d,types,value,c.signature).toLowerCase()!==c.key.toLowerCase())process.exit(1);`
	cmd := exec.Command("node", "--input-type=module", "--eval", script)
	cmd.Stdin = strings.NewReader(string(payload))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ethers interoperability: %v %s", err, output)
	}
}
