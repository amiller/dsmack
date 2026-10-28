package payments

import (
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	lc "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

func TestBuyerBindingAndReceiptInteroperability(t *testing.T) {
	coordinator, _ := secp.GeneratePrivateKey()
	buyer, _, _ := lc.GenerateEd25519Key(rand.Reader)
	id, _ := peer.IDFromPrivateKey(buyer)
	pub, _ := buyer.GetPublic().Raw()
	m, e := New(Config{Escrow: "0x1000000000000000000000000000000000000001", Operator: "0x2000000000000000000000000000000000000002", GrantSigner: address(coordinator.PubKey()), EnrollmentKeyID: hexed(make([]byte, 32)), BuildID: hexed(make([]byte, 32)), DestinationPolicyHash: hexed(make([]byte, 32)), RunExpires: time.Now().Unix() + 3600})
	if e != nil {
		t.Fatal(e)
	}
	g := Grant{"1", m.Node, hexed(pub), 1, "4", time.Now().Unix(), time.Now().Unix() + 60, hexed(make([]byte, 32))}
	d, _ := g.Digest(m.Escrow)
	env := Envelope{g, sign(coordinator, d)}
	raw, _ := json.Marshal(env)
	if _, e = m.Verify(raw, id.String(), 1, time.Now().Unix()); e != nil {
		t.Fatal(e)
	}
	wrong, _, _ := lc.GenerateEd25519Key(rand.Reader)
	wrongID, _ := peer.IDFromPrivateKey(wrong)
	if _, e = m.Verify(raw, wrongID.String(), 1, time.Now().Unix()); e == nil {
		t.Fatal("another buyer spent the grant")
	}
	first, _ := m.Receipt(g, 1, false)
	last, _ := m.Receipt(g, 2, true)
	if last.Receipt.Sequence != 2 || first.Receipt.Used != "1" {
		t.Fatal("cumulative sequence")
	}
	digest, _ := last.Receipt.Digest(m.Escrow)
	signer, e := recover(digest, last.Signature)
	if e != nil || signer != m.ReceiptSigner {
		t.Fatal("guest signature", e)
	}
	if _, e = m.Verify(raw, id.String(), 1, time.Now().Unix()); e == nil {
		t.Fatal("finalized purchase reopened")
	}
	if _, e = m.Receipt(g, 2, true); e == nil {
		t.Fatal("duplicate finalization")
	}
	if out := os.Getenv("PAYMENTS_EVIDENCE"); out != "" {
		binding, _ := m.Binding(id.String(), hexed(make([]byte, 32)), hexed(make([]byte, 32)))
		evidence := map[string]any{"escrow": m.Escrow, "registration": m.Registration, "peer": id.String(), "grant": env, "receipt": last, "receiptDigest": hexed(digest), "binding": hexed(binding)}
		b, _ := json.Marshal(evidence)
		if e = os.WriteFile(filepath.Join(out, "guest-interop.json"), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
}

func TestOnlyOperatorCanStopAdmittedRun(t *testing.T) {
	operator, _ := secp.GeneratePrivateKey()
	const zero = "0x0000000000000000000000000000000000000000000000000000000000000000"
	m, e := New(Config{Escrow: "0x1000000000000000000000000000000000000001", Operator: address(operator.PubKey()), GrantSigner: address(operator.PubKey()), EnrollmentKeyID: zero, BuildID: zero, DestinationPolicyHash: zero, RunExpires: time.Now().Unix() + 3600})
	if e != nil {
		t.Fatal(e)
	}
	expiry := time.Now().Unix() + 60
	node, _ := raw(m.Node, 32)
	d, _ := typed(m.Escrow, join(hash([]byte("Stop(bytes32 node,uint64 expires)")), node, uintWord(expiry)))
	if e = m.VerifyStop(sign(operator, d), expiry); e != nil {
		t.Fatal(e)
	}
	wrong, _ := secp.GeneratePrivateKey()
	if e = m.VerifyStop(sign(wrong, d), expiry); e == nil {
		t.Fatal("unapproved operator stopped run")
	}
	if e = m.VerifyStop(sign(operator, d), time.Now().Unix()-1); e == nil {
		t.Fatal("expired stop request")
	}
}
