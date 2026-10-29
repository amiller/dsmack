package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	lc "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

func TestForwardedAdmissionCannotRelabelBuyerNodeGrantOrCiphertext(t *testing.T) {
	key, _, err := lc.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := peer.IDFromPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	a := admission{JobID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Grant: map[string]any{"client_peer": id.String(), "grant_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}, ClientPeer: id.String(), BundleSHA256: digest([]byte("sealed envelope"))}
	fields := map[string]any{"bundle_sha256": a.BundleSHA256, "client_peer": a.ClientPeer, "grant_sha256": digest(canon(a.Grant)), "job_id": a.JobID, "node_peer": "node"}
	sig, err := key.Sign(canon(fields))
	if err != nil {
		t.Fatal(err)
	}
	a.Signature = hex.EncodeToString(sig)
	if got, err := a.forwardedClient("node", "broker-transport"); err != nil || got != id.String() {
		t.Fatalf("valid buyer authorization: %s %v", got, err)
	}
	if _, err := a.forwardedClient("other-node", "broker-transport"); err == nil {
		t.Fatal("node substitution accepted")
	}
	other := a
	other.JobID = "cccccccccccccccccccccccccccccccc"
	if _, err := other.forwardedClient("node", "broker-transport"); err == nil {
		t.Fatal("job replay relabel accepted")
	}
	other = a
	other.Grant = map[string]any{"grant_id": "different"}
	if _, err := other.forwardedClient("node", "broker-transport"); err == nil {
		t.Fatal("grant substitution accepted")
	}
	other = a
	other.BundleSHA256 = digest([]byte("replacement ciphertext"))
	if _, err := other.forwardedClient("node", "broker-transport"); err == nil {
		t.Fatal("ciphertext substitution accepted")
	}
	other = a
	other.ClientPeer = "malformed"
	if _, err := other.forwardedClient("node", "broker-transport"); err == nil {
		t.Fatal("buyer substitution accepted")
	}
}

func TestNestedCredentialUsesJobSpecificSecretBox(t *testing.T) {
	secret, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credential := json.RawMessage(`{"schema":"claude-subscription/1","credential":{"accessToken":"test-secret"}}`)
	b, err := seal(public(secret), "job/credential", credential)
	if err != nil {
		t.Fatal(err)
	}
	raw := canon(map[string]any{"schema": "dsmack-sealed-credential/1", "box": b})
	opened, err := openNestedCredential(secret, "job", raw)
	if err != nil || string(opened) != string(credential) {
		t.Fatalf("credential opening: %s %v", opened, err)
	}
	if _, err := openNestedCredential(secret, "other-job", raw); err == nil {
		t.Fatal("credential reused in another job")
	}
	if opened, err := openNestedCredential(secret, "job", credential); err != nil || opened != nil {
		t.Fatal("ordinary credential changed")
	}
}

func TestNodeStopsAdmittingBeforeItsWatchdogDeadline(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	n := &engine{broker: pub, node: "node", until: time.Now().Add(time.Hour), admissionUntil: time.Now().Add(-time.Second), seen: map[string]bool{}, used: map[string]int64{}}
	if _, _, code := n.reserve(admission{JobID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Grant: grantFor(priv)}, "client"); code != "busy" {
		t.Fatalf("draining node admitted a new job: %s", code)
	}
}
