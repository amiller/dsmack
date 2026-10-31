package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"
)

func grantFor(key ed25519.PrivateKey) map[string]any {
	g := map[string]any{"v": float64(1), "grant_id": "0123456789abcdef0123456789abcdef", "relay_peer": "node", "client_peer": "client", "unit": "seconds", "seconds": float64(20), "expires_at": float64(time.Now().Unix() + 60)}
	g["sig"] = hex.EncodeToString(ed25519.Sign(key, canon(g)))
	return g
}

func TestExpiredGrantRefused(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	g := grantFor(priv)
	delete(g, "sig")
	g["expires_at"] = float64(time.Now().Unix() - 1)
	g["sig"] = hex.EncodeToString(ed25519.Sign(priv, canon(g)))
	if _, err := checkGrant(g, pub, "node", "client", time.Now().Unix()); err == nil {
		t.Fatal("expired grant accepted")
	}
}

func TestOneHourSignedGrantAndCeiling(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	for _, seconds := range []float64{3600, 3601} {
		grant := grantFor(priv)
		delete(grant, "sig")
		grant["seconds"] = seconds
		grant["sig"] = hex.EncodeToString(ed25519.Sign(priv, canon(grant)))
		_, err := checkGrant(grant, pub, "node", "client", time.Now().Unix())
		if (err == nil) != (seconds == 3600) {
			t.Fatal("one-hour grant ceiling", seconds, err)
		}
	}
}
