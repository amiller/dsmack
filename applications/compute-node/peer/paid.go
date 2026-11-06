package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	payments "dsmack-payments"
	"dsmack-peer/p2p"
	"github.com/libp2p/go-libp2p/core/peer"
)

// PAYMENTS_CONFIG names no App Attest key; the run binds to the key that signs this guest's attestation.
func paidConfig() *payments.Config {
	raw := os.Getenv("PAYMENTS_CONFIG")
	if raw == "" {
		return nil
	}
	var cfg payments.Config
	d := json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	must(d.Decode(&cfg))
	return &cfg
}

func paidMeter(cfg *payments.Config, attestation []byte) (*payments.Meter, error) {
	if cfg == nil {
		return nil, nil
	}
	kid, e := payments.AttestedKeyID(attestation)
	if e != nil {
		return nil, e
	}
	return payments.New(*cfg, kid)
}

func paidReport(m *payments.Meter, id peer.ID, seal, receipt []byte, challenge string) ([]byte, error) {
	c, e := hex.DecodeString(challenge)
	if e != nil || len(c) != 32 {
		return nil, fmt.Errorf("payment challenge must be 32 bytes")
	}
	keys := append(append([]byte{}, receipt...), m.ReceiptPublicKey()...)
	return p2p.ReportData(id, seal, keys, c), nil
}

// Let the peer receive the acknowledgement before closing the libp2p host.
func acknowledgeStop(stream io.ReadWriter, stop func()) {
	if writeFrame(stream, map[string]string{"status": "stopping"}) != nil {
		return
	}
	io.Copy(io.Discard, stream)
	stop()
}
