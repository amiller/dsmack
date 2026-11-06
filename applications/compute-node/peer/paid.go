package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	payments "dsmack-payments"
	"dsmack-peer/p2p"
	"github.com/libp2p/go-libp2p/core/peer"
)

func paidMeter() *payments.Meter {
	raw := os.Getenv("PAYMENTS_CONFIG")
	if raw == "" {
		return nil
	}
	var cfg payments.Config
	must(json.Unmarshal([]byte(raw), &cfg))
	m, e := payments.New(cfg)
	must(e)
	return m
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
