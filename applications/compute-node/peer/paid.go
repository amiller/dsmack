package main

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"os"

	payments "dsmack-payments"
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

func paidReport(m *payments.Meter, registration map[string]any, legacy []byte, challenge string) ([]byte, error) {
	if _, e := hex.DecodeString(challenge); e != nil {
		return nil, e
	}
	return m.Report(registration["relay_peer"].(string), registration["manifest_sha256"].(string), registration["os_image_hash"].(string), legacy, challenge)
}

// Let the peer receive the acknowledgement before closing the libp2p host.
func acknowledgeStop(stream io.ReadWriter, stop func()) {
	if writeFrame(stream, map[string]string{"status": "stopping"}) != nil {
		return
	}
	io.Copy(io.Discard, stream)
	stop()
}
