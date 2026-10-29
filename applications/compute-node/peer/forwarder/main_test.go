package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
)

func TestForwarderWaitsForReadyAndReturnsSealedResult(t *testing.T) {
	node, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	client, err := libp2p.New(libp2p.NoListenAddrs)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	target := node.Addrs()[0].String() + "/p2p/" + node.ID().String()
	sealed := json.RawMessage(`{"ct":"encrypted","epk":"public","iv":"nonce"}`)
	result := json.RawMessage(`{"status":"complete","outputs":{"patch":{"ct":"encrypted-output"}}}`)
	seen := make(chan []byte, 1)
	node.SetStreamHandler("/dsmack/job/1", func(s network.Stream) {
		defer s.Close()
		admission, err := readFrame(s, 4096)
		if err != nil {
			return
		}
		if frame(s, []byte(`{"status":"ready"}`)) != nil {
			return
		}
		raw, err := readFrame(s, bundleLimit)
		if err != nil {
			return
		}
		seen <- append(append([]byte{}, admission...), raw...)
		frame(s, result)
	})
	f := forwarder{host: client, token: "service-token"}
	payload, _ := json.Marshal(request{Target: target, Admission: json.RawMessage(`{"job_id":"job","signature":"buyer-signature"}`), Sealed: sealed})
	req := httptest.NewRequest(http.MethodPost, "/jobs", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer service-token")
	out := httptest.NewRecorder()
	f.serve(out, req)
	if out.Code != 200 || !bytes.Equal(out.Body.Bytes(), result) {
		t.Fatalf("result %d %s", out.Code, out.Body.String())
	}
	if !bytes.Contains(<-seen, sealed) {
		t.Fatal("ciphertext changed")
	}
	denied := httptest.NewRecorder()
	f.serve(denied, httptest.NewRequest(http.MethodPost, "/jobs", bytes.NewReader(payload)))
	if denied.Code != 401 {
		t.Fatalf("missing service credential: %d", denied.Code)
	}
}

func TestForwarderFetchesFreshPaidNodeAttestation(t *testing.T) {
	node, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	client, err := libp2p.New(libp2p.NoListenAddrs)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	node.SetStreamHandler("/dsmack/payments-attest/1", func(s network.Stream) {
		defer s.Close()
		raw, err := readFrame(s, 4096)
		if err != nil {
			return
		}
		var q map[string]string
		json.Unmarshal(raw, &q)
		json.NewEncoder(s).Encode(map[string]string{"challenge": q["challenge"], "attestation": "node-proof"})
	})
	payload, _ := json.Marshal(request{Target: node.Addrs()[0].String() + "/p2p/" + node.ID().String(), Challenge: "browser-nonce"})
	out := httptest.NewRecorder()
	(forwarder{host: client}).serve(out, httptest.NewRequest(http.MethodPost, "/attestation", bytes.NewReader(payload)))
	body, _ := io.ReadAll(out.Result().Body)
	var value map[string]string
	json.Unmarshal(body, &value)
	if out.Code != 200 || value["challenge"] != "browser-nonce" || value["attestation"] != "node-proof" {
		t.Fatalf("fresh proof %d %s", out.Code, body)
	}
}
