// Forward opaque browser jobs over Noise/libp2p. The browser signs admission;
// this helper never receives a buyer private key or plaintext job/output.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p"
	lc "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
)

const bundleLimit = 48 << 20

type forwarder struct {
	host  host.Host
	token string
}
type request struct {
	Target    string          `json:"target"`
	Challenge string          `json:"challenge"`
	Admission json.RawMessage `json:"admission"`
	Sealed    json.RawMessage `json:"sealed"`
}

func frame(w io.Writer, raw []byte) error {
	if len(raw) == 0 || len(raw) > bundleLimit {
		return fmt.Errorf("frame size")
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(raw))); err != nil {
		return err
	}
	_, err := io.Copy(w, bytes.NewReader(raw))
	return err
}
func readFrame(r io.Reader, limit uint32) (json.RawMessage, error) {
	var size uint32
	if err := binary.Read(r, binary.BigEndian, &size); err != nil {
		return nil, err
	}
	if size == 0 || size > limit {
		return nil, fmt.Errorf("frame size")
	}
	raw := make([]byte, size)
	_, err := io.ReadFull(r, raw)
	if err == nil && !json.Valid(raw) {
		err = fmt.Errorf("invalid JSON frame")
	}
	return raw, err
}
func (f forwarder) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	refuse := func(status int, code string) {
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]string{"error": code})
	}
	if f.token != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+f.token)) != 1 {
		refuse(401, "forwarder_auth")
		return
	}
	if r.Method != "POST" || (r.URL.Path != "/attestation" && r.URL.Path != "/jobs") {
		refuse(404, "not_found")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, bundleLimit+16384)
	var q request
	if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
		refuse(400, "request")
		return
	}
	info, err := peer.AddrInfoFromString(q.Target)
	if err != nil {
		refuse(400, "target")
		return
	}
	ctx, cancel := context.WithTimeout(network.WithAllowLimitedConn(r.Context(), "sandbox-forward"), 900*time.Second)
	defer cancel()
	if err = f.host.Connect(ctx, *info); err != nil {
		refuse(502, "node_unreachable")
		return
	}
	proto := "/dsmack/job/1"
	if r.URL.Path == "/attestation" {
		proto = "/dsmack/attest/1"
		if q.Challenge != "" {
			proto = "/dsmack/payments-attest/1"
		}
	}
	stream, err := f.host.NewStream(ctx, info.ID, protocol.ID(proto))
	if err != nil {
		refuse(502, "node_protocol")
		return
	}
	defer stream.Close()
	// Interrupt a blocked read when the HTTP consumer leaves.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			stream.Reset()
		case <-done:
		}
	}()
	if r.URL.Path == "/attestation" {
		stream.SetDeadline(time.Now().Add(25 * time.Second))
		if q.Challenge != "" {
			raw, _ := json.Marshal(map[string]string{"challenge": q.Challenge})
			if frame(stream, raw) != nil {
				refuse(502, "node_write")
				return
			}
		}
		raw, e := io.ReadAll(io.LimitReader(stream, 150001))
		if e != nil || len(raw) > 150000 || !json.Valid(raw) {
			refuse(502, "node_attestation")
			return
		}
		w.Write(raw)
		return
	}
	stream.SetDeadline(time.Now().Add(900 * time.Second))
	if len(q.Admission) > 4096 || !json.Valid(q.Admission) || !json.Valid(q.Sealed) {
		refuse(400, "job_frames")
		return
	}
	if frame(stream, q.Admission) != nil {
		refuse(502, "node_write")
		return
	}
	ready, e := readFrame(stream, 4096)
	if e != nil {
		refuse(502, "node_admission")
		return
	}
	var status struct {
		Status string `json:"status"`
	}
	json.Unmarshal(ready, &status)
	if status.Status != "ready" {
		w.Write(ready)
		return
	}
	if frame(stream, q.Sealed) != nil {
		refuse(502, "node_write")
		return
	}
	result, e := readFrame(stream, bundleLimit)
	if e != nil {
		refuse(502, "node_result_lost")
		return
	}
	w.Write(result)
}
func main() {
	listen := flag.String("listen", "127.0.0.1:18271", "internal HTTP listener")
	keyFile := flag.String("key", "forwarder.key", "persistent libp2p transport key")
	flag.Parse()
	token := os.Getenv("SANDBOX_FORWARDER_TOKEN")
	addr, _, err := net.SplitHostPort(*listen)
	if err != nil {
		log.Fatal(err)
	}
	if (net.ParseIP(addr) == nil || !net.ParseIP(addr).IsLoopback()) && len(token) < 32 {
		log.Fatal("non-loopback listener requires SANDBOX_FORWARDER_TOKEN of at least 32 characters")
	}
	raw, err := os.ReadFile(*keyFile)
	if os.IsNotExist(err) {
		k, _, e := lc.GenerateEd25519Key(rand.Reader)
		if e != nil {
			log.Fatal(e)
		}
		raw, e = lc.MarshalPrivateKey(k)
		if e != nil {
			log.Fatal(e)
		}
		file, e := os.OpenFile(*keyFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			log.Fatal(e)
		}
		_, e = file.Write(raw)
		file.Close()
		if e != nil {
			log.Fatal(e)
		}
	} else if err != nil {
		log.Fatal(err)
	}
	key, err := lc.UnmarshalPrivateKey(raw)
	if err != nil {
		log.Fatal(err)
	}
	h, err := libp2p.New(libp2p.Identity(key), libp2p.NoListenAddrs, libp2p.EnableRelay(), libp2p.Security(noise.ID, noise.New))
	if err != nil {
		log.Fatal(err)
	}
	defer h.Close()
	srv := &http.Server{Addr: *listen, Handler: http.HandlerFunc((forwarder{host: h, token: strings.TrimSpace(token)}).serve), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	log.Printf("sandbox forwarder listening %s peer %s", *listen, h.ID())
	log.Fatal(srv.ListenAndServe())
}
