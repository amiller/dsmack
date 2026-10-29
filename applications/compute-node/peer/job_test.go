package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSecretBoxPythonInteropAndRunIsolation(t *testing.T) {
	k, _ := ecdh.P256().GenerateKey(rand.Reader)
	b, e := seal(public(k), "job", []byte("sealed credential"))
	if e != nil {
		t.Fatal(e)
	}
	opened, e := openBox(k, "job", b)
	if e != nil || string(opened) != "sealed credential" {
		t.Fatal(e)
	}
	other, _ := ecdh.P256().GenerateKey(rand.Reader)
	if _, e = openBox(other, "job", b); e == nil {
		t.Fatal("another run opened bundle")
	}
	if _, e = openBox(k, "other", b); e == nil {
		t.Fatal("task binding")
	}
	raw, _ := json.Marshal(map[string]any{"k": hex.EncodeToString(k.Bytes()), "epk": b.EPK, "iv": b.IV, "ct": b.CT})
	code := "import sys,json;sys.path.insert(0,'../../../dstack-compat');from secret_box import open_secret;v=json.loads(sys.argv[1]);assert open_secret(int(v['k'],16),'job',bytes.fromhex(v['epk']),bytes.fromhex(v['iv']),bytes.fromhex(v['ct']))==b'sealed credential'"
	if out, e := exec.Command("python3", "-c", code, string(raw)).CombinedOutput(); e != nil {
		t.Fatalf("Python interoperability: %v %s", e, out)
	}
}
func grantFor(key ed25519.PrivateKey) map[string]any {
	g := map[string]any{"v": float64(1), "grant_id": "0123456789abcdef0123456789abcdef", "relay_peer": "node", "client_peer": "client", "unit": "seconds", "seconds": float64(20), "expires_at": float64(time.Now().Unix() + 60)}
	g["sig"] = hex.EncodeToString(ed25519.Sign(key, canon(g)))
	return g
}
func TestAdmissionRejectsBeforeBundle(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	n := &engine{broker: pub, node: "node", until: time.Now().Add(time.Hour), seen: map[string]bool{}, used: map[string]int64{}}
	a := admission{JobID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Grant: grantFor(priv)}
	if _, _, c := n.reserve(a, "wrong"); c != "grant" {
		t.Fatal(c)
	}
	terms, _, c := n.reserve(a, "client")
	if c != "" {
		t.Fatal(c)
	}
	if _, _, c = n.reserve(a, "client"); c != "replay" {
		t.Fatal(c)
	}
	a.JobID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if _, _, c = n.reserve(a, "client"); c != "busy" {
		t.Fatal(c)
	}
	n.busy = false
	n.used[terms.id] = 20
	if _, _, c = n.reserve(a, "client"); c != "grant" {
		t.Fatal(c)
	}
	a.Grant["seconds"] = float64(40)
	if _, _, c = n.reserve(a, "client"); c != "grant" {
		t.Fatal(c)
	}
}

func TestJobReturnsSealedAttestedOutputsAndRejectsReplay(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	receipt, signer, _ := ed25519.GenerateKey(rand.Reader)
	secret, _ := ecdh.P256().GenerateKey(rand.Reader)
	output, _ := ecdh.P256().GenerateKey(rand.Reader)
	worker := filepath.Join(t.TempDir(), "worker.py")
	os.WriteFile(worker, []byte("import sys,json,base64\nj=json.load(sys.stdin)\njson.dump({k:base64.b64encode(k.encode()).decode() for k in ['patch','transcript','verdict']},sys.stdout)\n"), 0600)
	var report []byte
	n := &engine{broker: pub, secret: secret, signer: signer, node: "node", run: "run", until: time.Now().Add(time.Hour), worker: worker, seen: map[string]bool{}, used: map[string]int64{}, attest: func(rd []byte) ([]byte, error) { report = rd; return []byte("attested"), nil }}
	g := grantFor(priv)
	id := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	j := job{JobID: id, GrantID: g["grant_id"].(string), OutputPub: hex.EncodeToString(public(output)), Credential: json.RawMessage(`{"private":"credential"}`)}
	sealed, e := seal(public(secret), id, canon(j))
	if e != nil {
		t.Fatal(e)
	}
	run := func(bundle bool) map[string]any {
		server, client := net.Pipe()
		defer client.Close()
		done := make(chan struct{})
		go func() { defer close(done); defer server.Close(); n.handle(server, "client") }()
		writeFrame(client, admission{JobID: id, Grant: g})
		var result map[string]any
		if e := readFrame(client, 4096, &result); e != nil {
			t.Fatal(e)
		}
		if bundle {
			if result["status"] != "ready" {
				t.Fatal(result)
			}
			writeFrame(client, sealed)
			if e := readFrame(client, 48<<20, &result); e != nil {
				t.Fatal(e)
			}
		}
		<-done
		return result
	}
	result := run(true)
	if result["status"] != "complete" {
		t.Fatal(result)
	}
	statement := result["statement"].(map[string]any)
	if statement["bundle_sha256"] != digest(canon(sealed)) || hex.EncodeToString(report[:32]) != digest(canon(statement)) {
		t.Fatal("attestation binding")
	}
	outputs := result["outputs"].(map[string]any)
	for _, name := range []string{"patch", "transcript", "verdict"} {
		raw := canon(outputs[name])
		var b box
		json.Unmarshal(raw, &b)
		plain, e := openBox(output, id+"/"+name, b)
		if e != nil || string(plain) != name {
			t.Fatal("output seal", e)
		}
	}
	rec := result["receipt"].(map[string]any)
	sig, _ := hex.DecodeString(rec["sig"].(string))
	delete(rec, "sig")
	if !ed25519.Verify(receipt, canon(rec), sig) {
		t.Fatal("receipt signature")
	}
	refused := run(false)
	if refused["error"] != "replay" {
		t.Fatal(refused)
	}
}

func TestExpiredGrantNeverReleasesBundle(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	g := grantFor(priv)
	delete(g, "sig")
	g["expires_at"] = float64(time.Now().Unix() - 1)
	g["sig"] = hex.EncodeToString(ed25519.Sign(priv, canon(g)))
	if _, err := checkGrant(g, pub, "node", "client", time.Now().Unix()); err == nil {
		t.Fatal("expired grant accepted")
	}
}

func TestBudgetDeadlineStopsWorkerAndConsumesGrant(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	secret, _ := ecdh.P256().GenerateKey(rand.Reader)
	output, _ := ecdh.P256().GenerateKey(rand.Reader)
	marker := filepath.Join(t.TempDir(), "terminated")
	worker := filepath.Join(t.TempDir(), "worker.py")
	source := "import signal,time,pathlib\ndef stop(*_):\n pathlib.Path(" + string(canon(marker)) + ").write_text('stopped')\n raise SystemExit(1)\nsignal.signal(signal.SIGTERM,stop)\ntime.sleep(30)\n"
	os.WriteFile(worker, []byte(source), 0600)
	n := &engine{broker: pub, secret: secret, node: "node", until: time.Now().Add(time.Hour), worker: worker, seen: map[string]bool{}, used: map[string]int64{}}
	g := grantFor(priv)
	delete(g, "sig")
	g["seconds"] = float64(1)
	g["sig"] = hex.EncodeToString(ed25519.Sign(priv, canon(g)))
	id := "cccccccccccccccccccccccccccccccc"
	j := job{JobID: id, GrantID: g["grant_id"].(string), OutputPub: hex.EncodeToString(public(output))}
	sealed, _ := seal(public(secret), id, canon(j))
	server, client := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() { defer close(done); defer server.Close(); n.handle(server, "client") }()
	writeFrame(client, admission{JobID: id, Grant: g})
	var result map[string]any
	readFrame(client, 4096, &result)
	if result["status"] != "ready" {
		t.Fatal(result)
	}
	writeFrame(client, sealed)
	readFrame(client, 4096, &result)
	<-done
	if result["error"] != "execution" {
		t.Fatal(result)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("worker did not receive graceful timeout", err)
	}
	if n.used[g["grant_id"].(string)] != 1 || n.busy {
		t.Fatal("grant settlement")
	}
}

func TestBrokerDialsMeasuredIPWithoutProviderProxy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Host, "broker.invalid:") {
			t.Error("broker hostname lost")
		}
		w.Write([]byte("registered"))
	}))
	defer server.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	t.Setenv("BROKER_IP", "127.0.0.1")
	t.Setenv("HTTPS_PROXY", "http://192.0.2.1:1")
	t.Setenv("HTTP_PROXY", "http://192.0.2.1:1")
	client, err := brokerClient("http://broker.invalid:" + port)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Get("http://broker.invalid:" + port + "/nodes")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode)
	}
}
