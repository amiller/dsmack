"""The TLS canary's guest code, run locally against the stealing host: with the pre-#170 bundle
the host reads K and K signs a valid claim; with the sentinel roots it reads nothing."""
import http.server
import json
import os
import socketserver
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parents[1] / "contracts")]
import tls  # noqa: E402
import tls_host  # noqa: E402
from canary_claim import claim_digest  # noqa: E402


class Attest(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers["content-length"]))
        out = json.dumps({"attestation": "00"}).encode()
        self.send_response(200)
        self.send_header("content-length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


def run_guest(roots):
    with tempfile.TemporaryDirectory() as t:
        sock = os.path.join(t, "dstack.sock")
        srv = socketserver.UnixStreamServer(sock, Attest)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        host = tls_host.steal(0, t)
        src = tls.code(roots, host.port, 0, sock=sock, proxy="127.0.0.1", out=os.path.join(t, "oracle.json"))
        res = subprocess.run([sys.executable, "-I", "-c", src], capture_output=True, text=True, timeout=60)
        srv.shutdown()
        return json.loads(open(os.path.join(t, "oracle.json")).read()), res.stdout, tls_host.stolen(host)


def test_old_bundle_gives_host_the_key():
    out, stdout, k = run_guest(str(tls_host.poc.GUEST))
    assert "provider 200" in stdout
    key = ec.derive_private_key(int(k, 16), ec.SECP256R1())
    assert key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)[1:].hex() == out["public_key"]
    digest = claim_digest(84532, "0x" + "11" * 20, 0, "0x" + "22" * 20)
    key.public_key().verify(key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256()))), digest, ec.ECDSA(Prehashed(hashes.SHA256())))


def test_sentinel_roots_keep_the_key():
    _, stdout, k = run_guest(tls.SENTINEL_ROOTS.read_text())
    assert "provider SSLCertVerificationError" in stdout and k is None
