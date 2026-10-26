"""Coordinator side, run inside the dstack app: mint a worker grant.

python3 grant.py mint <dstack.sock> <task_id> <worker_id> <worker_compose_hash> <ttl_s>
python3 grant.py serve <dstack.sock> <port> <enroll dir> <cdhash> <compose_hash>...

The scoped root is GetKey on the coordinator's own socket under a per-(task, worker)
domain, so the coordinator can reissue it and the Mac never sees the app root key.
A grant is {"grant": <public grant JSON text>, "root_key": hex}; the runner app logs
sha256(grant text) as the guest's worker-grant event.

`serve` is the release policy for one enrolled Mac: POST /grant with {task_id, compose_hash,
run, seal_pub, assertion}. It verifies the App Attest assertion over grant_request_client_data
with the key from <enroll dir> (attestation.cbor, keyId.txt, clientData.bin), the build's
cdhash and a counter above the last one seen, requires compose_hash in the allowed set, then
mints for worker_id = keyId and seals root_key to seal_pub (P-256 ECDH, HKDF-SHA256, AES-GCM
with sha256(grant text) as associated data). Only ciphertext of the root key crosses the network.
"""
import hashlib
import http.client
import json
import os
import socket
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from dsmack_dstack import grant_statement, sign

SIGNER_DOMAIN = "dsmack-grant-signer/1"
REQUEST_DOMAIN = b"dsmack.appattest.grant-request/1"
SEAL_INFO = b"dsmack-grant-seal/1"


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost")
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.connect(self.path)


def call(sock, method, body):
    c = UnixHTTP(sock)
    c.request("POST", "/v1/" + method, json.dumps(body), {"Content-Type": "application/json"})
    r = c.getresponse()
    out = json.loads(r.read())
    if r.status != 200:
        raise RuntimeError("%s: %s" % (method, out))
    return out


def mint(sock, task_id, worker_id, compose_hash, ttl):
    signer = call(sock, "GetKey", {"domain": SIGNER_DOMAIN, "algorithm": "secp256k1"})
    root = call(sock, "GetKey", {"domain": "dsmack-worker-root/1/%s/%s" % (task_id, worker_id), "algorithm": "secp256k1"})
    g = {"task_id": task_id, "worker_id": worker_id, "compose_hash": compose_hash,
         "expires": int(time.time()) + ttl, "root_pub": root["public_key"],
         "signer_domain": SIGNER_DOMAIN, "app_id": call(sock, "Info", {})["app_id"]}
    g["chain"] = [sign(bytes.fromhex(signer["key"]), grant_statement(g)).hex()] + signer["signature_chain"]
    return {"grant": json.dumps(g, sort_keys=True, separators=(",", ":")), "root_key": root["key"]}


def grant_request_client_data(manifest_sha256, run, seal_pub, task_id):
    """32-byte domain || manifest_sha256 || run || sha256(seal_pub) || sha256(task_id) = 160 bytes."""
    h = lambda b: hashlib.sha256(b).digest()
    return REQUEST_DOMAIN + manifest_sha256 + run + h(seal_pub) + h(task_id.encode())


def seal(grant, seal_pub, eph=None, nonce=None):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    eph = eph or ec.generate_private_key(ec.SECP256R1())
    nonce = nonce or os.urandom(12)
    epk = eph.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    shared = eph.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), seal_pub))
    key = HKDF(SHA256(), 32, None, SEAL_INFO + seal_pub + epk).derive(shared)
    ct = AESGCM(key).encrypt(nonce, bytes.fromhex(grant["root_key"]), hashlib.sha256(grant["grant"].encode()).digest())
    return {"grant": grant["grant"], "epk": epk.hex(), "nonce": nonce.hex(), "ct": ct.hex()}


def serve(sock, port, enroll, cdhash, compose_hashes, ttl=600):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from cryptography import x509
    from verifier import core
    enroll = Path(enroll)
    key_id = (enroll / "keyId.txt").read_text().strip()
    att = (enroll / "attestation.cbor").read_bytes()
    policy = core.Policy(app_id="DC9JH5DRMY.dev.dsmack.provider", environment="production", categories=(3,),
                         cdhashes=(bytes.fromhex(cdhash),))
    leaf = x509.load_der_x509_certificate(core.decode(att)["attStmt"]["x5c"][0])
    root_pem = (Path(__file__).resolve().parent.parent / "trust/apple-app-attestation-root.pem").read_bytes()
    public_key = core.verify_attestation(att, key_id, (enroll / "clientData.bin").read_bytes(), policy, root_pem,
                                         at_time=leaf.not_valid_before_utc.timestamp() + 60)["public_key"]
    last = [0]

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            try:
                r = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if r["compose_hash"] not in compose_hashes:
                    raise ValueError("compose_hash not in this task's set")
                seal_pub = bytes.fromhex(r["seal_pub"])
                cd = grant_request_client_data(bytes.fromhex(r["compose_hash"]), bytes.fromhex(r["run"]), seal_pub, r["task_id"])
                a = core.verify_assertion(bytes.fromhex(r["assertion"]), cd, public_key, last[0], policy)
                last[0] = a["counter"]
                out, code = seal(mint(sock, r["task_id"], key_id, r["compose_hash"], ttl), seal_pub), 200
            except (KeyError, ValueError, core.Reject) as e:
                out, code = {"error": str(e)}, 400
            data = json.dumps(out).encode()
            self.send_response(code)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    HTTPServer(("0.0.0.0", port), H).serve_forever()


if __name__ == "__main__":
    a = sys.argv
    if a[1] == "mint":
        print(json.dumps(mint(a[2], a[3], a[4], a[5], int(a[6]))))
    else:
        serve(a[2], int(a[3]), a[4], a[5], set(a[6:]))
