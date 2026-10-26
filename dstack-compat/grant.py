"""Coordinator side, run inside the dstack app: mint a worker grant.

python3 grant.py mint <dstack.sock> <task_id> <worker_id> <worker_compose_hash> <ttl_s>

The scoped root is GetKey on the coordinator's own socket under a per-(task, worker)
domain, so the coordinator can reissue it and the Mac never sees the app root key.
A grant is {"grant": <public grant JSON text>, "root_key": hex}; the runner app logs
sha256(grant text) as the guest's worker-grant event.

The coordinator app (applications/coordinator) serves the release policy at POST /grant and
seals root_key to the runner app's seal_pub with `seal` (P-256 ECDH, HKDF-SHA256, AES-GCM with
sha256(grant text) as associated data). Only ciphertext of the root key crosses the network.
The grant is signed with libsecp256k1 (coincurve); the guest's stdlib secp256k1 is not constant-time.
"""
import hashlib
import http.client
import json
import os
import socket
import sys
import time

from coincurve import PrivateKey

from dsmack_dstack import grant_statement

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
    g["chain"] = [PrivateKey(bytes.fromhex(signer["key"])).sign_recoverable(grant_statement(g), hasher=None).hex()] + signer["signature_chain"]
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


if __name__ == "__main__":
    a = sys.argv
    print(json.dumps(mint(a[2], a[3], a[4], a[5], int(a[6]))))
