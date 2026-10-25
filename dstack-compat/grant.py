"""Coordinator side, run inside the dstack app: mint a worker grant.

python3 grant.py <dstack.sock> <task_id> <worker_id> <worker_compose_hash> <ttl_s>

The scoped root is GetKey on the coordinator's own socket under a per-(task, worker)
domain, so the coordinator can reissue it and the Mac never sees the app root key.
In deployment the release policy encrypts the output to the attested guest key.
"""
import http.client
import json
import socket
import sys
import time

from dsmack_dstack import grant_statement, sign

SIGNER_DOMAIN = "dsmack-grant-signer/1"


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
    g["root_key"] = root["key"]
    return g


if __name__ == "__main__":
    print(json.dumps(mint(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5]))))
