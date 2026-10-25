"""dstack guest-api-v1 shim for a dsmack guest: python3 agent.py <grant.json> <socket>.

Serves /v1/GetKey, /v1/Info and /v1/Version on the socket a dstack workload
mounts as /var/run/dstack.sock. Attest is absent: a dsmack guest has no runtime
attestation call; the runner's result assertion carries what the workload writes.
"""
import json
import os
import socketserver
import sys
from http.server import BaseHTTPRequestHandler

from dsmack_dstack import get_key

grant = json.load(open(sys.argv[1]))
root = bytes.fromhex(grant.pop("root_key"))


def info(_):
    return {"app_id": grant["app_id"], "app_name": grant["task_id"], "compose_hash": grant["compose_hash"],
            "instance_id": grant["worker_id"].encode().hex(), "device_id": "", "os_image_hash": "",
            "mr_aggregated": "", "key_provider_info": json.dumps({"dsmack_worker_grant": grant})}


METHODS = {
    "GetKey": lambda r: get_key(root, r["domain"], r["algorithm"], grant["chain"]),
    "Info": info,
    "Version": lambda _: {"version": "dsmack-dstack-shim/0", "rev": ""},
}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        method = self.path.removeprefix("/v1/")
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}"
        if not self.path.startswith("/v1/") or method not in METHODS:
            return self.reply(404, {"error": "Service not found: %s" % method})
        try:
            self.reply(200, METHODS[method](json.loads(body)))
        except (KeyError, ValueError) as e:
            self.reply(400, {"error": str(e)})

    def reply(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def address_string(self):
        return "unix"


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    pass


if os.path.exists(sys.argv[2]):
    os.unlink(sys.argv[2])
Server(sys.argv[2], Handler).serve_forever()
