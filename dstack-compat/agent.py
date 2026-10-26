"""dstack guest-api-v1 shim for a dsmack guest.

python3 agent.py --dir <socket dir> [--ctl <port>] [--event NAME=HEX]... [--canary-key PATH] [--secret-key] [--grant grant.json] SERVICE...

--canary-key writes a fresh P-256 scalar to PATH (0600; the supervisor puts it in
guest-root tmpfs) and adds its public key as the canary-guest-key event. --secret-key makes a
P-256 key kept only in the agent's memory, adds its public key as the secret-key event and serves
/v1/GetSecret, which opens a task secret sealed to that key (secret_box.py) for the calling service.
With --ctl (the dsmack-ctl virtio console port) the agent asks the app for hello,
takes the run's worker grant if the app offers one (the app logs its digest as the
worker-grant event), sends the supervisor's system events and the seal, writes
<dir>/sealed and then serves /v1/Attest. With a grant, from the app or from
--grant (a file of the same {"grant", "root_key"} shape, for tests off the Mac),
it serves /v1/GetKey. /v1/Info and /v1/Version
always. Each service gets <dir>/<service>.sock, which lowering binds to that
service's /var/run/dstack.sock; the socket that accepted a call is its caller tag.
"""
import argparse
import json
import os
import re
import socketserver
import struct
import threading
from http.server import BaseHTTPRequestHandler

import guest_attest

MAX_FRAME = 4096
SERVICE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


class Ctl:
    """uint32_be(len) || JSON frames over the dsmack-ctl port, one request in flight."""

    def __init__(self, fd):
        self.fd, self.lock = fd, threading.Lock()

    def send(self, obj):
        data = json.dumps(obj).encode()
        if len(data) > MAX_FRAME:
            raise ValueError("dsmack-ctl frame exceeds %d bytes" % MAX_FRAME)
        data = struct.pack(">I", len(data)) + data
        while data:
            data = data[os.write(self.fd, data):]

    def recv(self):
        n = struct.unpack(">I", self._read(4))[0]
        if n > MAX_FRAME:
            raise ValueError("dsmack-ctl frame exceeds %d bytes" % MAX_FRAME)
        return json.loads(self._read(n))

    def _read(self, n):
        b = b""
        while len(b) < n:
            chunk = os.read(self.fd, n - len(b))
            if not chunk:
                raise EOFError("dsmack-ctl closed")
            b += chunk
        return b

    def call(self, obj):
        with self.lock:
            self.send(obj)
            reply = self.recv()
        if "error" in reply:
            raise ValueError(reply["error"])
        return reply


def methods(ctl, hello, grant, secret=None):
    def info(_, __):
        i = dict.fromkeys(("app_id", "app_name", "compose_hash", "instance_id", "device_id", "os_image_hash",
                           "mr_aggregated", "key_provider_info"), "")
        if hello:
            i.update(compose_hash=hello["manifest_sha256"], instance_id=hello["run"], os_image_hash=hello["os_image_hash"])
        if grant:
            g = json.loads(grant["grant"])
            i.update(app_id=g["app_id"], app_name=g["task_id"], compose_hash=g["compose_hash"],
                     instance_id=g["worker_id"].encode().hex(), key_provider_info=grant["grant"])
        return i

    def attest(req, caller):
        rd = bytes.fromhex(req["report_data"])
        if len(rd) > 64:
            raise ValueError("report_data is %d bytes, at most 64" % len(rd))
        rd = rd.ljust(64, b"\0")
        reply = ctl.call({"op": "attest", "caller": caller.hex(), "report_data": rd.hex()})
        return {"attestation": guest_attest.attestation(hello, caller, rd, reply).hex()}

    m = {"Info": info, "Version": lambda _, __: {"version": "dsmack-dstack-shim/1", "rev": ""}}
    if ctl:
        m["Attest"] = attest
    if secret is not None:
        import secret_box
        m["GetSecret"] = lambda r, _: {"secret": secret_box.open_secret(
            secret, r["task_id"], *(bytes.fromhex(r[f]) for f in ("epk", "iv", "ct"))).hex()}
    if grant:
        from dsmack_dstack import get_key
        root, chain = bytes.fromhex(grant["root_key"]), json.loads(grant["grant"])["chain"]
        m["GetKey"] = lambda r, _: get_key(root, r["domain"], r["algorithm"], chain)
    return m


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        method = self.path.removeprefix("/v1/")
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}"
        if not self.path.startswith("/v1/") or method not in self.server.methods:
            return self.reply(404, {"error": "Service not found: %s" % method})
        try:
            self.reply(200, self.server.methods[method](json.loads(body), self.server.caller))
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
    daemon_threads = True


def start(sockdir, services, ctl_fd=None, events=(), grant=None, secret=None):
    """Seal (with a port), then serve one socket per service on background threads."""
    for s in services:
        if not SERVICE_RE.fullmatch(s):
            raise ValueError("service name %r is not a compose service name" % s)
    ctl = hello = None
    if ctl_fd is not None:
        ctl = Ctl(ctl_fd)
        hello = ctl.call({"op": "hello"})
        if hello.get("grant"):
            grant = ctl.call({"op": "grant"})
        for name, payload in events:
            ctl.call({"op": "event", "name": name, "payload": payload.hex()})
        ctl.call({"op": "seal"})
        open(os.path.join(sockdir, "sealed"), "w").close()
    m = methods(ctl, hello, grant, secret)
    servers = []
    for s in services:
        path = os.path.join(sockdir, s + ".sock")
        srv = Server(path, Handler)
        srv.methods, srv.caller = m, guest_attest.sha256(s.encode())
        os.chmod(path, 0o666)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
    return servers


def canary_key(path):
    k = int.from_bytes(os.urandom(32), "big") % (guest_attest.P256_N - 1) + 1
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, k.to_bytes(32, "big"))
    os.close(fd)
    return k


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--dir", required=True)
    p.add_argument("--ctl")
    p.add_argument("--event", action="append", default=[], type=lambda e: (e.split("=")[0], bytes.fromhex(e.split("=")[1])))
    p.add_argument("--canary-key")
    p.add_argument("--secret-key", action="store_true")
    p.add_argument("--grant", type=lambda f: json.load(open(f)))
    p.add_argument("services", nargs="*")
    a = p.parse_args()
    if a.canary_key:
        a.event.append((guest_attest.CANARY_GUEST_EVENT, guest_attest.p256_public(canary_key(a.canary_key))))
    secret = int.from_bytes(os.urandom(32), "big") % (guest_attest.P256_N - 1) + 1 if a.secret_key else None
    if secret:
        a.event.append(("secret-key", guest_attest.p256_public(secret)))
    start(a.dir, a.services, a.ctl and os.open(a.ctl, os.O_RDWR), a.event, a.grant, secret)
    threading.Event().wait()
