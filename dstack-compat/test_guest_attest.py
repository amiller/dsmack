import hashlib
import http.client
import json
import os
import pathlib
import socket
import tempfile
import threading

import pytest

import agent
import guest_attest
from guest_attest import SYSTEM_READY, client_data, replay, sha256, verify

# Shared with the Swift GuestAttest tests in marAttestTests.
VECTOR = pathlib.Path(__file__).parent.parent / "runner-vm/control-src/Tests/marAttestTests/Fixtures/guest-attest-vector.json"


class FakeApp:
    """The app end of dsmack-ctl as V3Launch's handler runs it, with the assertion replaced by the client data."""

    def __init__(self, hello):
        self.hello, self.events, self.sealed = hello, [], False

    def handle(self, m):
        op = m["op"]
        if op == "hello":
            return {k: self.hello[k] for k in ("os_image_hash", "manifest_sha256", "run")}
        if op == "event" and not self.sealed:
            self.events.append((m["name"], bytes.fromhex(m["payload"])))
        elif op == "seal" and not self.sealed:
            self.sealed = True
            self.events.append((SYSTEM_READY, b""))
        elif op == "attest" and self.sealed:
            h = {k: bytes.fromhex(self.hello[k]) for k in ("os_image_hash", "manifest_sha256", "run")}
            cd = client_data(h["os_image_hash"], h["manifest_sha256"], h["run"], replay(self.events),
                             bytes.fromhex(m["caller"]), bytes.fromhex(m["report_data"]))
            return {"key_id": "ab" * 32, "assertion": cd.hex(),
                    "events": [{"name": n, "payload": p.hex()} for n, p in self.events]}
        else:
            return {"error": "%s refused %s seal" % (op, "after" if self.sealed else "before")}
        return {"head": replay(self.events).hex()}


def test_vector_seal_rules_and_client_data():
    v = json.loads(VECTOR.read_text())
    app = FakeApp(v["hello"])
    for step in v["ops"]:
        r = app.handle(step["frame"])
        if "error" in step:
            assert "error" in r, step
        elif step["frame"]["op"] == "attest":
            assert r["assertion"] == step["client_data"]
            assert len(bytes.fromhex(step["client_data"])) == 255
        else:
            assert r["head"] == step["head"]
    # Independent of guest_attest: head_1 = sha256(0^32 || sha256(LP(name) || LP(payload))).
    e = v["ops"][1]["frame"]
    name, payload = e["name"].encode(), bytes.fromhex(e["payload"])
    digest = hashlib.sha256(len(name).to_bytes(4, "big") + name + len(payload).to_bytes(4, "big") + payload).digest()
    assert hashlib.sha256(bytes(32) + digest).hexdigest() == v["ops"][1]["head"]
    cd = bytes.fromhex(v["ops"][-1]["client_data"])
    assert cd[:31] == b"dsmack.appattest.guest-attest/1" and cd[127:159].hex() == v["ops"][3]["head"]


@pytest.fixture
def guest():
    app_end, guest_end = socket.socketpair()
    hello = {"os_image_hash": "11" * 32, "manifest_sha256": "22" * 32, "run": "33" * 32}
    app = FakeApp(hello)
    peer = agent.Ctl(app_end.fileno())

    def serve():
        try:
            while True:
                peer.send(app.handle(peer.recv()))
        except EOFError:  # the guest end closed at teardown
            return

    threading.Thread(target=serve, daemon=True).start()
    d = tempfile.mkdtemp()
    servers = agent.start(d, ["worker"], guest_end.fileno(), [("canary-key", b"\x01" + b"\xee" * 20)])
    yield d, app
    for s in servers:
        s.shutdown()


def call(path, method, body):
    class C(http.client.HTTPConnection):
        def connect(self):
            self.sock = socket.socket(socket.AF_UNIX)
            self.sock.connect(path)
    c = C("localhost")
    c.request("POST", "/v1/" + method, json.dumps(body), {"Content-Type": "application/json"})
    r = c.getresponse()
    return r.status, json.loads(r.read())


def test_agent_attest_replays_to_the_sealed_log(guest):
    d, app = guest
    assert os.path.exists(os.path.join(d, "sealed"))
    code, out = call(os.path.join(d, "worker.sock"), "Attest", {"report_data": "aa" * 16})
    assert code == 200
    a = verify(bytes.fromhex(out["attestation"]))
    assert a["system_events"] == [("canary-key", b"\x01" + b"\xee" * 20)]
    assert a["caller"] == sha256(b"worker") and a["report_data"] == b"\xaa" * 16 + bytes(48)
    assert a["head"] == replay(app.events) and a["client_data_hash"] == sha256(a["assertion"])


def test_agent_refuses_oversized_report_data(guest):
    d, _ = guest
    code, out = call(os.path.join(d, "worker.sock"), "Attest", {"report_data": "aa" * 65})
    assert code == 400 and "at most 64" in out["error"]


def test_verify_rejects_event_after_system_ready(guest):
    d, app = guest
    app.events.append(("late", b""))  # a log the sealed app would never produce
    _, out = call(os.path.join(d, "worker.sock"), "Attest", {"report_data": ""})
    with pytest.raises(ValueError, match="system-ready"):
        verify(bytes.fromhex(out["attestation"]))


def test_canary_key_public_matches_cryptography(tmp_path):
    # A wrong public key in the canary-guest-key event would make the canary unclaimable even after a break.
    from cryptography.hazmat.primitives.asymmetric import ec
    k = agent.canary_key(tmp_path / "k")
    assert oct(os.stat(tmp_path / "k").st_mode & 0o777) == "0o600"
    n = ec.derive_private_key(k, ec.SECP256R1()).public_key().public_numbers()
    assert guest_attest.p256_public(k) == n.x.to_bytes(32, "big") + n.y.to_bytes(32, "big")


if __name__ == "__main__":
    # Regenerate the shared vector: python3 test_guest_attest.py
    hello = {"os_image_hash": "11" * 32, "manifest_sha256": "22" * 32, "run": "33" * 32}
    app, ops = FakeApp(hello), []
    caller, rd = sha256(b"worker").hex(), bytes(range(64)).hex()
    for frame in [{"op": "attest", "caller": caller, "report_data": rd},
                  {"op": "event", "name": "canary-key", "payload": "01" + "ee" * 20},
                  {"op": "event", "name": "guest-key", "payload": "04" + "5a" * 64},
                  {"op": "seal"},
                  {"op": "event", "name": "late", "payload": ""},
                  {"op": "seal"},
                  {"op": "attest", "caller": caller, "report_data": rd}]:
        r = app.handle(frame)
        ops.append({"frame": frame, **({"error": True} if "error" in r else
                                        {"client_data": r["assertion"]} if frame["op"] == "attest" else r)})
    VECTOR.write_text(json.dumps({"hello": hello, "ops": ops}, indent=1) + "\n")
