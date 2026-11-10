#!/usr/bin/python3 -IB
"""Attest, obtain the payload key, decrypt on tmpfs, and exec through PRoot."""
import ctypes
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import resource
import socket
import sys
import tarfile
import tempfile
import urllib.parse

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"dsmack.encrypted-payload/1\n"
MEMORY = Path("/run/dsmack")
ARTIFACTS = Path("/workspace/artifacts")


class Agent(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.connect("/var/run/dstack.sock")


def post(conn, path, body):
    try:
        conn.request("POST", path, json.dumps(body), {"Content-Type": "application/json"})
        response = conn.getresponse()
        raw = response.read(1 << 20)
        if response.status != 200:
            # The release refusal is public evidence; never dump response data on other failures.
            if response.status == 403:
                (ARTIFACTS / "release.json").write_text(json.dumps({"status": 403, "error": json.loads(raw)["error"]}))
            raise RuntimeError("request refused: " + str(response.status))
        return json.loads(raw)
    finally:
        conn.close()


def require_tmpfs(path):
    # Fail before writing plaintext if the runtime bind is not actually tmpfs.
    buf = ctypes.create_string_buffer(256)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.statfs(os.fsencode(path), buf) != 0 or ctypes.c_long.from_buffer(buf).value != 0x01021994:
        raise RuntimeError("payload storage is not tmpfs")


def main(task, url, digest):
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    require_tmpfs(MEMORY)
    ciphertext = Path("/opt/encrypted/payload.aes").read_bytes()
    if hashlib.sha256(ciphertext).hexdigest() != digest or not ciphertext.startswith(MAGIC):
        raise RuntimeError("ciphertext digest or format mismatch")
    rd = hashlib.sha256(b"dsmack.secret-request/1" + task.encode()).digest() + bytes(32)
    att = post(Agent("localhost"), "/v1/Attest", {"report_data": rd.hex()})["attestation"]
    (ARTIFACTS / "attestation.json").write_text(json.dumps({"task_id": task, "attestation": att}))
    u = urllib.parse.urlsplit(url)
    conn = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
    box = post(conn(u.netloc, timeout=60), u.path.rstrip("/") + "/release", {"task_id": task, "attestation": att})
    key = bytes.fromhex(post(Agent("localhost"), "/v1/GetSecret", dict(task_id=task, **box))["secret"])
    offset = len(MAGIC)
    plaintext = AESGCM(key).decrypt(ciphertext[offset:offset + 12], ciphertext[offset + 12:], MAGIC)
    root = Path(tempfile.mkdtemp(prefix="payload-", dir=MEMORY))
    # Authenticated author content, including its private launch config, stays in memory/tmpfs.
    with tarfile.open(fileobj=io.BytesIO(plaintext)) as bundle:
        launch = json.load(bundle.extractfile("launch.json"))
        with tarfile.open(fileobj=bundle.extractfile("rootfs.tar")) as rootfs:
            rootfs.extractall(root, filter="fully_trusted")
    for name in ("outputs", "tmp", "dev"):
        (root / name).mkdir(exist_ok=True)
    (ARTIFACTS / "release.json").write_text(json.dumps({"status": 200, "ciphertext_sha256": digest,
                                                        "storage": "tmpfs", "execution": "proot"}))
    env = dict(item.split("=", 1) for item in (launch["Env"] or []))
    env["PROOT_TMP_DIR"] = str(MEMORY)
    env["PROOT_NO_SECCOMP"] = "1"
    argv = ["/usr/bin/proot", "-r", str(root), "-w", launch["WorkingDir"] or "/",
            "-b", str(ARTIFACTS) + ":/outputs", "-b", "/dev/null", "-b", "/dev/urandom",
            *(launch["Entrypoint"] or []), *(launch["Cmd"] or [])]
    # exec replaces the loader address space (including the key and decrypted archive).
    os.execve(argv[0], argv, env)


if __name__ == "__main__":
    try:
        main(*sys.argv[1:])
    except Exception as e:
        # Private launch configuration and plaintext must never appear in a traceback.
        print("encrypted payload failed: " + type(e).__name__, file=sys.stderr)
        sys.exit(1)
