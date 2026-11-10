#!/usr/bin/env python3
"""Export a Docker image and encrypt its rootfs and launch configuration."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import subprocess
import tarfile
import tempfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"dsmack.encrypted-payload/1\n"


def encrypt(image, out):
    out.mkdir(mode=0o700)
    config = json.loads(subprocess.check_output(["docker", "image", "inspect", image]))[0]
    if config["Os"] != "linux" or config["Architecture"] != "arm64":
        raise ValueError("payload must be a Linux arm64 image")
    c = config["Config"]
    launch = {k: c.get(k) for k in ("Entrypoint", "Cmd", "Env", "WorkingDir")}
    container = subprocess.check_output(["docker", "create", image], text=True).strip()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            rootfs = Path(tmp) / "rootfs.tar"
            subprocess.run(["docker", "export", "--output", str(rootfs), container], check=True)
            bundle = io.BytesIO()
            with tarfile.open(fileobj=bundle, mode="w") as tar:
                tar.add(rootfs, arcname="rootfs.tar")
                raw = json.dumps(launch, separators=(",", ":")).encode()
                info = tarfile.TarInfo("launch.json")
                info.size = len(raw)
                tar.addfile(info, io.BytesIO(raw))
            key, nonce = secrets.token_bytes(32), secrets.token_bytes(12)
            ciphertext = MAGIC + nonce + AESGCM(key).encrypt(nonce, bundle.getvalue(), MAGIC)
    finally:
        subprocess.run(["docker", "rm", container], check=True, stdout=subprocess.DEVNULL)
    (out / "payload.aes").write_bytes(ciphertext)
    fd = os.open(out / "key.hex", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(key.hex() + "\n")
    digest = hashlib.sha256(ciphertext).hexdigest()
    (out / "ciphertext.sha256").write_text(digest + "\n")
    print(json.dumps({"ciphertext_sha256": digest, "ciphertext_bytes": len(ciphertext)}))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("image")
    p.add_argument("out", type=Path)
    a = p.parse_args()
    encrypt(a.image, a.out)
