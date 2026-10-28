#!/usr/bin/env python3
"""Local test-credit signer: keygen KEY | key KEY | grant KEY RELAY CLIENT BYTES EXPIRES.

The private seed is generated locally and never sent to the relay.
"""
import json
import secrets
import sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def main():
    command, filename, *args = sys.argv[1:]
    path = Path(filename)
    if command == "keygen":
        import os
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as out:
            out.write(secrets.token_bytes(32))
        return
    key = Ed25519PrivateKey.from_private_bytes(path.read_bytes())
    if command == "key":
        print(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex())
    elif command == "grant":
        relay, client, budget, expires = args
        grant = dict(v=1, grant_id=secrets.token_hex(16), relay_peer=relay,
                     client_peer=client, bytes=int(budget), expires_at=int(expires))
        grant["sig"] = key.sign(canon(grant)).hex()
        print(canon(grant).decode())
    else:
        raise ValueError("unknown signer command")


if __name__ == "__main__":
    main()
