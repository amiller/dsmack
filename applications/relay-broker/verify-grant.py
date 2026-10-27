#!/usr/bin/env python3
"""Independent grant verifier: verify-grant.py KEY_JSON GRANT_JSON [--at UNIX_SECONDS]."""
import argparse
import json
from pathlib import Path
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('key', type=Path)
    p.add_argument('grant', type=Path)
    p.add_argument('--at', type=int, default=None)
    a = p.parse_args()
    key = json.loads(a.key.read_bytes())
    grant = json.loads(a.grant.read_bytes())
    sig = bytes.fromhex(grant.pop('sig'))
    assert set(grant) == {'v', 'grant_id', 'relay_peer', 'client_peer', 'bytes', 'expires_at'}
    assert grant['v'] == 1 and len(bytes.fromhex(grant['grant_id'])) == 16
    assert type(grant['bytes']) is int and grant['bytes'] > 0
    assert type(grant['expires_at']) is int and grant['expires_at'] > (a.at if a.at is not None else time.time())
    raw = json.dumps(grant, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(key['public_key'])).verify(sig, raw)
    print(json.dumps({'verified': True, 'grant_id': grant['grant_id'], 'canonical_json': raw.decode()}))


if __name__ == '__main__':
    main()
