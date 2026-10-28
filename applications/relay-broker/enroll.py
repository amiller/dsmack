#!/usr/bin/env python3
"""Verify a runner enrollment against Apple's root; emit a public enrollment pin.

enroll.py ENROLLMENT_DIRECTORY CDHASH
"""
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from cryptography import x509
from verifier.core import decode, unb64, verify_key
from verifier.macos_policy import policy, root


def enrollment(folder, cdhash):
    raw = (folder / 'attestation.cbor').read_bytes()
    kid = (folder / 'keyId.txt').read_text().strip()
    result = verify_key(raw, kid, (folder / 'clientData.bin').read_bytes(),
                        policy(bytes.fromhex(cdhash)), root(), time.time())
    pub = unb64(result['public_key'])
    intermediate = x509.load_der_x509_certificate(decode(raw)['attStmt']['x5c'][1])
    return dict(kid=unb64(kid).hex(), x=pub[1:33].hex(), y=pub[33:].hex(),
                expires=int(intermediate.not_valid_after_utc.timestamp()))


if __name__ == '__main__':
    print(json.dumps(enrollment(Path(sys.argv[1]), sys.argv[2])))
