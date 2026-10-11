#!/usr/bin/env python3
"""Verify captured enrollment against an exact signed binary and explicit profile."""
import argparse
import base64
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'app/macos'))
from verifier.core import decode, verify_attestation, Policy
from check_evidence import code_directory_hash, root


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--request', type=Path, required=True)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--app-id', required=True)
    p.add_argument('--category', type=int, choices=(2, 3, 4, 6), required=True)
    p.add_argument('--at-time', type=int, help='Historical replay time, never fresh admission')
    args = p.parse_args()
    request = json.loads(args.request.read_text())
    raw = base64.b64decode(request['attestation'], validate=True)
    auth = decode(raw)['authData']
    if len(auth) < 87 or int.from_bytes(auth[53:55], 'big') != 32:
        raise SystemExit('Invalid credential ID extent')
    kid = base64.b64encode(auth[55:87]).decode()
    cd = code_directory_hash(args.binary.read_bytes())
    policy = Policy(args.app_id, environment='production', cdhashes=(cd,),
                    categories=(args.category,), require_macos_acl=True)
    verified = verify_attestation(raw, kid, bytes.fromhex(request['clientData'].removeprefix('0x')),
                                  policy, root(), args.at_time)
    print(json.dumps({'apple_chain_and_nonce_verified': True, 'signed_binary_code_pages_verified': True,
                      'signals': verified['signals'], 'network_enrollment_submitted': False,
                      'historical_replay_time': args.at_time}, indent=2))


if __name__ == '__main__':
    main()
