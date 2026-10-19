"""Verify a runner /attest response (notes/abalone-node-interface.md item 1) offline with verifier/core.py and the
verifier/macos_policy.py policy (pinned Apple root, production AAGUID, category 3, Mac ACL, CDHash allowlist on both the attestation
and the assertion): the enrollment clientData is attested, is a boot or re-enrollment for an allowed compose_hash and
at most --max-age seconds old; the assertion signs assertClientData under the attested key; assertClientData carries
the same compose_hash and exactly --data.

usage: verify_attest.py RESPONSE.json --cdhash HEX --compose app-compose.json --data STRING [--max-age 43200]
"""
import argparse, hashlib, json, sys, time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
from verifier.core import require, unb64, unique_json, verify_assertion, verify_attestation
from verifier.macos_policy import policy, root

p = argparse.ArgumentParser()
p.add_argument('response', type=Path)
p.add_argument('--cdhash', required=True)
p.add_argument('--compose', type=Path, required=True)
p.add_argument('--data', required=True)
p.add_argument('--max-age', type=int, default=43200)
a = p.parse_args()

ev = unique_json(a.response.read_bytes())
require(ev['type'] == 'macrunner', f"not_macrunner_evidence type={ev['type']}")
pol = policy(bytes.fromhex(a.cdhash))
enroll_bytes, assert_bytes = unb64(ev['bootClientData']), unb64(ev['assertClientData'])
att = verify_attestation(unb64(ev['attestation']), ev['keyId'], enroll_bytes, pol, root())
enroll = unique_json(enroll_bytes)
require(enroll['domain'] in ('mac-compose-boot/1', 'mac-compose-enroll/1') and enroll['attested'] is True, 'wrong_enrollment_domain')
require(enroll['compose_hash'] == hashlib.sha256(a.compose.read_bytes()).hexdigest(), 'compose_hash_not_allowed')
require(0 <= time.time() - enroll['enrolled_at'] <= a.max_age, 'enrollment_too_old')
sig = verify_assertion(unb64(ev['assertion']), assert_bytes, att['public_key'], 0, pol)
require(sig['signals']['cdhash'] == att['signals']['cdhash'], 'assertion_cdhash_differs')
assertion = unique_json(assert_bytes)
require(assertion['domain'] == 'mac-compose-assert/1', 'wrong_assert_domain')
require(assertion['compose_hash'] == enroll['compose_hash'], 'assert_compose_hash_mismatch')
require(assertion['data'] == a.data, 'unexpected_assert_data')
print(json.dumps({'ok': True, 'cdhash': att['signals']['cdhash'], 'app': enroll['app'], 'compose_hash': enroll['compose_hash'], 'enrollment': enroll['domain'],
                  'enrolled_at': enroll['enrolled_at'], 'key_id': ev['keyId'], 'counter': sig['counter'], 'receipt_pub': enroll['receipt_pub']}, indent=2))
