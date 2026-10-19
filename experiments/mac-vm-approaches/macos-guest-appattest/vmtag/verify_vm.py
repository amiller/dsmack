#!/usr/bin/env python3
"""Verify the VM-profile tag probe captures with verifier/core.py. usage: verify_vm.py <unix-time>
<unix-time> is when the certificate chain is checked; the leaf is valid for about three days."""
import json, re, sys
from pathlib import Path
REPO = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO))
from verifier.core import Policy, Reject, verify_attestation, verify_assertion

here = Path(__file__).parent
root = (REPO / 'trust/apple-app-attestation-root.pem').read_bytes()
at_time = int(sys.argv[1])
cd = bytes.fromhex(re.search(r'CandidateCDHashFull sha256=(\w+)', (here / 'codesign-vm.txt').read_text())[1])
pol = Policy('DC9JH5DRMY.dev.dsmack.provider', 'production', cdhashes=(cd,), require_macos_acl=True)
e, a = here / 'host-enroll', here / 'host-assert'
report = {'built_cdhash': cd.hex()}
try:
    att = verify_attestation((e / 'attestation.cbor').read_bytes(), (e / 'keyId.txt').read_text(), (e / 'clientData.json').read_bytes(), pol, root, at_time)
    asr = verify_assertion((a / 'assertion.cbor').read_bytes(), (a / 'clientData.json').read_bytes(), att['public_key'], 0, pol)
    report['host'] = {'pass': True, 'attest_cdhash': att['signals']['cdhash'], 'assert_cdhash': asr['signals']['cdhash'], 'counter': asr['counter']}
except Reject as x:
    report['host'] = {'pass': False, 'reject': str(x)}
report['host']['tag'] = json.loads((e / 'clientData.json').read_text())['tag']
g = here / 'guest-runs'
report['guest'] = {'tag': json.loads((g / 'vm-enroll/clientData.json').read_text())['tag'],
                   'enroll_error': (g / 'vm-enroll/error.txt').read_text(), 'enroll2_error': (g / 'vm-enroll2/error.txt').read_text(),
                   'attestation_produced': (g / 'vm-enroll/attestation.cbor').exists()}
print(json.dumps(report, indent=2))
