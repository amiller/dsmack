"""Offline check of a vz-spike capture pair: enrollment + assertion from the VZ-entitled app.

usage: python3 verify.py <enroll-capture> <assert-capture> <unix-time>
<unix-time> is the time the certificate chain is checked at; the leaf expires about two
days after enrollment, so a recorded capture is checked at a time inside its validity.
Checks the attestation (Apple root, Mac ACL, category 3, CDHash allowlist = the
CandidateCDHashFull that codesign reported for the captured binary), the assertion signature/counter/CDHash under the enrolled key, and
that the assertion's clientData commits to the challenge and to sha256(compose.yaml).
"""
import hashlib, json, sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))
from verifier.core import verify_attestation, verify_assertion
from verifier.macos_policy import policy, root

enroll, assertion = map(Path, sys.argv[1:3])
at_time = int(sys.argv[3])
results = {}
for name, folder in (('enroll', enroll), ('assert', assertion)):
    cd = next(l.split('=', 1)[1] for l in (folder / 'codesign.txt').read_text().splitlines()
              if l.startswith('CandidateCDHashFull sha256='))
    client = json.loads((folder / 'clientData.bin').read_bytes())
    assert client['challenge'] == (folder / 'challenge.bin').read_bytes().hex(), 'challenge_mismatch'
    assert client['compose_sha256'] == hashlib.sha256((folder / 'compose.yaml').read_bytes()).hexdigest(), 'compose_mismatch'
    results[name] = {'cdhash': cd, 'clientData': client}

pol = policy(bytes.fromhex(results['enroll']['cdhash']))
att = verify_attestation((enroll / 'attestation.cbor').read_bytes(), (enroll / 'keyId.txt').read_text().strip(),
                         (enroll / 'clientData.bin').read_bytes(), pol, root(), at_time)
assert (assertion / 'keyId.txt').read_text().strip() == (enroll / 'keyId.txt').read_text().strip(), 'key_mismatch'
asr = verify_assertion((assertion / 'assertion.cbor').read_bytes(), (assertion / 'clientData.bin').read_bytes(),
                       att['public_key'], 0, pol)
att.pop('receipt')
results.update(attestation=att, assertion=asr, vm_stdout=(assertion / 'vm_stdout.txt').read_text())
print(json.dumps(results, indent=2, sort_keys=True))
