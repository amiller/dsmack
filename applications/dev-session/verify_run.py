#!/usr/bin/env python3
"""verify_run.py DSMACK_REPO RUN_DIR ENROLLMENT_DIR CDHASH RESULT_IMG_SHA256 WORKLOAD_NAME BOUND_ARTIFACT

Checks one run launched with applications/compute-node/pool_mac_run.py: the App Attest enrollment key (Apple
root, runner cdhash), the launch assertion, the guest /v1/Attest assertion and the result assertion, that they
bind the manifest, the result disk and BOUND_ARTIFACT, and prints each service's security profile from the
measured compose."""
import base64, hashlib, json, sys, time
from pathlib import Path
repo, run, enroll = map(Path, sys.argv[1:4])
cdhash, result_img_sha, name, bound = sys.argv[4:8]
sys.path[:0] = [str(repo), str(repo / 'dstack-compat')]
from verifier.core import verify_key, verify_assertion
from verifier.macos_policy import policy, root
import guest_attest

sha = lambda b: hashlib.sha256(b).digest()
canon = lambda v: json.dumps(v, sort_keys=True, separators=(',', ':')).encode()
out, art = run / 'out', run / name / 'outputs/artifacts'
pol = policy(bytes.fromhex(cdhash))
key_id = (enroll / 'keyId.txt').read_text().strip()
pub = verify_key((enroll / 'attestation.cbor').read_bytes(), key_id, (enroll / 'clientData.bin').read_bytes(),
                 pol, root(), time.time())['public_key']
env = json.loads((out / 'envelope.json').read_bytes())
manifest_bytes = (run / 'compose-manifest.json').read_bytes()
manifest = sha(manifest_bytes).hex()
assert env['launch']['manifest_sha256'] == manifest and env['launch']['key_id_b64'] == key_id
launch_cd = (out / 'launch-client-data.bin').read_bytes()
assert manifest.encode() in launch_cd
c1 = verify_assertion((out / 'launch-assertion.cbor').read_bytes(), launch_cd, pub, 0, pol)['counter']

bound_bytes = (art / bound).read_bytes()
g = guest_attest.verify(bytes.fromhex(json.loads((art / 'attestation-json').read_bytes())['attestation']))
assert g['report_data'] == sha(bound_bytes) + bytes(32), 'report_data does not bind the artifact'
assert g['manifest_sha256'].hex() == manifest and g['run'] == sha(launch_cd)
assert g['key_id'] == base64.b64decode(key_id)
gcd = guest_attest.client_data(g['os_image_hash'], g['manifest_sha256'], g['run'], g['head'], g['caller'], g['report_data'])
# The guest's Attest binds sha256(launch client data); the runner signs the launch assertion later.
c2 = verify_assertion(g['assertion'], gcd, pub, 0, pol)['counter']

result_cd = (out / 'result-client-data.bin').read_bytes()
assert env['result_disk']['sha256'] == result_img_sha, 'result.img differs from the envelope'
assert result_cd.split(b'\0')[2] == sha(canon(['dsmack.run-result-envelope/1', env])).hex().encode(), 'result client data does not bind the envelope'
c3 = verify_assertion((out / 'result-assertion.cbor').read_bytes(), result_cd, pub, c1, pol)['counter']
services = json.loads(json.loads(manifest_bytes)['docker_compose_file'])['services']
print(json.dumps({'ok': True, 'runner_cdhash': cdhash, 'app_attest_key_id': key_id, 'manifest_sha256': manifest,
                  'os_image_hash': g['os_image_hash'].hex(), 'security_profiles': {s: v.get('security_profile') for s, v in services.items()},
                  'bound_artifact': bound, 'bound_sha256': sha(bound_bytes).hex(), 'result_disk_sha256': result_img_sha,
                  'counters': {'launch': c1, 'guest_attest': c2, 'result': c3}}, indent=1))
