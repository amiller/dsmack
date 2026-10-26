"""Check an admission from e2e_client.py admit with the alpha coordinator's verify path, on the Mac.

python3 - ADMISSION_DIR INSTALL_DIR < alpha_check.py
INSTALL_DIR holds bootstrap/ (alpha_stage.py, bootstrap.json) and installed/, the staged release the
coordinator re-signed. The bootstrap is the installed one with the coordinator's key as trust root.
"""
import hashlib, json, sys
from pathlib import Path

out, install = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
sys.path.insert(0, str(install / 'bootstrap'))
from alpha_stage import authenticate

pem, keys = out / 'coordinator.pem', json.loads((out / 'keys.json').read_bytes())
bootstrap = json.loads((install / 'bootstrap/bootstrap.json').read_bytes())
bootstrap.update(key_id=keys['key_id'], min_sequence=json.loads((out / 'release.json').read_bytes())['sequence'],
                 trust_key={'path': str(pem), 'bytes': pem.stat().st_size, 'sha256': hashlib.sha256(pem.read_bytes()).hexdigest()})
r = authenticate(bootstrap, out / 'release.json', out / 'release.sig', root=install / 'installed', profile='agent-turns-edit-v1',
                 workload_admission=out / 'workload-admission.json', workload_signature=out / 'workload.sig')
assert r['workload']['attempt_id'] == json.loads((out / 'closure-context.json').read_bytes())['attempt_id']
print(json.dumps({'inventory_sha256': r['inventory_sha256'], 'staged_files_checked': r['staged_files_checked'], 'workload': r['workload']}))
