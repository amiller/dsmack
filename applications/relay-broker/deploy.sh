#!/usr/bin/env bash
# Deploy only relay-broker to the shared Deno runtime; credentials stay local.
# deploy.sh CONFIG_JSON OPERATOR_TOKEN_FILE EVIDENCE_DIR [WEBHOST_URL]
set -euo pipefail
set +x
: "${TEE_DAEMON_TOKEN:?Export the webhost admin token as TEE_DAEMON_TOKEN}"
export TEE_DAEMON_TOKEN
export RELAY_BROKER_SOURCE_DIR
RELAY_BROKER_SOURCE_DIR=$(cd "$(dirname "$0")" && pwd)
python3 - "$@" <<'PY'
import hashlib, io, json, os, secrets, stat, subprocess, sys, tarfile, time, tempfile
from pathlib import Path
from urllib.request import Request, urlopen

config, token_path, evidence = (Path(x).resolve() for x in sys.argv[1:4])
cvm = (sys.argv[4] if len(sys.argv) > 4 else 'https://pod.dstack.soc1024.com').rstrip('/')
app = Path(os.environ['RELAY_BROKER_SOURCE_DIR'])
repo = app.parents[1]
evidence.mkdir(parents=True, exist_ok=True)
token_path.parent.mkdir(parents=True, exist_ok=True)
if not token_path.exists():
    with open(token_path, 'x', opener=lambda p, f: os.open(p, f, 0o600)) as f:
        f.write(secrets.token_hex(32))
if stat.S_IMODE(token_path.stat().st_mode) != 0o600:
    raise RuntimeError('operator token file must have mode 600')
token = token_path.read_text().strip()
if len(token) < 32:
    raise RuntimeError('operator token must have at least 32 characters')
admin = os.environ.pop('TEE_DAEMON_TOKEN')

def api(path, method='GET', data=None, kind=None, authenticated=False):
    headers = {}
    if authenticated:
        headers['Authorization'] = 'Bearer ' + admin
    if kind:
        headers['Content-Type'] = kind
    request = Request(cvm + path, method=method, data=data, headers=headers)
    with urlopen(request, timeout=180) as response:
        return response.status, response.read()

_, substrate = api('/_api/substrate')
(evidence / 'substrate.json').write_bytes(substrate)
if 'shared' not in json.loads(substrate)['isolation_modes']:
    raise RuntimeError('webhost does not support shared Deno')
_, before = api('/_api/projects', authenticated=True)
projects = json.loads(before)
summary = lambda p: {k: p.get(k) for k in ('name', 'runtime', 'isolation', 'mode', 'tree_hash', 'deployed_at', 'ref')}
(evidence / 'projects-before.json').write_text(json.dumps([summary(p) for p in projects], indent=2) + '\n')
secret_release_before = next((summary(p) for p in projects if p['name'] == 'secret-release'), None)
broker_before = next((p for p in projects if p['name'] == 'relay-broker'), None)
broker_key_before = api('/relay-broker/key')[1] if broker_before else None
payment_key_before = api('/relay-broker/payments/key')[1] if broker_before and json.loads(config.read_text()).get('payments') else None
if broker_key_before:
    (evidence / 'broker-key-before.json').write_bytes(broker_key_before)
if payment_key_before:
    (evidence / 'payments-key-before.json').write_bytes(payment_key_before)
_, release_key_before = api('/secret-release/public-key')
(evidence / 'secret-release-key-before.json').write_bytes(release_key_before)
ref = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()
manifest = {'name': 'relay-broker', 'source': 'tarball://relay-broker', 'ref': ref,
            'env': {'OPERATOR_TOKEN_SHA256': hashlib.sha256(token.encode()).hexdigest()}}
if os.environ.get('SANDBOX_FORWARDER_TOKEN'):
    manifest['env']['SANDBOX_FORWARDER_TOKEN'] = os.environ['SANDBOX_FORWARDER_TOKEN']
files = ['server.ts', 'key.ts', 'broker.mjs', 'grants.mjs', 'attestation.mjs', 'payments.mjs', 'sandbox.mjs']
package = io.BytesIO()
with tarfile.open(fileobj=package, mode='w:gz') as tar:
    for name in files:
        tar.add(app / name, arcname='applications/relay-broker/' + name)
    tar.add(config, arcname='applications/relay-broker/config.json')
    # Shared Deno serves a self-contained ethers bundle; no npm install on the pod.
    with tempfile.TemporaryDirectory(prefix='relay-payments-') as tmp:
        bundled = Path(tmp)/'schema.mjs'
        subprocess.run(['deno','bundle','--platform=browser','--minify',
                        str(repo/'applications/payments/schema.mjs'),'-o',str(bundled)],check=True)
        tar.add(bundled, arcname='applications/payments/schema.mjs')
    for name in ('quorum.mjs','admission.mjs'):
        tar.add(repo/'applications/payments'/name, arcname='applications/payments/'+name)
    tar.add(repo / 'dstack-compat/secret-release/policy.mjs', arcname='dstack-compat/secret-release/policy.mjs')
    tar.add(app / 'project.json', arcname='project.json')
boundary = 'relay-broker-' + secrets.token_hex(16)
body = (f'--{boundary}\r\nContent-Disposition: form-data; name="manifest"\r\nContent-Type: application/json\r\n\r\n'.encode()
        + json.dumps(manifest).encode()
        + f'\r\n--{boundary}\r\nContent-Disposition: form-data; name="files"; filename="app.tgz"\r\nContent-Type: application/gzip\r\n\r\n'.encode()
        + package.getvalue() + f'\r\n--{boundary}--\r\n'.encode())
status, deployed = api('/_api/projects', 'POST', body, 'multipart/form-data; boundary=' + boundary, True)
p = json.loads(deployed)
(evidence / 'deployment.json').write_text(json.dumps(summary(p), indent=2) + '\n')
if p['runtime'] != 'deno' or p['isolation'] != 'shared':
    raise RuntimeError('deployment did not select shared Deno')
# Promotion makes the project-scoped GetKey socket available in the shared runtime.
_, promoted = api('/_api/projects/relay-broker/promote', 'POST', authenticated=True)
p = json.loads(promoted)
(evidence / 'promotion.json').write_text(json.dumps(summary(p), indent=2) + '\n')
for _ in range(60):
    try:
        _, key = api('/relay-broker/key')
        json.loads(key)['public_key']
        break
    except (OSError, ValueError, KeyError):
        time.sleep(2)
else:
    raise RuntimeError('broker key endpoint did not become available after promotion')
(evidence / 'key.json').write_bytes(key)
if broker_key_before and json.loads(broker_key_before) != json.loads(key):
    raise RuntimeError('relay-broker signing key changed during deployment')
if payment_key_before:
    _, payment_key_after = api('/relay-broker/payments/key')
    (evidence / 'payments-key-after.json').write_bytes(payment_key_after)
    if json.loads(payment_key_before) != json.loads(payment_key_after):
        raise RuntimeError('payments signing key changed during deployment')
_, after = api('/_api/projects', authenticated=True)
projects = json.loads(after)
(evidence / 'projects-after.json').write_text(json.dumps([summary(p) for p in projects], indent=2) + '\n')
secret_release_after = next((summary(p) for p in projects if p['name'] == 'secret-release'), None)
_, release_key_after = api('/secret-release/public-key')
(evidence / 'secret-release-key-after.json').write_bytes(release_key_after)
if secret_release_before != secret_release_after or release_key_before != release_key_after:
    raise RuntimeError('secret-release changed during deployment')
print(json.dumps({'url': cvm + '/relay-broker/', 'runtime': p['runtime'], 'isolation': p['isolation'], 'ref': ref}))
PY
