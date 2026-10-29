#!/usr/bin/env bash
# Run explicitly after reviewing the broker config and W3 page archive.
# CONFIG OPERATOR_TOKEN_FILE PRIVATE_AGENT_TARBALL EVIDENCE_DIR [WEBHOST_URL]
set -euo pipefail
set +x
[[ $# -ge 4 && $# -le 5 ]] || { echo "usage: deploy-webapp.sh CONFIG OPERATOR_TOKEN_FILE PRIVATE_AGENT_TARBALL EVIDENCE_DIR [WEBHOST_URL]" >&2; exit 2; }
: "${TEE_DAEMON_TOKEN:?Export the webhost admin token on the deployment machine}"
export TEE_DAEMON_TOKEN
script_dir=$(cd "$(dirname "$0")" && pwd)
page_archive=$(realpath "$3")
evidence_dir=$(realpath -m "$4")
webhost_url=${5:-https://pod.dstack.soc1024.com}
# Validate the archive before changing either project.
python3 - "$page_archive" "$webhost_url" <<'PY'
import json, os, sys, tarfile
from urllib.request import Request, urlopen
with tarfile.open(sys.argv[1], 'r:gz') as archive:
    project = json.load(archive.extractfile('project.json'))
    if project.get('runtime') != 'deno' or project.get('isolation') != 'shared':
        raise RuntimeError('private-agent must use shared Deno')
    if project['entry'] not in archive.getnames():
        raise RuntimeError('private-agent archive is missing its entry')
with urlopen(Request(sys.argv[2].rstrip('/') + '/_api/projects',
                     headers={'Authorization': 'Bearer ' + os.environ['TEE_DAEMON_TOKEN']}), timeout=30) as response:
    if any(project['name'] == 'private-agent' for project in json.load(response)):
        raise RuntimeError('private-agent already exists; review it before replacing')
PY
bash "$script_dir/deploy.sh" "$1" "$2" "$evidence_dir/broker" "$webhost_url"
python3 - "$page_archive" "$evidence_dir/page" "$webhost_url" "$script_dir/../.." <<'PY'
import json, os, secrets, subprocess, sys
from pathlib import Path
from urllib.request import Request, urlopen
archive, evidence, host, code_root = sys.argv[1:]
evidence = Path(evidence)
evidence.mkdir(parents=True, exist_ok=True)
host = host.rstrip('/')
admin = os.environ.pop('TEE_DAEMON_TOKEN')

def api(path, method='GET', data=None, kind=None):
    headers = {'Authorization': 'Bearer ' + admin}
    if kind:
        headers['Content-Type'] = kind
    with urlopen(Request(host + path, data=data, headers=headers, method=method), timeout=180) as response:
        return json.load(response)

before = api('/_api/projects')
if any(project['name'] == 'private-agent' for project in before):
    raise RuntimeError('private-agent already exists; review it before replacing')
ref = subprocess.check_output(['git', '-C', code_root, 'rev-parse', 'HEAD'], text=True).strip()
manifest = {'name': 'private-agent', 'source': 'tarball://private-agent', 'ref': ref}
boundary = 'private-agent-' + secrets.token_hex(16)
body = (f'--{boundary}\r\nContent-Disposition: form-data; name="manifest"\r\nContent-Type: application/json\r\n\r\n'.encode()
        + json.dumps(manifest).encode()
        + f'\r\n--{boundary}\r\nContent-Disposition: form-data; name="files"; filename="app.tgz"\r\nContent-Type: application/gzip\r\n\r\n'.encode()
        + Path(archive).read_bytes() + f'\r\n--{boundary}--\r\n'.encode())
project = api('/_api/projects', 'POST', body, 'multipart/form-data; boundary=' + boundary)
if project['runtime'] != 'deno' or project['isolation'] != 'shared':
    raise RuntimeError('private-agent did not select shared Deno')
project = api('/_api/projects/private-agent/promote', 'POST')
summary = {k: project.get(k) for k in ('name', 'runtime', 'isolation', 'ref', 'tree_hash')}
(evidence / 'deployment.json').write_text(json.dumps(summary, indent=2) + '\n')
print(host + '/private-agent/')
PY
