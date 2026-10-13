#!/bin/bash
# Fetch NEAR's attestation report N times through the runner (key injected by the runner, never in the guest) and
# count distinct gateway/model signing addresses and TLS fingerprints. Run from runner/ on the mini.
# usage: test/near_diversity.sh N KEYS_FILE (--attest | --no-attest) [MODEL] [LABEL]
#   --attest needs ./sign.sh first (KMS allowlists build/cdhash.txt). --no-attest is DEV-ONLY: never give it a real key.
set -euo pipefail
cd "$(dirname "$0")/.."
N=$1 KEYS=$2 MODE=$3 MODEL=${4:-deepseek-ai/DeepSeek-V3.1}
LABEL=(); [ $# -ge 5 ] && LABEL=(--label "$5")
BASE=$(cd .. && pwd); PY=$BASE/.venv/bin/python
RUNS=$BASE/runs/near-diversity-$(date +%Y%m%dT%H%M%S); mkdir -p "$RUNS"; echo "runs dir: $RUNS"
$PY - "$RUNS/app-compose.json" "$N" "$MODEL" <<'EOF'
import json, sys
out, n, model = sys.argv[1], int(sys.argv[2]), sys.argv[3]
guest = f'''for i in $(seq {n}); do nonce=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \\n')
curl -sS --unix-socket /run/egress.sock "http://cloud-api.near.ai/v1/attestation/report?model={model}&nonce=$nonce&signing_algo=ecdsa&include_tls_fingerprint=true"; echo; done'''
image = 'docker.io/curlimages/curl@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69'
compose = {'docker_compose_file': json.dumps({'services': {'app': {'image': image, 'command': ['/bin/sh', '-c', guest]}}}),
           'egress': {'allow': [{'auth_header': 'Authorization', 'auth_prefix': 'Bearer ', 'host': 'cloud-api.near.ai', 'method': 'GET',
                                 'path_prefix': '/v1/attestation/report'}], 'max_requests': n, 'max_tokens': 0},
           'kms_enabled': True, 'manifest_version': 2, 'name': 'runner-near-diversity', 'runner': 'docker-compose'}
open(out, 'w').write(json.dumps(compose, sort_keys=True, separators=(',', ':')))
EOF
if [ "$MODE" = --attest ]; then
  export PATH=/opt/homebrew/bin:$PATH
  RUNNER=build/Runner.app/Contents/MacOS/runner; ALLOW=(--allow "$(cat build/cdhash.txt):$($RUNNER check "$RUNS/app-compose.json")")
else
  RUNNER=bin/runner; ALLOW=(--dev-unattested --allow-compose "$($RUNNER check "$RUNS/app-compose.json")")
fi
$PY kms/kms.py --state "$RUNS/kms-state" --port 8798 "${ALLOW[@]}" --keys-file "$KEYS" --provider nearai ${LABEL[@]+"${LABEL[@]}"} > "$RUNS/kms.log" 2>&1 & KPID=$!
sleep 1
if [ "$MODE" = --attest ]; then
  open -n -W --stderr "$RUNS/runner.log" "$PWD/build/Runner.app" --args run --base "$BASE" --dev-kms http://127.0.0.1:8798 --out "$RUNS/out" --compose "$RUNS/app-compose.json" --attest
else
  bin/runner run --base "$BASE" --dev-kms http://127.0.0.1:8798 --out "$RUNS/out" --compose "$RUNS/app-compose.json" --no-attest 2> "$RUNS/runner.log"
fi
kill $KPID
rm -rf "../store/containers/$(cat "$RUNS/out/container_id.txt")"
$PY - "$RUNS/out/guest_stdout.txt" <<'EOF'
import json, sys
seen = {k: set() for k in ('gateway_address', 'gateway_tls', 'model_address', 'model_tls')}
ok = errors = 0
for line in open(sys.argv[1]):
    if not line.strip():
        continue
    r = json.loads(line)
    if 'gateway_attestation' not in r:
        errors += 1; print('not a report:', line.strip()[:200]); continue
    ok += 1
    g = r['gateway_attestation']
    seen['gateway_address'].add(g['signing_address']); seen['gateway_tls'].add(g['tls_cert_fingerprint'])
    for m in r['model_attestations']:
        seen['model_address'].add(m['signing_address']); seen['model_tls'].add(m.get('tls_cert_fingerprint'))
print(json.dumps({'reports': ok, 'errors': errors, **{k: len(v) for k, v in seen.items()}}))
EOF
