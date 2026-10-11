#!/bin/bash
# Exercise the real app/API availability and HTTPS stack. No attestation replacement.
# Fixed localhost ports 8443/8444 must be free; this script manages its own servers.
set -euo pipefail
lab_root=$(cd "$(dirname "$0")/.." && pwd)
cd "$lab_root"
lab_runtime=${LAB_SIM_RUNTIME:-com.apple.CoreSimulator.SimRuntime.iOS-26-5}
lab_device_type=${LAB_SIM_DEVICE_TYPE:-com.apple.CoreSimulator.SimDeviceType.iPhone-16}
lab_run="build/preflight-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$lab_run" captures
if [[ ! -f build/simulator-id.txt ]]; then
  xcrun simctl create AppAttestSoK "$lab_device_type" "$lab_runtime" > build/simulator-id.txt
fi
lab_sim=$(cat build/simulator-id.txt)
# A previously booted simulator is fine; bootstatus verifies actual readiness.
xcrun simctl boot "$lab_sim" 2>/dev/null || true
xcrun simctl bootstatus "$lab_sim" -b
if [[ ! -f tls/simulator-good/ca.pem ]]; then
  .venv/bin/python scripts/make_lab_tls.py tls/simulator-good --host Andrews-Mac-mini.local
fi
if [[ ! -f tls/simulator-untrusted/ca.pem ]]; then
  .venv/bin/python scripts/make_lab_tls.py tls/simulator-untrusted
fi
xcrun simctl keychain "$lab_sim" add-root-cert tls/simulator-good/ca.pem
# Refuse to interfere with existing listeners, including a separately running lab server.
.venv/bin/python - <<'PY'
import socket
for port in (8443,8444):
    with socket.socket() as s:
        try: s.bind(('127.0.0.1',port))
        except OSError: raise SystemExit(f'Port {port} is in use; stop the existing lab listener first.')
PY
lab_good_pid=''
lab_bad_pid=''
cleanup() {
  if [[ -n "$lab_good_pid" ]]; then kill "$lab_good_pid" 2>/dev/null || true; fi
  if [[ -n "$lab_bad_pid" ]]; then kill "$lab_bad_pid" 2>/dev/null || true; fi
}
trap cleanup EXIT
bash scripts/serve-mac.sh --app-id DC9JH5DRMY.org.example.AppAttestLab --environment development \
  --database "$lab_run/good.sqlite" --tls-cert tls/simulator-good/server.pem --tls-key tls/simulator-good/server.key \
  > "$lab_run/verifier.log" 2>&1 & lab_good_pid=$!
bash scripts/serve-mac.sh --app-id DC9JH5DRMY.org.example.AppAttestLab --environment development \
  --database "$lab_run/bad.sqlite" --port 8444 --tls-cert tls/simulator-untrusted/server.pem --tls-key tls/simulator-untrusted/server.key \
  > "$lab_run/untrusted.log" 2>&1 & lab_bad_pid=$!
.venv/bin/python - <<'PY'
import ssl,time,urllib.request
for port,ca in [(8443,'good'),(8444,'untrusted')]:
    ctx=ssl.create_default_context(cafile=f'tls/simulator-{ca}/ca.pem')
    for attempt in range(30):
        try:
            with urllib.request.urlopen(f'https://localhost:{port}/health',context=ctx,timeout=1) as r:
                assert r.status==200
            break
        except OSError:
            if attempt==29: raise
            time.sleep(0.2)
PY
python3 scripts/make_project.py
for lab_variant in honest modified; do
  lab_flags=''
  if [[ "$lab_variant" == modified ]]; then lab_flags=MODIFIED; fi
  xcodebuild -quiet -project app/AppAttestLab.xcodeproj -scheme AppAttestLab -configuration Debug \
    -destination "platform=iOS Simulator,id=$lab_sim" -derivedDataPath "build/simulator-$lab_variant" \
    -resultBundlePath "$lab_run/$lab_variant.xcresult" -parallel-testing-enabled NO \
    CODE_SIGNING_ALLOWED=NO "SWIFT_ACTIVE_COMPILATION_CONDITIONS=$lab_flags" test \
    > "$lab_run/$lab_variant.log" 2>&1
  xcrun xcresulttool get test-results summary --path "$lab_run/$lab_variant.xcresult" --format json \
    > "$lab_run/$lab_variant-summary.json"
  .venv/bin/python - "$lab_run/$lab_variant-summary.json" <<'PY'
import json,sys
s=json.load(open(sys.argv[1]))
assert s['passedTests']==4 and s['failedTests']==0 and s['skippedTests']==0, s
print(sys.argv[1],': 4 tests passed')
PY
done
lab_container=$(xcrun simctl get_app_container "$lab_sim" org.example.AppAttestLab data)
mkdir "$lab_run/phone-documents"
cp "$lab_container"/Documents/capture-*.json "$lab_run/phone-documents/"
.venv/bin/python - "$lab_run" <<'PY'
import sqlite3,sys,pathlib,json
p=pathlib.Path(sys.argv[1]); counts={}
for name in ['good','bad']:
    with sqlite3.connect(p/f'{name}.sqlite') as con:
        counts[name]={table:con.execute(f'SELECT count(*) FROM {table}').fetchone()[0]
                      for table in ['keys','challenges','evidence']}
        assert all(n==0 for n in counts[name].values()), counts
(p/'server-state.json').write_text(json.dumps(counts,indent=2)+'\n')
print('No keys, challenges, or attestation evidence created by simulator preflight.')
PY
echo "Results: $lab_run"
