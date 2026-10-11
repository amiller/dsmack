#!/bin/bash
# Signed/attested test pass on the mini, after ./sign.sh. Run from runner/: test/attested.sh
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH=/opt/homebrew/bin:$PATH  # verifier/core.py runs `openssl verify -no-CAstore`; /usr/bin/openssl is LibreSSL
openssl version | grep -q '^OpenSSL 3' || { echo "attested.sh: need OpenSSL 3 on PATH, got $(openssl version)"; exit 1; }
BASE=$(cd .. && pwd); PY=$BASE/.venv/bin/python; APP=$PWD/build/Runner.app
CDH=$(cat build/cdhash.txt) || exit 1
codesign --verify --strict "$APP" || exit 1
[ "$(codesign -d --verbose=4 "$APP" 2>&1 | sed -n 's/^CandidateCDHashFull sha256=//p')" = "$CDH" ] || { echo "attested.sh: $APP does not match build/cdhash.txt"; exit 1; }
RUNS=$BASE/runs/attested-$(date +%Y%m%dT%H%M%S); mkdir -p "$RUNS"; echo "runs dir: $RUNS"; echo "cdhash: $CDH"
H=$(cat test/app-compose.sdk-hash)
KEY=sk-dummy-$(openssl rand -hex 16)
FAILED=0
check() { local name=$1; shift; if "$@" >/dev/null 2>&1; then echo "PASS $name"; else echo "FAIL $name"; FAILED=$((FAILED+1)); fi; }
# App Attest needs a LaunchServices-launched bundle, so the runner goes through `open`; its exit code is lost,
# and every check reads its output files instead. $1 = run name (out dir and stderr log), $2 = KMS port, $3 = compose,
# then extra runner arguments.
# --app is the genesis app "<cdhash>|<compose_hash>" unless RUN_APP is set. Volumes live under a per-run base ($VB): the
# kernel and image store are shared with $BASE, the volumes (the live node's ledgers) are not.
VB=$RUNS/base; mkdir -p "$VB/volumes"; ln -s "$BASE/vmlinux-arm64" "$BASE/store" "$VB/"
attested() { open -n -W --stdout "$RUNS/$1.stdout" --stderr "$RUNS/$1.txt" "$APP" --args run --base "$VB" \
  --kms "http://127.0.0.1:$2" --out "$RUNS/$1" --compose "$PWD/$3" --app "${RUN_APP:-$CDH|$("$APP/Contents/MacOS/runner" check "$3")}" --attest "${@:4}"
  echo "  $1: $(tail -1 "$RUNS/$1.txt")"; }
# The guest line after "== NAME" in run $1's stdout: a /attest or /key response body.
line() { awk -v s="== $2" '$0==s{getline; print; exit}' "$RUNS/$1/guest_stdout.txt"; }
same() { $PY -c "import json,sys; sys.exit(json.load(open(sys.argv[1]))[sys.argv[3]] != json.load(open(sys.argv[2]))[sys.argv[3]])" "$@"; }

check compose_hash_equals_dstack_sdk test "$("$APP/Contents/MacOS/runner" check test/app-compose.json)" = "$H"
HK=$("$APP/Contents/MacOS/runner" check test/app-compose-key.json); HK2=$("$APP/Contents/MacOS/runner" check test/app-compose-key2.json)
HR=$("$APP/Contents/MacOS/runner" check test/app-compose-reenroll.json)
HV=$("$APP/Contents/MacOS/runner" check test/app-compose-volume.json); HV2=$("$APP/Contents/MacOS/runner" check test/app-compose-volume2.json)
HTASKS=$("$APP/Contents/MacOS/runner" check test/app-compose-tasks.json)
KMSREC=$RUNS/kms-bodies; KMS_STATE=$RUNS/kms-state; KEY_CDHASH=$CDH
KMS_API_KEY=$KEY $PY kms/kms.py --state "$KMS_STATE" --port 8790 --record "$KMSREC" --allow "$CDH:$H" --allow "$CDH:$HK" --allow "$CDH:$HK2" --allow "$CDH:$HR" --allow "$CDH:$HV" --allow "$CDH:$HTASKS" --allow "shared:$CDH:$HV2" > "$RUNS/kms.log" 2>&1 & KPID=$!
KMS_API_KEY=$KEY $PY kms/kms.py --state "$RUNS/kms-wrongcdhash-state" --port 8792 --record "$RUNS/kms-wrongcdhash-bodies" --allow "$(printf '%064d' 0):$H" > "$RUNS/kms-wrongcdhash.log" 2>&1 & WPID=$!
sleep 1

attested wrong-cdhash 8792 test/app-compose.json
check kms_refuses_other_cdhash grep -q "403.*cdhash_policy_failed" "$RUNS/wrong-cdhash.txt"
attested changed-compose 8790 test/app-compose-byte.json
check kms_refuses_changed_compose grep -q "403.*cdhash_compose_pair_not_allowed" "$RUNS/changed-compose.txt"

OUT=$RUNS/boot
attested boot 8790 test/app-compose.json
cp "$RUNS/boot.txt" "$RUNS/runner.log"
check attested_release grep -q "API key and app key released by KMS" "$RUNS/runner.log"
check kms_released_attested grep -q "released key to app '$CDH|$H' compose $H .* attested" "$RUNS/kms.log"
check clientdata_names_genesis_app grep -qF "\"app\":\"$CDH|$H\"" "$OUT/clientData.bin"
check no_enrollment_evidence_on_disk sh -c "! ls '$OUT/keyId.txt' '$OUT/attestation.cbor'"
line boot attest > "$OUT/attest.json"
$PY -c "import base64,json,sys; sys.stdout.buffer.write(base64.b64decode(json.load(open(sys.argv[1]))['bootClientData']))" "$OUT/attest.json" > "$RUNS/attest-enrollment.bin"
check attest_serves_boot_enrollment cmp -s "$RUNS/attest-enrollment.bin" "$OUT/clientData.bin"

# Replay the boot's exact /release request; the KMS checks the nonce last, so this also re-passes attestation.
$PY - "$OUT" > "$RUNS/replay.txt" 2>&1 <<'EOF'
import base64, json, sys, urllib.error, urllib.request
from pathlib import Path
o = Path(sys.argv[1]); ev = json.loads((o / 'attest.json').read_text())
body = json.dumps({'mode': 'attested', 'client_data': base64.b64encode((o / 'clientData.bin').read_bytes()).decode(),
                   'attestation': ev['attestation'], 'key_id': ev['keyId']}).encode()
try:
    r = urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8790/release', body, {'content-type': 'application/json'}))
    print(r.status, r.read().decode())
except urllib.error.HTTPError as e:
    print(e.code, e.read().decode())
EOF
echo "  replay: $(cat "$RUNS/replay.txt")"
check kms_refuses_replayed_attestation grep -q "^403 .*unknown_or_stale_nonce" "$RUNS/replay.txt"
check key_released_exactly_once test "$(grep -c 'released key' "$RUNS/kms.log")" = 1

DATA='abalone-attest/1|peerA|peerB|n1'
va() { $PY kms/verify_attest.py "$@" 2>&1; }
va "$OUT/attest.json" --cdhash "$CDH" --compose test/app-compose.json --data "$DATA" > "$RUNS/verify-attest.txt"; cat "$RUNS/verify-attest.txt"
check attest_response_verifies grep -q '"ok": true' "$RUNS/verify-attest.txt"
check attest_cdhash_is_signed_build grep -q "\"cdhash\": \"$CDH\"" "$RUNS/verify-attest.txt"
check attest_compose_hash_equals_boot grep -q "\"compose_hash\": \"$H\"" "$RUNS/verify-attest.txt"
va "$OUT/attest.json" --cdhash "$(printf '%064d' 0)" --compose test/app-compose.json --data "$DATA" > "$RUNS/verify-attest-cdhash.txt"
check attest_other_cdhash_refused grep -q "cdhash_policy_failed" "$RUNS/verify-attest-cdhash.txt"
va "$OUT/attest.json" --cdhash "$CDH" --compose test/app-compose-byte.json --data "$DATA" > "$RUNS/verify-attest-compose.txt"
check attest_other_compose_refused grep -q "compose_hash_not_allowed" "$RUNS/verify-attest-compose.txt"
va "$OUT/attest.json" --cdhash "$CDH" --compose test/app-compose.json --data 'abalone-attest/1|peerA|peerC|n1' > "$RUNS/verify-attest-data.txt"
check attest_other_data_refused grep -q "unexpected_assert_data" "$RUNS/verify-attest-data.txt"

# Key stability: the key compose twice and a changed compose, all under this CDHash and KMS master.
attested key1 8790 test/app-compose-key.json
attested key2 8790 test/app-compose-key.json
attested key3 8790 test/app-compose-key2.json
echo "  keys: key1 $(line key1 peer-id) key2 $(line key2 peer-id) key3 $(line key3 peer-id)"
check attested_key_is_64_hex sh -c "echo '$(line key1 peer-id)' | grep -Eq '^\{\"key\":\"[0-9a-f]{64}\"\}$'"
check attested_key_stable_across_boots test "$(line key1 peer-id)" = "$(line key2 peer-id)"
check attested_key_changed_compose_differs test "$(line key1 peer-id)" != "$(line key3 peer-id)"
check attested_key_matches_kms_derivation test "$(line key1 peer-id)" = "{\"key\":\"$($PY test/derive_key.py "$KMS_STATE/master.key" "$CDH" "$HK" peer-id)\"}"

# Re-enrollment every 5 s; the guest's two /attest calls are 12 s apart.
attested reenroll 8790 test/app-compose-reenroll.json --reenroll-seconds 5
line reenroll attest_1 > "$RUNS/reenroll/attest_1.json"; line reenroll attest_2 > "$RUNS/reenroll/attest_2.json"
for i in 1 2; do va "$RUNS/reenroll/attest_$i.json" --cdhash "$CDH" --compose test/app-compose-reenroll.json --data "abalone-attest/1|peerA|peerB|r$i" > "$RUNS/verify-reenroll-$i.txt"; cat "$RUNS/verify-reenroll-$i.txt"; done
check reenroll_logged grep -q "re-enrolled App Attest key" "$RUNS/reenroll.txt"
check reenroll_attest_1_verifies grep -q '"ok": true' "$RUNS/verify-reenroll-1.txt"
check reenroll_attest_2_verifies grep -q '"ok": true' "$RUNS/verify-reenroll-2.txt"
check reenroll_attest_2_is_reenrollment grep -q '"enrollment": "mac-compose-enroll/1"' "$RUNS/verify-reenroll-2.txt"
check reenroll_new_key_id sh -c "$(declare -f same); PY='$PY'; ! same '$RUNS/verify-reenroll-1.txt' '$RUNS/verify-reenroll-2.txt' key_id"
check reenroll_same_receipt_pub same "$RUNS/verify-reenroll-2.txt" "$RUNS/reenroll/clientData.bin" receipt_pub
check reenroll_names_app grep -q "\"app\": \"$CDH|$HR\"" "$RUNS/verify-reenroll-2.txt"
check reenroll_keeps_boot_nonce $PY -c "import base64,json,sys; e=json.loads(base64.b64decode(json.load(open(sys.argv[1]))['bootClientData'])); b=json.load(open(sys.argv[2])); sys.exit(not (e['domain']=='mac-compose-enroll/1' and e['nonce']==b['nonce']))" "$RUNS/reenroll/attest_2.json" "$RUNS/reenroll/clientData.bin"
# Named volume: the second attested boot of the same compose reads what the first wrote.
attested vol1 8790 test/app-compose-volume.json --oci-archive "$BASE/oci/peer-arm64.oci.tar"
attested vol2 8790 test/app-compose-volume.json --oci-archive "$BASE/oci/peer-arm64.oci.tar"
check attested_volume_persists sh -c "test -n '$(line vol1 wrote)' && test '$(line vol2 before)' = '$(line vol1 wrote)'"
check attested_volume_keyed_by_app grep -q "created volume ledger at $VB/volumes/$(printf '%s' "$CDH|$HV" | shasum -a 256 | cut -c1-64)/ledger.ext4\$" "$RUNS/vol1.txt"
check attested_volume_marker_is_compose_hash test "$(line vol2 marker)" = "$HV"
# The genesis app's image at the pre-app path volumes/<cdhash>/<HV>/ is found there.
mkdir -p "$VB/volumes/$CDH/$HV"; mv "$VB/volumes/$(printf '%s' "$CDH|$HV" | shasum -a 256 | cut -c1-64)/ledger.ext4" "$VB/volumes/$CDH/$HV/"
attested vol-legacy 8790 test/app-compose-volume.json --oci-archive "$BASE/oci/peer-arm64.oci.tar"
check attested_legacy_volume_path_used grep -q "volumes of app $CDH|$HV at $VB/volumes/$CDH/$HV\$" "$RUNS/vol-legacy.txt"
check attested_legacy_volume_persists test "$(line vol-legacy before)" = "$(line vol1 wrote)"
# App "shared" (a non-genesis app): its /key is HKDF of the app id, not of the build.
RUN_APP=shared attested app-shared 8790 test/app-compose-volume2.json --oci-archive "$BASE/oci/peer-arm64.oci.tar"
check attested_app_key_matches_app_derivation test "$(line app-shared peer-id)" = "{\"key\":\"$($PY test/derive_key.py "$KMS_STATE/master.key" --app shared peer-id)\"}"
check attested_clientdata_names_app grep -q '"app":"shared"' "$RUNS/app-shared/clientData.bin"
RUN_APP=other attested app-wrong 8790 test/app-compose-volume2.json
check attested_kms_refuses_build_under_other_app grep -q "403.*build_not_in_requested_app" "$RUNS/app-wrong.txt"
# Task guests: the same driver as run_tests.sh; each task boot's guest/attest.json is a real runner assertion.
attested tasks 8790 test/app-compose-tasks.json --oci-archive "$BASE/oci/peer-arm64.oci.tar" --task-archive "$BASE/oci/task-test.oci.tar"
kill $KPID $WPID

VERIFY=(--cdhash "$CDH"); BINDING=(clientData.bin attest.json)
source test/boot_checks.sh
TOUT=$RUNS/tasks; TLOG=$RUNS/tasks.txt
source test/task_checks.sh
check task_evidence_is_macrunner grep -q '"type":"macrunner"' "$RUNS/task-collect/guest/attest.json"
check task_receipts_bound_to_attested_cdhash grep -q "\"boot_binding\": \"attested (runner assertion under the peer enrollment), cdhash $CDH\"" "$RUNS/verify-task.txt"
$PY kms/verify_receipts.py "$RUNS/task-collect" --task --peer-compose test/app-compose-tasks.json --cdhash "$(printf '%064d' 0)" > "$RUNS/verify-task-cdhash.txt" 2>&1
check task_other_cdhash_refused grep -q "cdhash_policy_failed" "$RUNS/verify-task-cdhash.txt"
check receipts_bound_to_attested_cdhash grep -q "\"boot_binding\": \"attested, cdhash $CDH\"" "$RUNS/verify.txt"
check key_absent_from_kms_logs sh -c "! grep -r -q -a -F '$KEY' '$RUNS/kms.log' '$RUNS/kms-wrongcdhash.log' '$RUNS/replay.txt' '$RUNS/kms-wrongcdhash-bodies'"
for d in key1 key2 key3 reenroll vol1 vol2 vol-legacy app-shared; do rm -rf "../store/containers/$(cat "$RUNS/$d/container_id.txt")"; done
cat "$RUNS/kms.log" "$RUNS/kms-wrongcdhash.log"
echo "FAILED=$FAILED"; exit $FAILED
