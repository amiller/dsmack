#!/bin/bash
# Ad-hoc (--no-attest, DEV-ONLY) test pass on the mini. Run from runner/: test/run_tests.sh
set -uo pipefail
cd "$(dirname "$0")/.."
PY=../.venv/bin/python; NODE=/opt/homebrew/bin/node
RUNS=$(cd .. && pwd)/runs/$(date +%Y%m%dT%H%M%S); mkdir -p "$RUNS"; echo "runs dir: $RUNS"
H=$(cat test/app-compose.sdk-hash)
KEY=sk-dummy-$(openssl rand -hex 16)
FAILED=0
check() { local name=$1; shift; if "$@" >/dev/null 2>&1; then echo "PASS $name"; else echo "FAIL $name"; FAILED=$((FAILED+1)); fi; }
# A per-run base: the kernel and image store are shared with ~/vz-runner, volumes are not (the live node's ledgers are there).
VB=$RUNS/base; mkdir -p "$VB/volumes"; ln -s "$(cd .. && pwd)/vmlinux-arm64" "$(cd .. && pwd)/store" "$VB/"
# --app is the genesis app "dev|<compose_hash>" unless RUN_APP is set.
run() { local a=("$@") i c; for i in "${!a[@]}"; do [ "${a[$i]}" = --compose ] && c=${a[$((i+1))]}; done
  bin/runner run --base "$VB" --dev-kms http://127.0.0.1:${PORT:-8790} --app "${RUN_APP:-dev|$(bin/runner check "$c")}" "$@"; }
appdir() { printf '%s' "$1" | shasum -a 256 | cut -c1-64; }
same() { test -n "$1" && test "$1" = "$2"; }
# A KMS that must refuse to start: it gets 3 s to exit on its own, else it is killed and the check fails.
kms_fails() { local log=$1; shift; $PY kms/kms.py "$@" > "$log" 2>&1 & local pid=$!; sleep 3
  if kill $pid 2>/dev/null; then echo "kms did not exit" >> "$log"; fi; wait $pid 2>/dev/null; echo "  $(tail -1 "$log")"; }

# Synthetic abalone node key store (lib/nodekeys.mjs format). Never a real one.
cat > "$RUNS/keys.json" <<EOF
{"active": {"redpill": "main"}, "keys": [
  {"kind": "api", "provider": "redpill", "label": "main", "key": "$KEY", "added": "2026-10-08T00:00:00Z"},
  {"kind": "api", "provider": "redpill", "label": "spare", "key": "sk-dummy-spare", "added": "2026-10-08T00:00:00Z"}]}
EOF
chmod 600 "$RUNS/keys.json"
KEYS=(--keys-file "$RUNS/keys.json" --provider redpill)

check compose_hash_equals_dstack_sdk test "$(bin/runner check test/app-compose.json)" = "$H"
check byte_change_changes_hash test "$(bin/runner check test/app-compose-byte.json)" != "$H"
bin/runner check test/app-compose-tag.json > "$RUNS/tag.txt" 2>&1; echo "  $(cat "$RUNS/tag.txt")"
check tag_only_image_refused grep -q "not pinned by an @sha256: digest" "$RUNS/tag.txt"
bin/runner check test/app-compose-volume-bind.json > "$RUNS/volume-bind.txt" 2>&1; echo "  $(cat "$RUNS/volume-bind.txt")"
check volume_host_bind_refused grep -q 'volume "/tmp/ledger:/abalone-ledger" is not <name>:/<path>' "$RUNS/volume-bind.txt"
sed 's/"onchain":{/"compose_hashes":["00"],"onchain":{/' test/app-compose-abalone.json > "$RUNS/onchain-both.json"
bin/runner check "$RUNS/onchain-both.json" > "$RUNS/onchain-both.txt" 2>&1; echo "  $(cat "$RUNS/onchain-both.txt")"
check onchain_with_compose_hashes_refused grep -q "exactly one of a non-empty compose_hashes list and onchain" "$RUNS/onchain-both.txt"
sed 's/0xf550fdfb4eb8ad787c1bcd423f091cbb4a4431ae/0xF550fdfb4eb8ad787c1bcd423f091cbb4a4431ae/' test/app-compose-abalone.json > "$RUNS/onchain-case.json"
bin/runner check "$RUNS/onchain-case.json" > "$RUNS/onchain-case.txt" 2>&1; echo "  $(cat "$RUNS/onchain-case.txt")"
check onchain_non_lowercase_app_refused grep -q "lowercase 0x DstackApp addresses" "$RUNS/onchain-case.txt"
bin/runner check test/app-compose-tasks-overcap.json > "$RUNS/tasks-overcap.txt" 2>&1; echo "  $(cat "$RUNS/tasks-overcap.txt")"
check tasks_resource_over_1800s_refused grep -q "tasks.resources.small needs .* 1 <= max_seconds <= 1800" "$RUNS/tasks-overcap.txt"
# On-chain admission against live Base (selector, allowed/random/old-block composes, app-id not in apps, RPC error, unanchored TLS).
$NODE verify/provider_quote.test.mjs > "$RUNS/provider-quote-unit.txt" 2>&1; cat "$RUNS/provider-quote-unit.txt"
check provider_quote_onchain_unit grep -qx "FAILED=0" "$RUNS/provider-quote-unit.txt"

kms_fails "$RUNS/kms-nofile.log" --state "$RUNS/kms-x" --dev-unattested --allow-compose "$H" --keys-file "$RUNS/missing.json" --provider redpill
check kms_missing_keys_file_fails grep -q "FileNotFoundError" "$RUNS/kms-nofile.log"
kms_fails "$RUNS/kms-noactive.log" --state "$RUNS/kms-x" --dev-unattested --allow-compose "$H" --keys-file "$RUNS/keys.json" --provider nearai
check kms_no_active_label_fails grep -q "KeyError: 'nearai'" "$RUNS/kms-noactive.log"
kms_fails "$RUNS/kms-nolabel.log" --state "$RUNS/kms-x" --dev-unattested --allow-compose "$H" --keys-file "$RUNS/keys.json" --provider redpill --label nope
check kms_missing_label_fails grep -q "0 keys for provider redpill label nope" "$RUNS/kms-nolabel.log"
check kms_keys_file_errors_omit_key sh -c "! grep -q -a -F -e '$KEY' -e sk-dummy-spare '$RUNS'/kms-no*.log"

HM=$(bin/runner check test/app-compose-meter.json); HA=$(bin/runner check test/app-compose-abalone.json)
HK=$(bin/runner check test/app-compose-key.json); HK2=$(bin/runner check test/app-compose-key2.json)
HP=$(bin/runner check test/app-compose-peer.json); HPM=$(bin/runner check test/app-compose-peer-mismatch.json)
HT=$(bin/runner check test/app-compose-tunnel.json); HTASKS=$(bin/runner check test/app-compose-tasks.json); HREAL=$(bin/runner check test/app-compose-tasks-real.json)
HV=$(bin/runner check test/app-compose-volume.json); HV2=$(bin/runner check test/app-compose-volume2.json); HVH=$(bin/runner check test/app-compose-volume-hold.json); HD=$(bin/runner check test/app-compose-volume-durable.json)
DEVALLOW=(); for h in "$H" "$HM" "$HA" "$HK" "$HK2" "$HP" "$HPM" "$HT" "$HV" "$HV2" "$HD" "$HTASKS" "$HREAL"; do DEVALLOW+=(--allow-compose "$h"); done
KMSREC=$RUNS/kms-bodies; KMS_STATE=$RUNS/kms-state; KEY_CDHASH=dev
$PY kms/kms.py --state "$RUNS/kms-attested-state" --port 8791 --record "$RUNS/kms-attested-bodies" --allow "$(printf '%064d' 0):$H" "${KEYS[@]}" > "$RUNS/kms-attested.log" 2>&1 & APID=$!
$PY kms/kms.py --state "$KMS_STATE" --dev-unattested --record "$KMSREC" "${DEVALLOW[@]}" "${KEYS[@]}" > "$RUNS/kms.log" 2>&1 & KPID=$!
$PY kms/kms.py --state "$RUNS/kms-noappkey-state" --port 8797 --dev-unattested --dev-omit-app-key --allow-compose "$H" "${KEYS[@]}" > "$RUNS/kms-noappkey.log" 2>&1 & NPID=$!
FAKE_KEY=$KEY $PY test/fake_upstream.py "$RUNS/fake" 8443 > "$RUNS/fake.log" 2>&1 & FPID=$!
mkdir -p "$RUNS/tunnel-www"; echo "tunnel-bytes-$(openssl rand -hex 8)" > "$RUNS/tunnel-www/tunnel.txt"
$PY -m http.server 8794 --bind 127.0.0.1 --directory "$RUNS/tunnel-www" > "$RUNS/tunnel-server.log" 2>&1 & TPID=$!
curl -sS -o "$RUNS/recorded-report.json" "https://api.redpill.ai/v1/aci/attestation?nonce=$(openssl rand -hex 32)"
$PY test/replay_report.py "$RUNS/recorded-report.json" 8795 > "$RUNS/replay-server.log" 2>&1 & RPID=$!
sleep 1
# Same master as the boot KMS; admits HV2 and HVH to app "shared" (the boot KMS has HV2 in its genesis app "dev|HV2").
$PY kms/kms.py --state "$KMS_STATE" --port 8798 --dev-unattested --allow "shared:dev:$HV2" --allow "shared:dev:$HVH" "${KEYS[@]}" > "$RUNS/kms-app.log" 2>&1 & SPID=$!
# Same master again; admits HV2 as an upgrade in HV's genesis app "dev|HV".
$PY kms/kms.py --state "$KMS_STATE" --port 8799 --dev-unattested --allow "dev|$HV:dev:$HV2" "${KEYS[@]}" > "$RUNS/kms-upgrade.log" 2>&1 & UPID=$!
sleep 1
check kms_reads_keys_file grep -q "API key from $RUNS/keys.json provider redpill label main" "$RUNS/kms.log"
kms_fails "$RUNS/kms-twoapps.log" --state "$RUNS/kms-x" --dev-unattested --allow "a:dev:$HV" --allow "b:dev:$HV" "${KEYS[@]}"
check kms_build_in_two_apps_fails grep -q "build dev:$HV is in two apps: 'a', 'b'" "$RUNS/kms-twoapps.log"
kms_fails "$RUNS/kms-devmix.log" --state "$RUNS/kms-x" --dev-unattested --allow "a:$(printf '%064d' 0):$HV" "${KEYS[@]}"
check kms_dev_mode_refuses_real_cdhash grep -q "configure exactly one mode" "$RUNS/kms-devmix.log"

run --compose test/app-compose.json --out "$RUNS/attest" --attest > "$RUNS/attest.txt" 2>&1; echo "  $(tail -1 "$RUNS/attest.txt")"
check attest_on_adhoc_build_fails_loudly grep -q "isSupported is false" "$RUNS/attest.txt"
check attest_logs_own_cdhash grep -q "cdhash $(codesign -d --verbose=4 bin/runner 2>&1 | sed -n 's/^CandidateCDHashFull sha256=//p'), app dev|$H\$" "$RUNS/attest.txt"
bin/runner run --base "$VB" --dev-kms http://127.0.0.1:8790 --compose test/app-compose.json --out "$RUNS/noapp" --no-attest > "$RUNS/noapp.txt" 2>&1; echo "  $(tail -1 "$RUNS/noapp.txt")"
check runner_requires_app grep -q "missing --app <value>" "$RUNS/noapp.txt"
run --compose test/app-compose-meter.json --out "$RUNS/attest-anchor" --attest --dev-test-anchor "$RUNS/fake/ca.der" > "$RUNS/attest-anchor.txt" 2>&1; echo "  $(tail -1 "$RUNS/attest-anchor.txt")"
check attest_refuses_dev_test_anchor grep -q "dev-test-anchor is DEV-ONLY and refused with --attest" "$RUNS/attest-anchor.txt"
PORT=8791 run --compose test/app-compose.json --out "$RUNS/devreq-to-attested-kms" --no-attest > "$RUNS/devreq.txt" 2>&1; echo "  $(tail -1 "$RUNS/devreq.txt")"
check attested_kms_refuses_unattested_request grep -q "attested_request_required" "$RUNS/devreq.txt"
run --compose test/app-compose-byte.json --out "$RUNS/notallowed" --no-attest > "$RUNS/notallowed.txt" 2>&1; echo "  $(tail -1 "$RUNS/notallowed.txt")"
check kms_refuses_unlisted_compose grep -q "compose_hash_not_allowed" "$RUNS/notallowed.txt"
PORT=8797 run --compose test/app-compose.json --out "$RUNS/noappkey" --no-attest > "$RUNS/noappkey.txt" 2>&1; echo "  $(tail -1 "$RUNS/noappkey.txt")"
check parcel_without_app_key_refused grep -q 'KMS parcel must be {"api_key": str, "app": str, "app_key": 64 hex}, got keys \["api_key"\]' "$RUNS/noappkey.txt"
PORT=8798 RUN_APP=shared run --compose test/app-compose-volume.json --out "$RUNS/app-unlisted" --no-attest > "$RUNS/app-unlisted.txt" 2>&1; echo "  $(tail -1 "$RUNS/app-unlisted.txt")"
check app_kms_refuses_build_not_in_allowlist grep -q "403.*compose_hash_not_allowed" "$RUNS/app-unlisted.txt"
PORT=8798 RUN_APP=other run --compose test/app-compose-volume2.json --out "$RUNS/app-wrong" --no-attest > "$RUNS/app-wrong.txt" 2>&1; echo "  $(tail -1 "$RUNS/app-wrong.txt")"
check app_kms_refuses_build_under_other_app grep -q "403.*build_not_in_requested_app" "$RUNS/app-wrong.txt"
cp verify/provider_quote.mjs "$RUNS/tampered.mjs"; echo "// one more byte" >> "$RUNS/tampered.mjs"
run --compose test/app-compose-abalone.json --out "$RUNS/tampered-helper" --no-attest --quote-helper "$RUNS/tampered.mjs" --node $NODE > "$RUNS/tampered-helper.txt" 2>&1; echo "  $(tail -1 "$RUNS/tampered-helper.txt")"
check quote_helper_hash_mismatch_refused grep -q "!= compiled-in" "$RUNS/tampered-helper.txt"
run --compose test/app-compose-peer-mismatch.json --out "$RUNS/peer-mismatch" --no-attest --oci-archive ../oci/peer-arm64.oci.tar > "$RUNS/peer-mismatch.txt" 2>&1; echo "  $(tail -1 "$RUNS/peer-mismatch.txt")"
check oci_archive_digest_mismatch_refused grep -q "manifest digest sha256:4de0c490.* != compose image digest sha256:4de0c491" "$RUNS/peer-mismatch.txt"

run --compose test/app-compose-tasks.json --out "$RUNS/task-archive-wrong" --no-attest --task-archive ../oci/peer-arm64.oci.tar > "$RUNS/task-archive-wrong.txt" 2>&1; echo "  $(tail -1 "$RUNS/task-archive-wrong.txt")"
check task_archive_not_in_tasks_images_refused grep -q -- "--task-archive manifest digest sha256:4de0c490.* != compose image digest sha256:" "$RUNS/task-archive-wrong.txt"
run --compose test/app-compose-peer.json --out "$RUNS/task-archive-notasks" --no-attest --task-archive ../oci/task-test.oci.tar > "$RUNS/task-archive-notasks.txt" 2>&1; echo "  $(tail -1 "$RUNS/task-archive-notasks.txt")"
check task_archive_needs_tasks_compose grep -q -- "--task-archive needs a compose with tasks" "$RUNS/task-archive-notasks.txt"

OUT=$RUNS/boot
run --compose test/app-compose.json --out "$OUT" --no-attest 2> "$RUNS/runner.log"; echo "runner exit=$?"
MOUT=$RUNS/meter
run --compose test/app-compose-meter.json --out "$MOUT" --no-attest --dev-test-anchor "$RUNS/fake/ca.der" 2> "$RUNS/meter.log"; echo "meter runner exit=$?"
AOUT=$RUNS/abalone
run --compose test/app-compose-abalone.json --out "$AOUT" --no-attest --quote-helper verify/provider_quote.mjs --node $NODE 2> "$RUNS/abalone.log"; echo "abalone runner exit=$?"
run --compose test/app-compose-peer.json --out "$RUNS/peer" --no-attest --oci-archive ../oci/peer-arm64.oci.tar 2> "$RUNS/peer.log"; echo "peer runner exit=$?"
run --compose test/app-compose-tunnel.json --out "$RUNS/tunnel" --no-attest --oci-archive ../oci/peer-arm64.oci.tar 2> "$RUNS/tunnel.log"; echo "tunnel runner exit=$?"
run --compose test/app-compose-key.json --out "$RUNS/key1" --no-attest 2> "$RUNS/key1.log"
run --compose test/app-compose-tasks.json --out "$RUNS/tasks" --no-attest --oci-archive ../oci/peer-arm64.oci.tar --task-archive ../oci/task-test.oci.tar --dev-task-boot-delay-ms 3000 2> "$RUNS/tasks.log"; echo "tasks runner exit=$?"
run --compose test/app-compose-tasks.json --out "$RUNS/delay-attest" --attest --dev-task-boot-delay-ms 3000 > "$RUNS/delay-attest.txt" 2>&1
check task_boot_delay_refused_with_attest grep -q "dev-task-boot-delay-ms is DEV-ONLY and refused with --attest" "$RUNS/delay-attest.txt"
run --compose test/app-compose-tasks-real.json --out "$RUNS/tasks-real" --no-attest --oci-archive ../oci/peer-arm64.oci.tar --task-archive ../oci/task.oci.tar 2> "$RUNS/tasks-real.log"; echo "real task runner exit=$?"
for v in vol1:volume vol2:volume vol3:volume2; do
  run --compose "test/app-compose-${v#*:}.json" --out "$RUNS/${v%%:*}" --no-attest --oci-archive ../oci/peer-arm64.oci.tar 2> "$RUNS/${v%%:*}.log"
done
# The genesis app's image moved to the pre-app path volumes/dev/<HV>/: the next boot of HV must find it there.
mkdir -p "$VB/volumes/dev/$HV"; mv "$VB/volumes/$(appdir "dev|$HV")/ledger.ext4" "$VB/volumes/dev/$HV/"
run --compose test/app-compose-volume.json --out "$RUNS/vol-legacy" --no-attest 2> "$RUNS/vol-legacy.log"
# An upgrade (build HV2) admitted to the genesis app "dev|HV" finds the same pre-app image and the same keys.
PORT=8799 RUN_APP="dev|$HV" run --compose test/app-compose-volume2.json --out "$RUNS/vol-upgrade" --no-attest 2> "$RUNS/vol-upgrade.log"
# App "shared": build HVH holds the volume 20 s; a concurrent boot of HV2 in the same app is refused at the lock;
# afterwards HV2 boots and reads what HVH wrote.
PORT=8798 RUN_APP=shared run --compose test/app-compose-volume-hold.json --out "$RUNS/app-hold" --no-attest 2> "$RUNS/app-hold.log" & HOLD=$!
for i in $(seq 60); do grep -qx "== holding" "$RUNS/app-hold/guest_stdout.txt" 2>/dev/null && break; sleep 1; done
PORT=8798 RUN_APP=shared run --compose test/app-compose-volume2.json --out "$RUNS/app-locked" --no-attest > "$RUNS/app-locked.txt" 2>&1; echo "app-locked exit=$?  $(tail -1 "$RUNS/app-locked.txt")"
check app_hold_still_running kill -0 $HOLD
wait $HOLD; echo "app-hold exit=$?"
PORT=8798 RUN_APP=shared run --compose test/app-compose-volume2.json --out "$RUNS/app-next" --no-attest 2> "$RUNS/app-next.log"
# Durability: the guest syncs 3 lines (sync -f) and writes a 4th without, then the runner (found by its own --out) is SIGKILLed.
run --compose test/app-compose-volume-durable.json --out "$RUNS/durable" --no-attest 2> "$RUNS/durable.log" & DUR=$!
for i in $(seq 60); do grep -qx "== SYNCED" "$RUNS/durable/guest_stdout.txt" 2>/dev/null && break; sleep 1; done
pkill -KILL -f -- "--out $RUNS/durable "; wait $DUR; echo "durable runner exit=$? (SIGKILL is 137)"
/opt/homebrew/opt/e2fsprogs/sbin/debugfs -R "cat /durable.txt" "$VB/volumes/$(appdir "dev|$HD")/ledger.ext4" > "$RUNS/durable-image.txt" 2> "$RUNS/durable-debugfs.log"
kill $KPID; wait $KPID 2>/dev/null
$PY kms/kms.py --state "$KMS_STATE" --dev-unattested "${DEVALLOW[@]}" "${KEYS[@]}" > "$RUNS/kms-restarted.log" 2>&1 & KPID=$!
sleep 1
run --compose test/app-compose-key.json --out "$RUNS/key2" --no-attest 2> "$RUNS/key2.log"
run --compose test/app-compose-key2.json --out "$RUNS/key3" --no-attest 2> "$RUNS/key3.log"
kill $KPID $APID $NPID $SPID $UPID $FPID $TPID $RPID
VERIFY=(--dev-unattested); BINDING=(clientData.bin)
source test/boot_checks.sh
check key_absent_from_attested_kms_bodies sh -c "! grep -r -q -a -F '$KEY' '$RUNS/kms-attested-bodies'"
check key_absent_from_kms_logs sh -c "! grep -q -a -F '$KEY' '$RUNS'/kms*.log"
check attest_dev_type sh -c "$(declare -f sec); OUT='$OUT'; sec attest | head -1 | grep -q '\"type\":\"dev\"'"
sec attest | head -1 | $PY -c "import base64,json,sys; d=json.load(sys.stdin); print(base64.b64decode(d['assertClientData']).decode())" > "$RUNS/assert-client-data.txt"
check attest_dev_assert_client_data_canonical test "$(cat "$RUNS/assert-client-data.txt")" = "{\"compose_hash\":\"$H\",\"data\":\"abalone-attest/1|peerA|peerB|n1\",\"domain\":\"mac-compose-assert/1\"}"

echo "---- key boots"; cat "$RUNS/key1/guest_stdout.txt" "$RUNS/key2/guest_stdout.txt" "$RUNS/key3/guest_stdout.txt"
kk() { awk -v s="== $2" '$0==s{getline; print; exit}' "$RUNS/$1/guest_stdout.txt"; }
check key_boot_value_is_64_hex sh -c "echo '$(kk key1 peer-id)' | grep -Eq '^\{\"key\":\"[0-9a-f]{64}\"\}$'"
check key_same_compose_same_key_across_boots_and_kms_restart test "$(kk key1 peer-id)" = "$(kk key2 peer-id)"
check key_boot_path_differs test "$(kk key1 peer-id)" != "$(kk key1 other)"
check key_changed_compose_differs test "$(kk key1 peer-id)" != "$(kk key3 peer-id)"

echo "---- volume boots"; for v in vol1 vol2 vol3; do echo "-- $v"; cat "$RUNS/$v.log" "$RUNS/$v/guest_stdout.txt"; done
vsec() { awk -v s="== $2" '$0==s{f=1;next} /^== /{f=0} f' "$RUNS/$1/guest_stdout.txt"; }
check volume_created_on_first_boot_under_app_dir grep -q "created volume ledger at $VB/volumes/$(appdir "dev|$HV")/ledger.ext4\$" "$RUNS/vol1.log"
check volume_marker_is_compose_hash test "$(vsec vol1 marker)" = "$HV"
check volume_marker_other_compose test "$(vsec vol3 marker)" = "$HV2"
check volume_mounted_ext4 sh -c "$(declare -f vsec); RUNS='$RUNS'; vsec vol1 mount | grep -q '^/dev/vd[a-z] /abalone-ledger ext4 rw'"
check volume_first_boot_empty test "$(vsec vol1 entries | tr '\n' ' ')" = ".abalone-persistent lost+found "
check volume_written_token_is_16_hex sh -c "$(declare -f vsec); RUNS='$RUNS'; vsec vol1 wrote | grep -Eqx '[0-9a-f]{16}'"
check volume_second_boot_reads_first same "$(vsec vol2 before)" "$(vsec vol1 wrote)"
check volume_second_boot_reuses_image sh -c "! grep -q 'created volume' '$RUNS/vol2.log'"
check volume_other_compose_fresh sh -c "$(declare -f vsec); RUNS='$RUNS'; test \"\$(vsec vol3 entries | tr '\\n' ' ')\" = '.abalone-persistent lost+found ' && grep -q 'created volume ledger at $VB/volumes/$(appdir "dev|$HV2")/ledger.ext4' '$RUNS/vol3.log'"
check genesis_app_key_matches_pre_app_derivation test "$(kk vol1 peer-id)" = "{\"key\":\"$($PY test/derive_key.py "$KMS_STATE/master.key" dev "$HV" peer-id)\"}"

echo "---- app boots"; for v in vol-legacy vol-upgrade app-hold app-locked app-next; do echo "-- $v"; cat "$RUNS/$v.log" "$RUNS/$v.txt" "$RUNS/$v/guest_stdout.txt" 2>/dev/null; done
check legacy_volume_path_used_for_genesis_app grep -q "volumes of app dev|$HV at $VB/volumes/dev/$HV\$" "$RUNS/vol-legacy.log"
check legacy_volume_not_recreated sh -c "! grep -q 'created volume' '$RUNS/vol-legacy.log'"
check legacy_volume_holds_earlier_tokens test "$(vsec vol-legacy before | tr '\n' ' ')" = "$(vsec vol1 wrote) $(vsec vol2 wrote) "
check genesis_upgrade_uses_legacy_path grep -q "volumes of app dev|$HV at $VB/volumes/dev/$HV\$" "$RUNS/vol-upgrade.log"
check genesis_upgrade_reads_ledger test "$(vsec vol-upgrade before | tr '\n' ' ')" = "$(vsec vol1 wrote) $(vsec vol2 wrote) $(vsec vol-legacy wrote) "
check genesis_upgrade_keeps_key same "$(kk vol-upgrade peer-id)" "$(kk vol1 peer-id)"
check app_volume_lock_refuses_second_boot grep -q "volume ledger at $VB/volumes/$(appdir shared)/ledger.ext4 is locked (Resource temporarily unavailable): another runner of app shared is live; refusing to boot" "$RUNS/app-locked.txt"
check app_locked_boot_started_no_guest test ! -e "$RUNS/app-locked/guest_stdout.txt"
check app_hold_kept_running sh -c "$(declare -f vsec); RUNS='$RUNS'; test \"\$(vsec app-hold held)\" = ok && grep -q 'exitCode: 0' '$RUNS/app-hold/guest_exit.txt'"
check app_two_builds_same_volume same "$(vsec app-next before)" "$(vsec app-hold wrote)"
check app_second_build_reuses_image sh -c "! grep -q 'created volume' '$RUNS/app-next.log'"
check app_two_builds_same_key same "$(kk app-hold peer-id)" "$(kk app-next peer-id)"
check app_key_matches_app_derivation test "$(kk app-next peer-id)" = "{\"key\":\"$($PY test/derive_key.py "$KMS_STATE/master.key" --app shared peer-id)\"}"
check app_same_build_other_app_differs sh -c "test -n '$(kk vol3 peer-id)' && test '$(kk app-next peer-id)' != '$(kk vol3 peer-id)'"
check app_marker_is_own_compose test "$(vsec app-next marker)" = "$HV2"
echo "---- durability"; cat "$RUNS/durable.log" "$RUNS/durable/guest_stdout.txt" "$RUNS/durable-image.txt"
check durable_runner_sigkilled grep -qx "== SYNCED" "$RUNS/durable/guest_stdout.txt"
check durable_runner_died sh -c "! test -e '$RUNS/durable/guest_exit.txt'"
check durable_synced_lines_survive_sigkill test "$(head -3 "$RUNS/durable-image.txt" | tr '\n' ' ')" = "synced-1 synced-2 synced-3 "
check clientdata_names_app grep -q '"app":"shared"' "$RUNS/app-next/clientData.bin"
check clientdata_names_genesis_app grep -qF "\"app\":\"dev|$H\"" "$OUT/clientData.bin"

echo "---- peer boot (OCI archive)"; cat "$RUNS/peer.log" "$RUNS/peer/guest_stdout.txt"
check oci_archive_loaded grep -q "loaded peer-arm64.oci.tar" "$RUNS/peer.log"
check oci_peer_prints_node_version grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+' "$RUNS/peer/guest_stdout.txt"

echo "---- abalone-interface boot"; cat "$RUNS/abalone.log" "$AOUT/guest_stdout.txt" "$AOUT/receipts.jsonl"
asec() { awk -v s="== $1" '$0==s{f=1;next} /^== /{f=0} f' "$AOUT/guest_stdout.txt"; }
ac() { local name=$1; shift; check "$name" sh -c "$(declare -f asec); AOUT='$AOUT'; $*"; }
ac provider_quote_404_before_fetch "asec quote_before_fetch | grep -q 'status=404'"
ac provider_quote_redpill_200 "asec redpill | grep -q 'status=200'"
ac provider_quote_redpill_again_200 "asec redpill_again | grep -q 'status=200'"
ac large_body_20_identical "test \$(asec large_body_repeat | wc -l) = 1 && asec large_body_repeat | grep -q '^ *20 '"
check provider_quote_fetched_once test "$(grep -c 'provider quote verified: redpill .* for api.redpill.ai' "$RUNS/abalone.log")" = 1
QSHA=$(grep -o 'provider_quote_sha256[^,]*' "$AOUT/receipts.jsonl" | tr -d '\\":' | sed 's/provider_quote_sha256//' | sort -u)
echo "receipt provider_quote_sha256: $QSHA"
check provider_quote_in_both_receipts test "$(grep -c "provider_quote_sha256.....$QSHA" "$AOUT/receipts.jsonl")" = 2
check provider_quote_endpoint_bytes_match_receipt test "$(asec redpill_quote_bytes | cut -c1-64)" = "$QSHA"
check provider_quote_saved_report_matches_receipt test "$($PY -c "import base64,hashlib,json,sys; print(hashlib.sha256(base64.b64decode(json.load(open(sys.argv[1]))['report_b64'])).hexdigest())" "$AOUT/provider-quote-${QSHA:0:16}.json")" = "$QSHA"
check provider_quote_spki_pin_matched_redpill sh -c "! grep -q 'attested SPKI pin refused api.redpill.ai' '$RUNS/abalone.log'"
ac provider_quote_spki_mismatch_502 "asec spki_mismatch | grep -q 'status=502'"
check provider_quote_spki_mismatch_logged grep -q "attested SPKI pin refused openrouter.phala.com: leaf spki_sha256 [0-9a-f]\{64\} not in \[\"1989293e" "$RUNS/abalone.log"
ac provider_quote_wrong_compose_502 "asec wrong_compose | grep -q 'status=502' && asec wrong_compose | grep -q 'is not in the accepted list'"
ac provider_quote_failed_endpoint_502 "asec wrong_compose_quote | grep -q 'status=502'"
ac provider_quote_replayed_nonce_502 "asec replayed | grep -q 'status=502' && asec replayed | grep -q 'report_data'"
check provider_quote_replayed_no_upstream_contact sh -c "! grep -q '/v1/replayed' '$RUNS/fake.log'"
# The helper reads the Base block (pinned TLS to mainnet.base.org) before it fetches NEAR's report, so a 401 means the RPC leg passed.
ac provider_quote_nearai_bad_key_502 "asec nearai_bad_key | grep -q 'status=502' && asec nearai_bad_key | grep -q 'HTTP 401'"
check key_absent_from_abalone_out sh -c "! grep -r -q -a -F '$KEY' '$AOUT' '$RUNS/abalone.log'"
$PY kms/verify_receipts.py "$AOUT" --compose test/app-compose-abalone.json --dev-unattested > "$RUNS/verify-abalone.txt" 2>&1
check abalone_receipts_verify grep -q '"receipts": 2' "$RUNS/verify-abalone.txt"

echo "---- CONNECT boot (abalone peer image)"; cat "$RUNS/tunnel.log" "$RUNS/tunnel/guest_stdout.txt"
tsec() { awk -v s="== $1" '$0==s{f=1;next} /^== /{f=0} f' "$RUNS/tunnel/guest_stdout.txt"; }
tc() { local name=$1; shift; check "$name" sh -c "$(declare -f tsec); RUNS='$RUNS'; $*"; }
tc connect_tunnel_200 "tsec tunnel_ok | grep -q '^connect: HTTP/1.1 200 Connection Established'"
tc connect_tunnel_bytes "tsec tunnel_ok | grep -qF '$(cat "$RUNS/tunnel-www/tunnel.txt")'"
check connect_server_saw_tunnel grep -q "GET /tunnel.txt HTTP/1.0" "$RUNS/tunnel-server.log"
tc connect_unlisted_port_403 "tsec tunnel_refused_port | grep -q '^connect: HTTP/1.1 403'"
tc connect_unlisted_host_403 "tsec tunnel_refused_host | grep -q '^connect: HTTP/1.1 403'"
check connect_refusals_logged test "$(grep -c 'refused CONNECT' "$RUNS/tunnel.log")" = 2

echo "---- metering boot (DEV-ONLY test anchor)"; cat "$RUNS/meter.log" "$MOUT/guest_stdout.txt" "$MOUT/receipts.jsonl"
msec() { awk -v s="== $1" '$0==s{f=1;next} /^== /{f=0} f' "$MOUT/guest_stdout.txt"; }
for s in anthropic:200 openai:200 no_usage:502 settled:200 exhausted:402 sse:200; do
  check "meter_${s%%:*}_${s##*:}" sh -c "$(declare -f msec); MOUT='$MOUT'; msec ${s%%:*} | grep -q 'status=${s##*:}'"
done
check meter_no_usage_reason sh -c "$(declare -f msec); MOUT='$MOUT'; msec no_usage | grep -q 'no usage; reservation of 100 stays charged'"
check meter_settled_budget_620 sh -c "$(declare -f msec); MOUT='$MOUT'; msec exhausted | grep -q 'max_tokens 621 exceeds remaining per-boot budget 620'"
check meter_receipts_charge_usage test "$(grep -o 'tokens_charged[^,]*' "$MOUT/receipts.jsonl" | tr -d '\\"' | tr '\n' ' ')" = "tokens_charged:65 tokens_charged:150 tokens_charged:65 tokens_charged:150 "
$PY kms/verify_receipts.py "$MOUT" --compose test/app-compose-meter.json --dev-unattested | tee "$RUNS/verify-meter.txt"
check meter_receipts_verify grep -q '"receipts": 4' "$RUNS/verify-meter.txt"
check verify_receipts_names_app grep -qF "\"app\": \"dev|$HM\"" "$RUNS/verify-meter.txt"
check key_absent_from_meter_out sh -c "! grep -r -q -a -F '$KEY' '$MOUT' '$RUNS/meter.log' '$RUNS/fake.log'"
TOUT=$RUNS/tasks; TLOG=$RUNS/tasks.log; EARLY_BOOTING=1
source test/task_checks.sh
# The real abalone task image (bin/task-guest.mjs): init, finish, collect.
TOUT=$RUNS/tasks-real; TLOG=$RUNS/tasks-real.log
echo "---- real task image boot"; cat "$TLOG"; grep -v -x '[A-Za-z0-9+/=]\{200,\}' "$TOUT/guest_stdout.txt" | cut -c1-300
tk real_task_infer_frame "tsk real_frames | grep -q '^{\"t\":\"infer\",\"id\":1,'"
tk real_task_outputs_frame "tsk real_frames | grep -q '^{\"t\":\"outputs\",\"files\":\[{\"path\":\"patch.diff\"'"
tk real_task_exited_0 "tsk real_exited | grep -q '\"exit_code\":0,\"reason\":null,.*\"state\":\"exited\"'"
mkdir -p "$RUNS/real-collect"; tsk real_collect_b64 | base64 -d | tar -xf - -C "$RUNS/real-collect"
check real_task_check_ran_on_inputs sh -c "grep -q '^git version' '$RUNS/real-collect/out/test.log' && grep -qx 'hello from inputs' '$RUNS/real-collect/out/test.log'"
check real_task_finish_json test "$(cat "$RUNS/real-collect/out/finish.json")" = '{"reason":"runner test"}'
$PY kms/verify_receipts.py "$RUNS/real-collect" --task --peer-compose test/app-compose-tasks-real.json "${VERIFY[@]}" > "$RUNS/verify-real.txt" 2>&1; cat "$RUNS/verify-real.txt"
check real_task_receipts_verify grep -q '"ok": true' "$RUNS/verify-real.txt"
for c in $(sed -n 's/.*running (\(task-[0-9a-f]*-[0-9]*\),.*/\1/p' "$TLOG") $(cat "$TOUT/container_id.txt"); do rm -rf "../store/containers/$c"; done
for d in meter abalone peer tunnel key1 key2 key3 vol1 vol2 vol3 vol-legacy vol-upgrade app-hold app-next durable; do rm -rf "../store/containers/$(cat "$RUNS/$d/container_id.txt")"; done
cat "$RUNS/kms.log" "$RUNS/kms-restarted.log"
echo "FAILED=$FAILED"; exit $FAILED
