# Task-guest checks shared by run_tests.sh (ad-hoc) and attested.sh (signed). Sourced, not run.
# Needs: check(), RUNS, PY, TOUT (out dir of an app-compose-tasks.json boot), TLOG (its runner log), VERIFY (verify_receipts.py mode args).
echo "---- tasks boot"; cat "$TLOG"; grep -v -x '[A-Za-z0-9+/=]\{200,\}' "$TOUT/guest_stdout.txt"
tsk() { awk -v s="== $1" '$0==s{f=1;next} /^== /{f=0} f' "$TOUT/guest_stdout.txt"; }
tk() { local name=$1; shift; check "$name" sh -c "$(declare -f tsk); TOUT='$TOUT'; $*"; }
T1=$(printf task1 | shasum -a 256 | cut -c1-32); T9=$(printf task9 | shasum -a 256 | cut -c1-32)
tk task_start_booting "tsk start | grep -q '^status=200 .*\"state\":\"booting\"'"
tk task_start_same_compose_same_answer "test -n \"\$(tsk start)\" && test \"\$(tsk start)\" = \"\$(tsk start_again)\""
check task_start_same_compose_one_vm test "$(grep -c "task $T1 running" "$TLOG")" = 1
tk task_start_other_compose_409 "tsk start_other_compose | grep -q '^status=409 .*was started with compose'"
tk task_image_not_admitted_403 "tsk start_image_not_admitted | grep -q '^status=403 .*is not in tasks.images'"
tk task_nonempty_egress_403 "tsk start_egress | grep -q '^status=403 .*task egress must be empty'"
tk task_unknown_resource_403 "tsk start_unknown_resource | grep -q '^status=403 .*task must be {\"resource\"'"
tk task_other_route_keeps_1mib_limit "tsk stop_body_over_1mib | grep -q '^status=413 .*body over 1 MiB'"
tk task_silent_connection_closed_runner_survives "test \"\$(tsk silent_then_write)\" = 'true 200'"
check task_silent_connection_close_logged grep -q "closed a guest connection that sent no request in 2 s" "$TLOG"
tk task_running "tsk running | grep -q '\"state\":\"running\"'"
tk task_attach_200 "tsk attach | grep -q '^HTTP/1.1 200'"
tk task_second_attach_409 "tsk attach_second | grep -q '^HTTP/1.1 409'"
tk task_output_before_attach_delivered "test \"\$(tsk ready_buffered)\" = true"
tk task_echo_round_trip "test \"\$(tsk echo)\" = true"
tk task_reattach_200 "tsk reattach | grep -q '^HTTP/1.1 200'"
tk task_detached_output_delivered_on_reattach "test \"\$(tsk later_delivered)\" = true"
tk task_drop_count_reported "tsk dropped | grep -q '\"dropped_bytes\":1048577'"
tk task_reattach_gets_newest_4mib "test \"\$(tsk flood_bytes)\" = '4194304 true true'"
tk task_last_output_before_close "test \"\$(tsk done)\" = true"
tk task_attach_closed_on_exit "test \"\$(tsk closed_on_exit)\" = true"
tk task_exited_0 "tsk exited | grep -q '\"exit_code\":0,\"reason\":null,.*\"state\":\"exited\"'"
tk task_collect_byte_identical "tsk collect | awk '{exit !(\$1 == 200 && \$2 == 200 && \$3 == \$4)}'"
tk task_attach_after_exit_409 "tsk attach_after_exit | grep -q '^HTTP/1.1 409'"
tk task_early_attach_200 "tsk early_attach | grep -q '^HTTP/1.1 200'"
tk task_early_reattach_200 "tsk early_reattach | grep -q '^HTTP/1.1 200'"
# Only run_tests.sh holds the boot (--dev-task-boot-delay-ms), so only there is "booting" certain.
[ -n "${EARLY_BOOTING:-}" ] && tk task_early_attaches_while_booting "tsk early_attach | grep -q ' booting\$' && tsk early_reattach | grep -q ' booting\$'"
tk task_early_stdin_delivered "test \"\$(tsk early_echo)\" = true"
tk task_early_exited_0 "tsk early_done | grep -qx true && tsk early_exited | grep -q '\"exit_code\":0,\"reason\":null,.*\"state\":\"exited\"'"
tk task_max_concurrent_429 "tsk start_over_max | grep -q '^status=429 .*max_concurrent 2'"
tk task_peer_traffic_during_task_boots "tsk overlap | grep -Eq '^[0-9]+ 0 both_running'"
echo "  driver retries after runner-closed connections: $(tsk retries)"
tk task_delete_running_409 "tsk delete_running | grep -q '^status=409'"
tk task_collect_running_409 "tsk collect_running | grep -q '^status=409'"
tk task_stop_reason_stop "tsk t2_stopped | grep -q '\"reason\":\"stop\",.*\"state\":\"stopped\"'"
tk task_stop_idempotent "tsk stop_t2_again | grep -q '^status=200 .*\"reason\":\"stop\",.*\"state\":\"stopped\"'"
tk task_time_cap "tsk t5_time_cap | grep -q '\"reason\":\"time_cap\",.*\"state\":\"stopped\"'"
tk task_delete_200 "tsk delete_t1 | grep -q '^status=200 .*\"deleted\":true'"
tk task_status_after_delete_404 "tsk status_deleted | grep -q '^status=404'"
check task_runner_exit_stops_running grep -q "task $T9 stopped .*(runner_exit)" "$TLOG"
tk task_driver_finished "test \"\$(tsk end)\" = ok"

TC=$RUNS/task-collect; rm -rf "$TC" "$TC-t5"; mkdir -p "$TC" "$TC-t5"
tsk collect_b64 | base64 -d > "$TC.tar"; tar -xf "$TC.tar" -C "$TC"
tsk collect5_b64 | base64 -d > "$TC-t5.tar"; tar -xf "$TC-t5.tar" -C "$TC-t5"
tar -tvf "$TC.tar"
check task_collect_has_guest_files sh -c "cd '$TC/guest' && ls app-compose.json attest.json clientData.bin receipts.jsonl"
check task_no_network_interface test "$(cat "$TC/out/net.txt")" = lo
check task_inputs_at_in test "$(cat "$TC/out/in-copy.txt")" = "hello from inputs"
check task_in_read_only grep -q "Read-only file system" "$TC/out/in-write.txt"
check task_out_long_path test "$(cat "$TC"/out/deep/d*/e*/f.txt)" = long
check task_out_exec_bit test -x "$TC/out/run.sh"
check task_boot_domain grep -q '"domain":"mac-compose-task-boot/1"' "$TC/guest/clientData.bin"
$PY kms/verify_receipts.py "$TC" --task --peer-compose test/app-compose-tasks.json "${VERIFY[@]}" > "$RUNS/verify-task.txt" 2>&1; cat "$RUNS/verify-task.txt"
check task_receipts_verify grep -q '"ok": true' "$RUNS/verify-task.txt"
check task_receipt_events $PY -c "import json,sys; d=json.load(open(sys.argv[1])); sys.exit(d['events'] != ['task-start'] + ['attach', 'detach'] * 3 + ['exit'] or d['exit']['exit_code'] != 0 or d['exit']['reason'] is not None)" "$RUNS/verify-task.txt"
check task_receipt_inputs_sha256 grep -q "\"inputs_sha256\": \"$(tsk inputs_sha256)\"" "$RUNS/verify-task.txt"
$PY kms/verify_receipts.py "$TC-t5" --task --peer-compose test/app-compose-tasks.json "${VERIFY[@]}" > "$RUNS/verify-task-t5.txt" 2>&1; cat "$RUNS/verify-task-t5.txt"
check task_time_cap_receipt $PY -c "import json,sys; d=json.load(open(sys.argv[1])); sys.exit(d['exit']['reason'] != 'time_cap')" "$RUNS/verify-task-t5.txt"
cp -R "$TC" "$TC-tamper"; echo tampered > "$TC-tamper/out/result.json"
$PY kms/verify_receipts.py "$TC-tamper" --task --peer-compose test/app-compose-tasks.json "${VERIFY[@]}" > "$RUNS/verify-task-tamper.txt" 2>&1; echo "  $(tail -1 "$RUNS/verify-task-tamper.txt")"
check task_tampered_out_refused grep -q "out_sha256_mismatch" "$RUNS/verify-task-tamper.txt"
cp -R "$TC" "$TC-extra"; echo extra > "$TC-extra/out/extra.txt"
$PY kms/verify_receipts.py "$TC-extra" --task --peer-compose test/app-compose-tasks.json "${VERIFY[@]}" > "$RUNS/verify-task-extra.txt" 2>&1
check task_added_out_file_refused grep -q "out_sha256_mismatch" "$RUNS/verify-task-extra.txt"
cp -R "$TC" "$TC-compose"; sed -i '' 's/abalone-task-/abalone-tasK-/' "$TC-compose/guest/app-compose.json"
$PY kms/verify_receipts.py "$TC-compose" --task --peer-compose test/app-compose-tasks.json "${VERIFY[@]}" > "$RUNS/verify-task-compose.txt" 2>&1
check task_changed_compose_refused grep -q "compose_hash_mismatch" "$RUNS/verify-task-compose.txt"
$PY kms/verify_receipts.py "$TC" --task --peer-compose test/app-compose.json "${VERIFY[@]}" > "$RUNS/verify-task-peer.txt" 2>&1
check task_other_peer_compose_refused grep -q "peer_compose_hash_mismatch" "$RUNS/verify-task-peer.txt"
# An /attest response (domain mac-compose-assert/1, data chosen by the peer) offered as the task binding: refused, whether
# clientData.bin keeps the real task clientData or is replaced by the /attest wrapper.
for v in keep wrap; do
  cp -R "$TC" "$TC-attest-$v"
  $PY - "$TC-attest-$v/guest" $v <<'PYEOF'
import base64, json, sys
from pathlib import Path
g = Path(sys.argv[1]); ev = json.loads((g / 'attest.json').read_text()); peer = json.loads(base64.b64decode(ev['bootClientData']))
wrap = json.dumps({'compose_hash': peer['compose_hash'], 'data': (g / 'clientData.bin').read_text(), 'domain': 'mac-compose-assert/1'}, sort_keys=True, separators=(',', ':')).encode()
ev['assertClientData'] = base64.b64encode(wrap).decode()
(g / 'attest.json').write_text(json.dumps(ev, sort_keys=True, separators=(',', ':')))
if sys.argv[2] == 'wrap': (g / 'clientData.bin').write_bytes(wrap)
PYEOF
  $PY kms/verify_receipts.py "$TC-attest-$v" --task --peer-compose test/app-compose-tasks.json "${VERIFY[@]}" > "$RUNS/verify-task-attest-$v.txt" 2>&1; echo "  $(tail -1 "$RUNS/verify-task-attest-$v.txt")"
done
check task_attest_shaped_binding_refused grep -q "task_binding_not_task_boot_domain" "$RUNS/verify-task-attest-keep.txt"
check task_attest_shaped_clientdata_refused grep -q "wrong_boot_domain mac-compose-assert/1" "$RUNS/verify-task-attest-wrap.txt"
mkdir -p "$TC-early"; tsk early_collect_b64 | base64 -d | tar -xf - -C "$TC-early"
$PY kms/verify_receipts.py "$TC-early" --task --peer-compose test/app-compose-tasks.json "${VERIFY[@]}" > "$RUNS/verify-task-early.txt" 2>&1; cat "$RUNS/verify-task-early.txt"
# Held boot: the first attachment closed before the chain existed (no receipts), the second is signed after task-start.
# Signed pass: either that, or both attachments receipted if the chain was already there; the verifier checks the pairing.
check task_early_attach_receipts_after_task_start $PY -c "import json,sys; e=json.load(open(sys.argv[1]))['events']; sys.exit(e != ['task-start', 'attach', 'detach', 'exit'] and (sys.argv[2] or e != ['task-start'] + ['attach', 'detach'] * 2 + ['exit']))" "$RUNS/verify-task-early.txt" "${EARLY_BOOTING:-}"
for c in $(sed -n 's/.*running (\(task-[0-9a-f]*-[0-9]*\),.*/\1/p' "$TLOG") $(cat "$TOUT/container_id.txt"); do rm -rf "../store/containers/$c"; done
