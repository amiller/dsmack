# Workload checks shared by run_tests.sh (ad-hoc) and attested.sh (signed). Sourced, not run.
# Needs: check(), OUT, RUNS, KEY, PY, VERIFY (verify_receipts.py mode args), BINDING (boot-binding files in OUT),
# KMSREC (the boot KMS's --record dir), KMS_STATE (its --state dir), KEY_CDHASH (cdhash hex, or "dev").
cat "$RUNS/runner.log"; echo "---- guest stdout"; cat "$OUT/guest_stdout.txt"; echo "---- end guest stdout"
sec() { awk -v s="== $1" '$0==s{f=1;next} /^== /{f=0} f' "$OUT/guest_stdout.txt"; }
check guest_exit_0 grep -q "exitCode: 0" "$OUT/guest_exit.txt"
check only_lo_in_sys_class_net test "$(sec net | head -1)" = lo
check no_eth_in_ip_addr sh -c "awk '/^== net/,/^== direct_ip/' '$OUT/guest_stdout.txt' | grep -q ' lo' && ! awk '/^== net/,/^== direct_ip/' '$OUT/guest_stdout.txt' | grep -q eth"
check direct_ip_fetch_fails sh -c "awk '/^== direct_ip\$/{f=1;next} f' '$OUT/guest_stdout.txt' | grep -m1 '^exit=' | grep -qv 'exit=0'"
check direct_dns_fetch_fails sh -c "awk '/^== direct_dns\$/{f=1;next} f' '$OUT/guest_stdout.txt' | grep -m1 '^exit=' | grep -qv 'exit=0'"
check allowed_200 sh -c "$(declare -f sec); OUT='$OUT'; sec allowed | grep -q 'status=200'"
check injected_key_reached_upstream sh -c "$(declare -f sec); OUT='$OUT'; sec allowed | grep -q '\"Authorization\": \"Bearer \[REDACTED-API-KEY\]\"'"
check guest_authorization_stripped sh -c "$(declare -f sec); OUT='$OUT'; sec allowed | grep -q 'status=200' && ! sec allowed | grep -q -e GUEST-SECRET -e guest-xkey"
for s in xkey:200 not_allowlisted_host:403 wrong_method:403 wrong_path:403 dot_segments:403 metered_no_usage:502 metered_over_budget:402 metered_no_max_tokens:400 redirect_not_followed:302 pin_fail:502; do
  check "${s%%:*}_${s##*:}" sh -c "$(declare -f sec); OUT='$OUT'; sec ${s%%:*} | grep -q 'status=${s##*:}'"
done
check injects_x_api_key sh -c "$(declare -f sec); OUT='$OUT'; sec xkey | grep -q '\"X-Api-Key\": \"\[REDACTED-API-KEY\]\"'"
check metered_without_usage_refused sh -c "$(declare -f sec); OUT='$OUT'; sec metered_no_usage | grep -q 'metered upstream 200 response has no usage'"
check no_usage_keeps_reservation sh -c "$(declare -f sec); OUT='$OUT'; sec metered_over_budget | grep -q 'remaining per-boot budget 900'"
check keepalive_two_answers sh -c "$(declare -f sec); OUT='$OUT'; test \$(sec keepalive | grep -c 'status=200') -eq 2"
check keepalive_connection_reused sh -c "$(declare -f sec); OUT='$OUT'; sec keepalive | grep -qE 'Re-?using'"
check pin_refusal_logged grep -q "TLS pin refused example.com" "$RUNS/runner.log"
check request_cap_429 test "$(sec request_cap | grep -c 'status=429')" = 2
gkey() { sec "$1" | head -1 | sed -n 's/^{"key":"\([0-9a-f]\{64\}\)"}$/\1/p'; }
echo "keys: peer-id $(gkey key_a) / $(gkey key_a2), other $(gkey key_b)"
check get_key_is_64_hex test -n "$(gkey key_a)"
check get_key_same_path_same_key test "$(gkey key_a)" = "$(gkey key_a2)"
check get_key_other_path_differs test "$(gkey key_a)" != "$(gkey key_b)"
check get_key_matches_kms_derivation test "$(gkey key_a)" = "$($PY test/derive_key.py "$KMS_STATE/master.key" "$KEY_CDHASH" "$(shasum -a 256 test/app-compose.json | cut -c1-64)" peer-id)"
check kms_master_key_mode_0600 test "$(stat -f %Lp "$KMS_STATE/master.key")" = 600

CID=$(cat "$OUT/container_id.txt"); ROOTFS=../store/containers/$CID/rootfs.ext4
ls -ls "$ROOTFS" "$OUT/initfs.ext4"
echo "grep key in rootfs: $(grep -c -a -F "$KEY" "$ROOTFS")  marker in rootfs: $(grep -c -a -F 'REDACTED-API-KEY' "$ROOTFS")"
check rootfs_grep_positive_control grep -q -a -F "Bearer [REDACTED-API-KEY]" "$ROOTFS"
check key_absent_from_rootfs sh -c "! grep -q -a -F '$KEY' '$ROOTFS'"
check key_absent_from_initfs sh -c "! grep -q -a -F '$KEY' '$OUT/initfs.ext4'"
BODY=$KMSREC/$(shasum -a 256 "$OUT/clientData.bin" | cut -c1-16)-200.json
echo "kms /release body for this boot: $(cat "$BODY")"
check kms_release_body_recorded grep -q '"sealed"' "$BODY"
check key_absent_from_kms_release_bodies sh -c "! grep -r -q -a -F '$KEY' '$KMSREC'"
$PY test/parcel_wrong_key.py "$BODY" "$OUT/clientData.bin" > "$RUNS/wrong-key.txt" 2>&1; echo "  $(tail -1 "$RUNS/wrong-key.txt")"
check parcel_wrong_key_fails grep -q "^wrong key: InvalidTag" "$RUNS/wrong-key.txt"
check key_absent_from_out_dir_and_logs sh -c "! grep -r -q -a -F '$KEY' '$OUT' '$RUNS/runner.log'"

$PY kms/verify_receipts.py "$OUT" --compose test/app-compose.json "${VERIFY[@]}" | tee "$RUNS/verify.txt"
check receipts_verify grep -q '"receipts": 7' "$RUNS/verify.txt"
mkdir -p "$RUNS/tamper-sig" "$RUNS/tamper-drop"
for f in "${BINDING[@]}"; do cp "$OUT/$f" "$RUNS/tamper-sig/"; cp "$OUT/$f" "$RUNS/tamper-drop/"; done
sed '2s/\\"status\\":200/\\"status\\":201/' "$OUT/receipts.jsonl" > "$RUNS/tamper-sig/receipts.jsonl"
sed "3d" "$OUT/receipts.jsonl" > "$RUNS/tamper-drop/receipts.jsonl"
check tamper_changed_a_byte sh -c "! cmp -s '$OUT/receipts.jsonl' '$RUNS/tamper-sig/receipts.jsonl'"
$PY kms/verify_receipts.py "$RUNS/tamper-sig" --compose test/app-compose.json "${VERIFY[@]}" > "$RUNS/tamper-sig.txt" 2>&1; echo "  $(tail -1 "$RUNS/tamper-sig.txt")"
check tampered_receipt_fails grep -q "bad_signature seq=2" "$RUNS/tamper-sig.txt"
$PY kms/verify_receipts.py "$RUNS/tamper-drop" --compose test/app-compose.json "${VERIFY[@]}" > "$RUNS/tamper-drop.txt" 2>&1; echo "  $(tail -1 "$RUNS/tamper-drop.txt")"
check dropped_receipt_fails grep -q "seq_gap" "$RUNS/tamper-drop.txt"
[ -n "$CID" ] && rm -rf "../store/containers/$CID"
