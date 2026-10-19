#!/usr/bin/env bash
# Phase C — persistent mailbox dispatch lifetime: 1 s, 10 s, 60 s, then 600 s.
# Single invocations; stopping at the first timeout/error. Each step responds
# for (T - margin) seconds, margin = min(5, T/2), so the GPU dispatch stays
# inside the 600 s bound; the host watchdog is duration + 20 s.
# usage: run_phaseC.sh <cpu_mode: default|dsbsy>   (run run_phaseB.sh first)
set -uo pipefail

EXP=$(cd "$(dirname "$0")" && pwd)
ROOT=${ROOT:-$EXP/out}
MODE=${1:-default}
LOG=$ROOT/logs/phaseC
mkdir -p "$LOG"
cd "$ROOT/logs/phaseB"   # reuse the phaseB build outputs

if [ ! -x ./mailbox_host ]; then echo "FATAL: run phaseB first"; exit 2; fi

SPIN_CAP=4194304
TRIPS=1000000000   # effectively unlimited; the CPU stop word ends the kernel

for T in 1 10 60 600; do
  # margin: half the step below 10 s, else 10 s — keeps the GPU dispatch
  # inside the nominal step and well inside the 600 s allowance.
  margin=$(awk -v t="$T" 'BEGIN { print (t <= 10) ? t / 2 : 10 }')
  respond=$(awk -v t="$T" -v m="$margin" 'BEGIN { print t - m }')
  wdbound=$(awk -v t="$T" 'BEGIN { printf "%d", t + 15 }')
  echo "===== [phaseC] T=${T}s respond=${respond}s watchdog=${wdbound}s mode=$MODE ====="
  date +%s > "$LOG/step_${T}_start_epoch.txt"
  "$EXP/../common/wd.sh" "$wdbound" ./mailbox_host mailbox.metallib \
    mailbox_system "$MODE" 1 "$TRIPS" "$SPIN_CAP" 700 "$respond" 0 \
    "$LOG/step_${T}_rate.csv" "phaseC_${T}s" \
    > "$LOG/step_${T}.json" 2> "$LOG/step_${T}.err"
  st=$?
  date +%s > "$LOG/step_${T}_end_epoch.txt"
  tail -2 "$LOG/step_${T}.err" || true
  echo "[phaseC] step T=${T}s exit $st"
  python3 - "$LOG/step_${T}.json" "$T" <<'EOF'
import json, sys
try:
    j = json.load(open(sys.argv[1]))
except Exception as e:
    print("json parse failed:", e); sys.exit(0)
tot = j["totals"]; ch = j["chunks_arr"][0]
print("  kernel_status=%s trips=%s cap_hits=%s cb_errors=%s gpu_dispatch=%.3fs wall=%.3fs" % (
    ch["kernel_status_name"], tot["trips_done_kernel"], tot["cap_hits"],
    tot["command_buffer_errors"], ch["gpu_dispatch_s"], ch["wall_s"]))
if ch["cb_errored"]:
    print("  CB ERROR code=%s name=%s desc=%s" % (
        ch["cb_error_code"], ch["cb_error_name"], ch["cb_error_desc"]))
EOF
  if [ "$st" -ne 0 ]; then
    echo "[phaseC] STOP: step T=${T}s exit $st at $(date)" | tee -a "$LOG/STOP.txt"
    exit 87
  fi
  if grep -q '"cb_errored": 1' "$LOG/step_${T}.json"; then
    echo "[phaseC] STOP: command buffer error at T=${T}s at $(date)" | \
      tee -a "$LOG/STOP.txt"
    exit 3
  fi
  sleep 2
done
echo "[phaseC] complete"
exit 0
