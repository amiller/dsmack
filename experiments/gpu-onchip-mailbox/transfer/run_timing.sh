#!/usr/bin/env bash
# Phase C — timing channel (transfer).
#
# 1. Measure the system-scope spin iteration time T_iter (sys_poll probe,
#    2^22 iterations, no CPU interaction; dev_poll control).
# 2. Sweep delta in {1,2,4,8} x T_iter and alphabet in {2,4,16}:
#      cal   — round-robin symbols, builds count->symbol calibration
#      rng   — >=10^4 symbols from the public fixed-seed PRNG, SER measured
#              offline by nearest-mean decoding of the GPU spin counts
#    plus a deterministic-delay control (constD) per delta at alphabet 16
#    midpoint (10^4 reps, count distribution recorded).
# One GPU invocation at a time; every invocation under wd.sh 30 s; all spin
# loops iteration-capped; abort on any nonzero exit or cap hit (host 87).
#
# usage: run_timing.sh   (OUT dir: $ROOT, default ./out)
set -uo pipefail

EXP=$(cd "$(dirname "$0")" && pwd)
ROOT=${ROOT:-$EXP/out}
LOG=$ROOT/logs/phaseC
BUILDD=$ROOT/build
mkdir -p "$LOG" "$BUILDD"
cd "$LOG"

D0_NS=10000
NSYM_RNG=10000               # >=10^4 measured symbols per config
TIMELINE=$LOG/timeline.txt
: > "$TIMELINE"
mark() {
  python3 -c 'import time; print(int(time.time()*1000))' | tr -d '\n' >> "$TIMELINE"
  echo " $1" >> "$TIMELINE"
}

xcrun metal -c "$EXP/transfer.metal" -o "$BUILDD/transfer.air" 2> build_metal.log
xcrun metallib "$BUILDD/transfer.air" -o "$BUILDD/transfer.metallib" 2>> build_metal.log
[ -f "$BUILDD/transfer.metallib" ] || { echo "FATAL: metallib build failed"; exit 2; }
xcrun clang++ -std=c++17 -O2 -fobjc-arc -framework Metal -framework Foundation \
  "$EXP/timing_host.mm" -o "$BUILDD/timing_host" 2> build_timing.log
echo "timing_host build exit: $?"
[ -x "$BUILDD/timing_host" ] || exit 2

echo "===== [phaseC] preflight process snapshot ====="
ps aux | grep -i -E "mailbox_host|hwtest|transfer_host|transfer2_host|timing_host|stream_gpu" \
  | grep -v grep > ps_research_hits.txt || true
echo "research-hit lines: $(wc -l < ps_research_hits.txt)"
if [ -s ps_research_hits.txt ]; then
  echo "FATAL: another GPU experiment is running"; cat ps_research_hits.txt; exit 87
fi

echo "===== [phaseC] T_iter probes ====="
"$EXP/../common/wd.sh" 30 "$BUILDD/timing_host" "$BUILDD/transfer.metallib" \
  sys_poll p 0 0 0 1 4194304 500 25 "$LOG/titer_sys.csv" titer_sys \
  > titer_sys.json 2> titer_sys.err
st=$?; cat titer_sys.json; tail -1 titer_sys.err || true
echo "sys_poll exit: $st"; [ "$st" -eq 0 ] || exit 87
"$EXP/../common/wd.sh" 30 "$BUILDD/timing_host" "$BUILDD/transfer.metallib" \
  dev_poll p 0 0 0 1 4194304 501 25 "$LOG/titer_dev.csv" titer_dev \
  > titer_dev.json 2> titer_dev.err
st=$?; cat titer_dev.json; tail -1 titer_dev.err || true
echo "dev_poll exit: $st"; [ "$st" -eq 0 ] || exit 87

# The host prints one POLL line of plain JSON; extract t_iter_ns from it.
TITER=$(sed -n 's/.*"t_iter_ns":\([0-9.]*\).*/\1/p' titer_sys.json | head -1)
echo "T_iter(system) = $TITER ns"
[ -n "$TITER" ] || { echo "FATAL: no T_iter"; exit 87; }

run_cfg() {
  label=$1 mode=$2 alpha=$3 delta_x=$4 nsym=$5
  delta=$(python3 - "$TITER" "$delta_x" <<'EOF'
import sys
print("%.1f" % (float(sys.argv[1]) * float(sys.argv[2])))
EOF
)
  mark "${label}_start"
  "$EXP/../common/wd.sh" 30 "$BUILDD/timing_host" "$BUILDD/transfer.metallib" \
    timing_system "$mode" "$D0_NS" "$delta" "$alpha" "$nsym" 4194304 \
    $((900 + RANDOM % 100)) 20 "$LOG/${label}.csv" "$label" \
    > "${label}.json" 2> "${label}.err"
  st=$?
  tail -2 "${label}.err" || true
  mark "${label}_end"
  echo "[phaseC:$label] mode=$mode A=$alpha delta=${delta}ns exit $st"
  if [ "$st" -ne 0 ]; then
    echo "[phaseC:$label] ABORT at $(date)" | tee -a "$LOG/ABORT.txt"
    exit 87
  fi
}

for dx in 1 2 4 8; do
  for alpha in 2 4 16; do
    run_cfg "cal_dx${dx}_a${alpha}"  c "$alpha" "$dx" $((alpha * 400))
    run_cfg "rng_dx${dx}_a${alpha}"  r "$alpha" "$dx" "$NSYM_RNG"
  done
  run_cfg "constD_dx${dx}" D 16 "$dx" "$NSYM_RNG"
done

echo "===== [phaseC] complete ====="
exit 0
