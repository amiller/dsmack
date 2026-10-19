#!/usr/bin/env bash
# Phase B — bounded round-trip mailbox, 10^4 trips per configuration.
# One GPU invocation at a time; each host process (one dispatch) is bounded by
# common/wd.sh at 30 s + 1 s grace. Any nonzero child exit aborts everything.
set -uo pipefail

EXP=$(cd "$(dirname "$0")" && pwd)
ROOT=${ROOT:-$EXP/out}
LOG=$ROOT/logs/phaseB
mkdir -p "$LOG/lat" "$LOG"
cd "$LOG"

SPIN_CAP=4194304   # 2^22 iterations max per trip wait (finite, no while(1))
TRIPS=1000         # trips per dispatch chunk; 10 chunks => 10^4 per config

echo "===== [phaseB] build ====="
{
  date; uname -a; sw_vers
  xcrun metal --version 2>&1 | head -2
  xcrun clang --version 2>&1 | head -2
} > env.txt 2>&1
cat env.txt

xcrun metal -S -emit-llvm -c "$EXP/mailbox.metal" -o mailbox.ll \
  > build_metal.log 2>&1; echo "mailbox emit-llvm exit: $?"
xcrun metal -c "$EXP/mailbox.metal" -o mailbox.air \
  >> build_metal.log 2>&1; echo "mailbox compile exit: $?"
xcrun metallib mailbox.air -o mailbox.metallib >> build_metal.log 2>&1
echo "metallib exit: $? sha256: $(shasum -a 256 mailbox.metallib | cut -d' ' -f1)"

xcrun clang++ -std=c++17 -O2 -fobjc-arc \
  -framework Metal -framework Foundation \
  "$EXP/mailbox_host.mm" -o mailbox_host 2> build_host.log
echo "host build exit: $?"
if [ ! -x ./mailbox_host ]; then echo "FATAL: host build failed"; exit 2; fi

echo "===== [phaseB] preflight process snapshot ====="
ps aux > ps_snapshot.txt 2>&1
echo "processes: $(wc -l < ps_snapshot.txt)"
# Read-only note of any other obviously active research binaries.
grep -i -E "mailbox|fence|hwtest|metallib_replacer|compiler_explorer" \
  ps_snapshot.txt | grep -v grep > ps_research_hits.txt || true
echo "research-hit lines: $(wc -l < ps_research_hits.txt)"

# run_config <name> <kernel> <mode> <respond_seconds|0> <seedbase> <chunks> <trips>
run_config() {
  name=$1 kernel=$2 mode=$3 respond=$4 seedbase=$5 chunks=$6 trips=$7
  echo "===== [phaseB] config $name (kernel=$kernel cpu=$mode) ====="
  mkdir -p "$LOG/$name"
  for c in $(seq 0 $((chunks - 1))); do
    "$EXP/../common/wd.sh" 30 ./mailbox_host mailbox.metallib "$kernel" "$mode" \
      1 "$trips" "$SPIN_CAP" "$((seedbase + c))" "$respond" 1 \
      "$LOG/lat/${name}_${c}.csv" "${name}_c${c}" \
      > "$LOG/$name/chunk_${c}.json" 2> "$LOG/$name/chunk_${c}.err"
    st=$?
    tail -1 "$LOG/$name/chunk_${c}.err" || true
    echo "[phaseB:$name] chunk $c exit $st"
    if [ "$st" -ne 0 ]; then
      echo "[phaseB:$name] ABORT: chunk $c exit $st at $(date)" | \
        tee -a "$LOG/ABORT.txt"
      return 87
    fi
  done
}

# Smoke: one dispatch, 10 trips, system scope, default CPU mode.
run_config smoke mailbox_system default 10 999 1 10 || { echo "smoke failed"; exit 87; }

# 1. System scope, CPU default seq_cst store/barrier (as MLX).
run_config sys_default mailbox_system default 0 100 10 "$TRIPS" || exit 87
# 2. System scope, CPU store + DSB SY.
run_config sys_dsbsy mailbox_system dsbsy 0 200 10 "$TRIPS" || exit 87
# 3. Negative control: device scope, CPU default.
run_config dev_default mailbox_device default 5 300 10 "$TRIPS" || exit 87
# 4. Control sharpening: device scope, CPU store + DSB SY.
run_config dev_dsbsy mailbox_device dsbsy 5 400 10 "$TRIPS" || exit 87

echo "===== [phaseB] quick latency summary ====="
for f in "$LOG"/lat/sys_default_0.csv "$LOG"/lat/sys_dsbsy_0.csv \
         "$LOG"/lat/dev_default_0.csv "$LOG"/lat/dev_dsbsy_0.csv; do
  [ -f "$f" ] || continue
  python3 - "$f" <<'EOF'
import sys
v = [int(x) for x in open(sys.argv[1]).read().split()[1:]]
if v:
    v.sort(); n = len(v)
    print("%s n=%d min=%d p10=%d p50=%d p90=%d p99=%d max=%d" % (
        sys.argv[1], n, v[0], v[n//10], v[n//2], v[9*n//10], v[99*n//100], v[-1]))
EOF
done
echo "[phaseB] complete"
exit 0
