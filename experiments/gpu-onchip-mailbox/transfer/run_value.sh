#!/usr/bin/env bash
# Value channel: per exchange the CPU writes a fresh 32-byte seed into the
# system-scope mailbox and the GPU folds it into a register hash. Two 1 s runs
# with different public seeds must each match the CPU's own recomputation and
# must differ from each other. Build and check lines are taken from
# ../dcs-bandwidth-calibration/run_phase2.sh.
set -uo pipefail

EXP=$(cd "$(dirname "$0")" && pwd)
ROOT=${ROOT:-$EXP/out}
LOG=$ROOT/logs/value
mkdir -p "$LOG"
cd "$LOG"

xcrun metal -c "$EXP/transfer.metal" -o transfer.air 2> build_metal.log
echo "metal compile exit: $?"
xcrun metallib transfer.air -o transfer.metallib 2>> build_metal.log
echo "metallib exit: $?"
xcrun clang++ -std=c++17 -O2 -fobjc-arc -framework Metal -framework Foundation \
  "$EXP/transfer2_host.mm" -o transfer2_host 2> build_host.log
echo "host build exit: $?"
[ -x ./transfer2_host ] && [ -f transfer.metallib ] || { echo "FATAL: build failed"; exit 2; }

for s in 1000 2000; do
  "$EXP/../common/wd.sh" 30 ./transfer2_host transfer.metallib vc_system fresh 1 \
    1100000 4194304 $s 3 917 lcg_s$s > lcg_seed$s.json 2> lcg_seed$s.err
  echo "seed $s exit: $?"
done

python3 - <<'PY' | tee lcg_verify.txt
import json, sys
c = [json.load(open(f'lcg_seed{s}.json'))['chunks_arr'][0] for s in (1000, 2000)]
for s, x in zip((1000, 2000), c):
    print(f"seed {s}: final={x['gpu_final_hash']} ok={x['final_hash_ok']} trips={x['trips_done']} "
          f"wrong_hash={x['cpu_wrong_hash']} cks_fail={x['kernel_cks_fail']} rate={x['trips_per_s']:.0f}/s")
ok = all(x['final_hash_ok'] == 1 and x['cpu_wrong_hash'] == 0 and x['kernel_cks_fail'] == 0 for x in c) \
     and c[0]['gpu_final_hash'] != c[1]['gpu_final_hash']
print("PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
PY
