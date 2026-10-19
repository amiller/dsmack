#!/usr/bin/env bash
# Phase 2 — mailbox retest (run only after the phase 1 gate passed).
#
# First verifies the LCG defect fix (words now derived from the high 32 bits
# of the 64-bit state): two 1 s smoke runs with different seeds must produce
# different gpu_final_hash values, each matching the CPU recomputation.
#
# Then 20 blocks; each block runs one window of every condition in a fixed
# randomized order (public seed 20261015, precomputed and embedded):
#   a    system-scope mailbox exchange at full rate (vc_system fresh),
#        1 chunk x 4.5M trips, spin_cap 4194304 (~4.1 s dispatch).
#   b    matched no-exchange control: identical CPU host loop against a
#        malloc'd never-GPU-mapped 128-byte line, seq self-advancing after a
#        917 ns spin, same trip count; concurrent device-scope dev_poll
#        kernel on its own private buffer, spin_cap 22M (~4 s dispatch).
#   c70 / c140  condition b plus the phase 1 injector at 70 / 140 MB/s
#        running concurrently (positive controls).
# Idle windows (n=5) follow blocks 3, 7, 11, 15, 19. Between every window:
# read-flush + 1 s settle. One iomon watch covers the phase (100 ms,
# 15600 samples). Every GPU invocation is wd.sh-bounded to 30 s.
set -uo pipefail

EXP=$(cd "$(dirname "$0")" && pwd)
ROOT=${ROOT:-$EXP/out}
LOG=$ROOT/logs/phase2
mkdir -p "$LOG"
cd "$LOG"

echo "===== [phase2] environment ====="
{
  date; uname -a; sw_vers
  xcrun clang --version 2>&1 | head -1
  xcrun metal --version 2>&1 | head -1
  python3 --version 2>&1
} > env.txt 2>&1
cat env.txt

echo "===== [phase2] preflight: no research process from another run ====="
ps aux | grep -E "mailbox_host|transfer_host|transfer2_host|timing_host|iomon|inject|stream_cpu|hwtestbed" \
  | grep -v grep > ps_preflight.txt || true
if [ -s ps_preflight.txt ]; then
  echo "FATAL: another research process is running"; cat ps_preflight.txt; exit 87
fi
echo "preflight clean"

echo "===== [phase2] build ====="
xcrun clang -O2 "$EXP/inject.c" -o inject 2> build_inject.log
echo "inject build exit: $?"
xcrun clang -O2 -fobjc-arc -framework IOKit -framework Foundation \
  "$EXP/iomon.m" -o iomon -lIOReport 2> build_iomon.log
echo "iomon build exit: $?"
xcrun metal -c "$EXP/../transfer/transfer.metal" -o transfer.air 2> build_metal.log
echo "metal compile exit: $?"
xcrun metallib transfer.air -o transfer.metallib 2>> build_metal.log
echo "metallib exit: $?"
xcrun clang++ -std=c++17 -O2 -fobjc-arc -framework Metal -framework Foundation \
  "$EXP/../transfer/transfer2_host.mm" -o transfer2_host 2> build_host.log
echo "host build exit: $?"
for t in inject iomon transfer2_host; do
  [ -x "./$t" ] || { echo "FATAL: $t missing"; exit 2; }
done
[ -f transfer.metallib ] || { echo "FATAL: metallib missing"; exit 2; }

TRIPS=4500000
SPIN_VC=4194304
SPIN_DEV=22000000
PERIOD_NS=917
RESPOND_S=12

echo "===== [phase2] LCG defect fix verification (two 1 s smoke runs) ====="
"$EXP/../common/wd.sh" 30 ./transfer2_host transfer.metallib vc_system fresh 1 \
  1100000 $SPIN_VC 1000 3 $PERIOD_NS lcg_s1000 > lcg_seed1000.json 2> lcg_seed1000.err
rc1=$?
"$EXP/../common/wd.sh" 30 ./transfer2_host transfer.metallib vc_system fresh 1 \
  1100000 $SPIN_VC 2000 3 $PERIOD_NS lcg_s2000 > lcg_seed2000.json 2> lcg_seed2000.err
rc2=$?
echo "smoke exits: $rc1 $rc2"
SUMMARY=$(python3 - <<'PY'
import json
out = []
for tag in ('lcg_seed1000', 'lcg_seed2000'):
    try:
        d = json.load(open(tag + '.json'))
        c = d['chunks_arr'][0]
        out.append('%s final=%s ok=%s trips=%s' %
                   (tag, c['gpu_final_hash'], c['final_hash_ok'], c['trips_done']))
    except Exception as e:
        out.append('%s PARSE_FAIL %s' % (tag, e))
print(' ; '.join(out))
PY
)
echo "$SUMMARY" | tee lcg_verify.txt
H1=$(python3 -c "import json;print(json.load(open('lcg_seed1000.json'))['chunks_arr'][0]['gpu_final_hash'])" 2>/dev/null || echo "")
H2=$(python3 -c "import json;print(json.load(open('lcg_seed2000.json'))['chunks_arr'][0]['gpu_final_hash'])" 2>/dev/null || echo "")
OK1=$(python3 -c "import json;print(json.load(open('lcg_seed1000.json'))['chunks_arr'][0]['final_hash_ok'])" 2>/dev/null || echo "")
OK2=$(python3 -c "import json;print(json.load(open('lcg_seed2000.json'))['chunks_arr'][0]['final_hash_ok'])" 2>/dev/null || echo "")
if [ "$rc1" -ne 0 ] || [ "$rc2" -ne 0 ] || [ -z "$H1" ] || [ -z "$H2" ] || \
   [ "$H1" = "$H2" ] || [ "$OK1" != "1" ] || [ "$OK2" != "1" ]; then
  echo "FATAL: LCG verification failed (hashes must differ across seeds and match)"
  exit 87
fi
echo "LCG fix verified: different seeds give different final hashes"

echo "===== [phase2] start the single iomon watch (100 ms x 15600) ====="
./iomon watch "PMP" "DCS BW" 100 15600 dram_watch.csv dram_meta.txt &
MON=$!
echo "sampler pid $MON"
sleep 2

: > timeline.txt
: > rates.log

now_ms() { python3 -c 'import time; print(int(time.time()*1000))'; }

# Fixed randomized orders, precomputed with public seed 20261015:
#   import random
#   random.seed(20261015)
#   conds = ['a','b','c70','c140']
#   for _ in range(20):
#       o = conds[:]; random.shuffle(o); print(','.join(o))
ORDERS="
c70,c140,a,b
b,c70,a,c140
b,c140,c70,a
a,c70,b,c140
c70,a,c140,b
c140,a,c70,b
c140,b,c70,a
c70,c140,b,a
a,b,c140,c70
c140,c70,a,b
c140,b,c70,a
b,c70,a,c140
c70,a,b,c140
b,c140,c70,a
c140,a,c70,b
b,a,c70,c140
c70,b,a,c140
a,c140,c70,b
c70,a,c140,b
c70,c140,a,b
"

nonce=5000
b=0
echo "$(now_ms) phase_start" >> timeline.txt
for order in $ORDERS; do
  echo "$(now_ms) block_start $b" >> timeline.txt
  IFS=',' read -ra CONDS <<< "$order"
  for cond in "${CONDS[@]}"; do
    # read-flush + 1 s settle between every window
    ./inject readflush 512 > /dev/null 2>> flush.log
    rc=$?
    [ $rc -ne 0 ] && echo "READFLUSH_FAIL block=$b rc=$rc" >> rates.log
    sleep 1
    nonce=$((nonce+1))
    case "$cond" in
      a)
        echo "$(now_ms) a_start $b" >> timeline.txt
        "$EXP/../common/wd.sh" 30 ./transfer2_host transfer.metallib vc_system \
          fresh 1 $TRIPS $SPIN_VC $((7000+b)) $RESPOND_S $PERIOD_NS "a_$b" \
          > "a_$b.json" 2> "a_$b.err"
        rc=$?
        echo "$(now_ms) a_end $b" >> timeline.txt
        INFO=$(python3 -c "
import json
try:
    d=json.load(open('a_$b.json')); c=d['chunks_arr'][0]; t=d['totals']
    print('trips_per_s=%.1f wrong_hash=%d final_ok=%d kernel_status=%s cb_err=%d' % (c['trips_per_s'], t['cpu_wrong_hash'], c['final_hash_ok'], c['kernel_status_name'], t['command_buffer_errors']))
except Exception as e: print('PARSE_FAIL')" 2>/dev/null)
        echo "EXCH block=$b cond=a rc=$rc $INFO" >> rates.log
        [ $rc -ne 0 ] && { echo "FATAL: a window failed block=$b"; kill -TERM $MON 2>/dev/null; exit 87; }
        ;;
      b)
        echo "$(now_ms) b_start $b" >> timeline.txt
        "$EXP/../common/wd.sh" 30 ./transfer2_host transfer.metallib dev_poll \
          matched 1 $TRIPS $SPIN_DEV $((8000+b)) $RESPOND_S $PERIOD_NS "b_$b" \
          > "b_$b.json" 2> "b_$b.err"
        rc=$?
        echo "$(now_ms) b_end $b" >> timeline.txt
        INFO=$(python3 -c "
import json
try:
    d=json.load(open('b_$b.json')); c=d['chunks_arr'][0]
    print('exchanges_per_s=%.1f dev_iters=%d dispatch_s=%.3f cb_err=%d' % (c['exchanges_per_s'], d['totals']['dev_poll_iters'], c['gpu_dispatch_s'], d['totals']['command_buffer_errors']))
except Exception as e: print('PARSE_FAIL')" 2>/dev/null)
        echo "EXCH block=$b cond=b rc=$rc $INFO" >> rates.log
        [ $rc -ne 0 ] && { echo "FATAL: b window failed block=$b"; kill -TERM $MON 2>/dev/null; exit 87; }
        ;;
      c70|c140)
        rate=${cond#c}
        echo "$(now_ms) ${cond}_start $b" >> timeline.txt
        ./inject write 1024 5 "$rate" "$nonce" > "inj_${b}_${cond}.log" 2>&1 &
        IPID=$!
        "$EXP/../common/wd.sh" 30 ./transfer2_host transfer.metallib dev_poll \
          matched 1 $TRIPS $SPIN_DEV $((9000+b)) $RESPOND_S $PERIOD_NS "${cond}_$b" \
          > "${cond}_$b.json" 2> "${cond}_$b.err"
        rc=$?
        wait $IPID
        irc=$?
        echo "$(now_ms) ${cond}_end $b" >> timeline.txt
        INFO=$(python3 -c "
import json
try:
    d=json.load(open('${cond}_$b.json')); c=d['chunks_arr'][0]
    print('exchanges_per_s=%.1f dev_iters=%d dispatch_s=%.3f cb_err=%d' % (c['exchanges_per_s'], d['totals']['dev_poll_iters'], c['gpu_dispatch_s'], d['totals']['command_buffer_errors']))
except Exception as e: print('PARSE_FAIL')" 2>/dev/null)
        echo "EXCH block=$b cond=$cond rc=$rc inj_rc=$irc $INFO $(tail -1 inj_${b}_${cond}.log)" >> rates.log
        [ $rc -ne 0 ] && { echo "FATAL: $cond window failed block=$b"; kill -TERM $MON 2>/dev/null; exit 87; }
        ;;
    esac
  done
  echo "$(now_ms) block_end $b" >> timeline.txt
  case $b in
    3|7|11|15|19)
      ./inject readflush 512 > /dev/null 2>> flush.log
      sleep 1
      echo "$(now_ms) idle_start $b" >> timeline.txt
      sleep 5
      echo "$(now_ms) idle_end $b" >> timeline.txt
      echo "IDLE block=$b" >> rates.log
      ;;
  esac
  b=$((b+1))
done
echo "$(now_ms) phase_end" >> timeline.txt

echo "===== [phase2] stop sampler and compress ====="
kill -TERM $MON 2>/dev/null
wait $MON 2>/dev/null
echo "sampler exit: $?"
gzip -f dram_watch.csv
echo "gzip exit: $?"
ls -la dram_watch.csv.gz timeline.txt rates.log
echo "PHASE2_COMPLETE"
touch "$ROOT/DONE"
