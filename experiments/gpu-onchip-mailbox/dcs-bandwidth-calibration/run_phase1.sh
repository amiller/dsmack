#!/usr/bin/env bash
# Phase 1 — counter sensitivity (CPU only, no GPU).
#
# Question: can the unprivileged IOReport PMP "DCS BW" histograms see a
# steady added DRAM write rate of 35..1000 MB/s? 20 blocks; each block runs
# one ~5 s window of every condition (r0 r35 r70 r140 r280 r1000 spin idle)
# in a fixed randomized order (public seed 20261014, precomputed and embedded
# below). Between every window: read-flush (XOR-read a 512 MiB buffer, the
# stream_cpu read shape) then a 1 s settle, so dirty lines from the previous
# window are displaced before the next one starts. One iomon watch covers the
# whole phase (100 ms, 15600 samples >= the phase length). spin = same pacing
# loop and duty cycle at 1000 MB/s line rate into a 32 KiB L1-resident buffer.
#
# Windows are marked in timeline.txt as "<ms> <cond>_start <block>" /
# "<ms> <cond>_end <block>". Achieved injector rates go to rates.log.
# On completion: gzip dram_watch.csv, touch DONE.
set -uo pipefail

EXP=$(cd "$(dirname "$0")" && pwd)
ROOT=${ROOT:-$EXP/out}
LOG=$ROOT/logs/phase1
mkdir -p "$LOG"
cd "$LOG"

echo "===== [phase1] environment ====="
{
  date; uname -a; sw_vers
  xcrun clang --version 2>&1 | head -1
  python3 --version 2>&1
} > env.txt 2>&1
cat env.txt

echo "===== [phase1] preflight: no research process from another run ====="
ps aux | grep -E "mailbox_host|transfer_host|timing_host|iomon|inject|stream_cpu|hwtestbed" \
  | grep -v grep > ps_preflight.txt || true
if [ -s ps_preflight.txt ]; then
  echo "FATAL: another research process is running"; cat ps_preflight.txt; exit 87
fi
echo "preflight clean"

echo "===== [phase1] build ====="
xcrun clang -O2 "$EXP/inject.c" -o inject 2> build_inject.log
echo "inject build exit: $?"
xcrun clang -O2 -fobjc-arc -framework IOKit -framework Foundation \
  "$EXP/iomon.m" -o iomon -lIOReport 2> build_iomon.log
echo "iomon build exit: $?"
[ -x ./inject ] || { echo "FATAL: inject missing"; exit 2; }
[ -x ./iomon ]  || { echo "FATAL: iomon missing"; exit 2; }

echo "===== [phase1] injector smoke (1 s paced + unpaced) ====="
./inject write 1024 1 140 999 > smoke_inject.log 2>&1; echo "smoke paced exit: $?"; cat smoke_inject.log
./inject write 1024 1 0 998 >> smoke_inject.log 2>&1; echo "smoke unpaced exit: $?"; tail -1 smoke_inject.log
./inject spin 1 1000 997 >> smoke_inject.log 2>&1; echo "smoke spin exit: $?"; tail -1 smoke_inject.log
./inject readflush 512 >> smoke_inject.log 2>&1; echo "smoke readflush exit: $?"; tail -1 smoke_inject.log

echo "===== [phase1] start the single iomon watch (100 ms x 15600) ====="
./iomon watch "PMP" "DCS BW" 100 15600 dram_watch.csv dram_meta.txt &
MON=$!
echo "sampler pid $MON"
sleep 2

: > timeline.txt
: > rates.log

now_ms() { python3 -c 'import time; print(int(time.time()*1000))'; }

BLOCKS=20
# Fixed randomized orders, precomputed with public seed 20261014:
#   import random
#   random.seed(20261014)
#   conds = ['r0','r35','r70','r140','r280','r1000','spin','idle']
#   for _ in range(20):
#       o = conds[:]; random.shuffle(o); print(','.join(o))
ORDERS="
r0,spin,r280,idle,r140,r35,r1000,r70
r0,idle,spin,r140,r35,r70,r280,r1000
r280,r1000,idle,r140,r0,r35,r70,spin
r1000,r280,r0,r35,r140,idle,r70,spin
r35,r1000,r70,r280,spin,idle,r0,r140
spin,r280,r35,idle,r0,r140,r70,r1000
r140,spin,r0,r280,idle,r1000,r35,r70
r1000,r280,r140,idle,spin,r35,r0,r70
r280,r35,r140,r1000,idle,r70,spin,r0
idle,r140,r280,r1000,r0,r70,spin,r35
r280,r140,r70,spin,r35,r0,r1000,idle
idle,r0,spin,r1000,r35,r70,r280,r140
idle,r70,r1000,spin,r280,r0,r35,r140
idle,r0,r1000,r35,spin,r280,r70,r140
r1000,idle,r35,r280,r140,spin,r0,r70
r280,idle,r35,r70,spin,r1000,r140,r0
idle,spin,r35,r70,r1000,r140,r0,r280
r0,r280,r35,r1000,r70,idle,r140,spin
r1000,r0,r35,r280,r70,spin,idle,r140
r70,r0,spin,r1000,r35,r280,idle,r140
"

nonce=1000
b=0
echo "$(now_ms) phase_start" >> timeline.txt
for order in $ORDERS; do
  [ "$b" -ge "$BLOCKS" ] && break
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
      idle)
        echo "$(now_ms) idle_start $b" >> timeline.txt
        sleep 5
        echo "$(now_ms) idle_end $b" >> timeline.txt
        echo "IDLE block=$b" >> rates.log
        ;;
      spin)
        echo "$(now_ms) spin_start $b" >> timeline.txt
        ./inject spin 5 1000 "$nonce" > "spin_$b.log" 2>&1
        rc=$?
        echo "$(now_ms) spin_end $b" >> timeline.txt
        echo "SPIN block=$b rc=$rc $(tail -1 spin_$b.log)" >> rates.log
        ;;
      r*)
        rate=${cond#r}
        echo "$(now_ms) ${cond}_start $b" >> timeline.txt
        ./inject write 1024 5 "$rate" "$nonce" > "inj_${b}_${cond}.log" 2>&1
        rc=$?
        echo "$(now_ms) ${cond}_end $b" >> timeline.txt
        echo "INJ block=$b cond=$cond rc=$rc $(tail -1 inj_${b}_${cond}.log)" >> rates.log
        ;;
    esac
  done
  echo "$(now_ms) block_end $b" >> timeline.txt
  b=$((b+1))
done
echo "$(now_ms) phase_end" >> timeline.txt

echo "===== [phase1] stop sampler and compress ====="
kill -TERM $MON 2>/dev/null
wait $MON 2>/dev/null
echo "sampler exit: $?"
gzip -f dram_watch.csv
echo "gzip exit: $?"
ls -la dram_watch.csv.gz timeline.txt rates.log
echo "PHASE1_COMPLETE"
touch "$ROOT/DONE"
