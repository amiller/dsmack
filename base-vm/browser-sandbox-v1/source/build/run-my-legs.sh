#!/bin/bash
# Driver: run both reproducibility legs concurrently inside the builder.
# Owned copy of dstack-smoke-finish/source/build/run-my-legs.sh (prior lane,
# read-only). Delta for THIS lane: no kernel phase — this lane starts from the
# PROVEN ec83a3fc kernel bytes (provenance preserved; the new content is the
# rootfs runner join), so each leg = rootfs build + assembly.
set -u
run_leg() {
  L=$1
  bash /w/source/build/build_leg_rootfs.sh "$L" > "/w/build/legs/$L-rootfs.log" 2>&1 &&
  bash /w/source/build/assemble_leg.sh "$L" > "/w/build/legs/$L-assemble.log" 2>&1
  echo "$L rc=$?" > "/w/build/legs/$L.rc"
}
mkdir -p /w/build/legs
run_leg legA & P1=$!
run_leg legB & P2=$!
wait $P1; wait $P2
cat /w/build/legs/legA.rc /w/build/legs/legB.rc
echo ALL-LEGS-DONE
