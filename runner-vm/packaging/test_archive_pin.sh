#!/bin/bash
# SWIFT03 repair4 NEGATIVE TEST — an alternate archive cannot be accepted by
# changing EXPECT_ARCHIVE_SHA256 (the rejected repair3 counterexample), and a
# relocated non-identical archive is refused. Runs where the frozen native handoff
# path exists (the Zed /data host); needs cc/ar/nm/sha256sum, NO swift, NO signing.
#
# It (1) fabricates a DIFFERENT static archive that EXPORTS the complete 19-symbol
# v1/v2/v3 set (so repair3's symbol check would pass), (2) shows the BASELINE
# (repair3) build.sh ACCEPTS it when EXPECT_ARCHIVE_SHA256 is set to the fake's
# digest (gate reaches "symbol set verified"), and (3) shows the REPAIR4 build.sh
# REFUSES it — both when the env digest is supplied (non-overridable pin) and when
# ARCHIVE_DIR is relocated to the fake without any env (authoritative-digest
# mismatch).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
R4_BUILD="$HERE/build.sh"
BASELINE_BUILD="${BASELINE_BUILD:-/home/amiller/dsmack-sprints/attested-runner-20261019/joined-sprint/app-compose-20261020/loop40-swift-repair3/candidate/packaging/build.sh}"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
rc_all=0
pass(){ echo "PASS $1"; }
fail(){ echo "FAIL $1"; rc_all=1; }

# ---- (1) fabricate a DIFFERENT archive exporting all 19 required symbols -------
SYMS="dsmack_join_vm_new dsmack_join_run dsmack_join_err_cap_min \
dsmack_ctl_v2_init dsmack_ctl_join_vm_new dsmack_ctl_join_run dsmack_ctl_join_receipt \
dsmack_ctl_join_receipt_cap_min dsmack_ctl_join_abi_version dsmack_ctl_join_err_cap_min \
dsmack_ctl_v3_init dsmack_ctl_join_vm_new_v3 dsmack_ctl_join_run_v3 dsmack_ctl_join_finalize_v3 \
dsmack_ctl_join_receipt_v3 dsmack_ctl_join_result_v3 dsmack_ctl_join_free_v3 \
dsmack_ctl_join_abi_version_v3 dsmack_ctl_join_err_cap_min_v3"
{ for s in $SYMS; do echo "int $s(void){return 0;}"; done; echo "const char* dsmack_fake_marker=\"NOT THE REVIEWED ARCHIVE\";"; } > "$WORK/fake.c"
cc -c "$WORK/fake.c" -o "$WORK/fake.o"
FAKE_DIR="$WORK/fake-archive-dir"; mkdir -p "$FAKE_DIR"
ar rcs "$FAKE_DIR/libdsmack_hvf_returning.a" "$WORK/fake.o"
FAKE_SHA="$(sha256sum "$FAKE_DIR/libdsmack_hvf_returning.a" | cut -d' ' -f1)"
PIN_SHA="$(sed -n 's/.*"archive_sha256"[[:space:]]*:[[:space:]]*"\([0-9a-f]\{64\}\)".*/\1/p' "$HERE/ARCHIVE-PIN.json" | head -1)"
echo "fabricated fake archive sha256=$FAKE_SHA (19 symbols); reviewed pin=$PIN_SHA"
if [ "$FAKE_SHA" = "$PIN_SHA" ]; then fail "fake archive accidentally equals the pin"; exit 1; fi
echo

# A build.sh refuses if build/ already exists and uses sibling ../app-src; run each
# from an isolated dir holding ONLY the build.sh (+ the pin for repair4) so the run
# stops at/just-after the pin gate (the subsequent `cp -R ../app-src` fails fast and
# is irrelevant — we assert only the gate markers).
run_build(){ # $1=tag $2=build.sh $3=extra-copy(pin|"") ; env EXPECT_ARCHIVE_SHA256 + ARCHIVE_DIR inherited
  local d="$WORK/run-$1"; mkdir -p "$d"; cp "$2" "$d/build.sh"
  [ "$3" = "pin" ] && cp "$HERE/ARCHIVE-PIN.json" "$d/ARCHIVE-PIN.json"
  ( cd "$d" && ARCHIVE_DIR="$ARCHIVE_DIR" bash ./build.sh ) >"$d/out.log" 2>&1
  echo $? >"$d/rc"; cat "$d/out.log"
}

echo "---- REPRO: BASELINE repair3 build.sh ACCEPTS the fake archive via EXPECT_ARCHIVE_SHA256 override ----"
export EXPECT_ARCHIVE_SHA256="$FAKE_SHA" ARCHIVE_DIR="$FAKE_DIR"
run_build baseline "$BASELINE_BUILD" "" | sed 's/^/    /'
if grep -q "symbol set verified" "$WORK/run-baseline/out.log"; then
  pass "baseline_gate_accepts_fake_via_env_override (DEFECT reproduced: reached symbol-set/verify past the pin)"
else
  fail "baseline_gate_accepts_fake_via_env_override (expected the fake to pass the pin on baseline)"
fi
echo

echo "---- FIX case 1: REPAIR4 build.sh REFUSES the env digest override (non-overridable pin) ----"
run_build fix-env "$R4_BUILD" "pin" | sed 's/^/    /'
if grep -q "may not replace the reviewed pin" "$WORK/run-fix-env/out.log" && ! grep -q "symbol set verified" "$WORK/run-fix-env/out.log"; then
  pass "repair4_refuses_env_digest_override"
else
  fail "repair4_refuses_env_digest_override"
fi
echo

echo "---- FIX case 2: REPAIR4 build.sh REFUSES a relocated non-identical archive (no env) ----"
unset EXPECT_ARCHIVE_SHA256
run_build fix-reloc "$R4_BUILD" "pin" | sed 's/^/    /'
if grep -q "!= authoritative pin" "$WORK/run-fix-reloc/out.log" && ! grep -q "symbol set verified" "$WORK/run-fix-reloc/out.log"; then
  pass "repair4_refuses_nonidentical_relocation"
else
  fail "repair4_refuses_nonidentical_relocation"
fi
echo

echo "---- FIX case 3: REPAIR4 build.sh ACCEPTS the genuine archive's provenance + authoritative digest ----"
# NOTE: the genuine archive is an arm64 Mach-O staticlib; its 19-symbol check uses
# macOS `nm` and runs on the Mini (see mini-swift03-genuine-symbols.log). GNU nm on
# this Linux host reports "file format not recognized" for Mach-O objects, so HERE
# we assert only the host-verifiable stages: the frozen native handoff + source
# inventory CONTENT pins and the AUTHORITATIVE archive digest all accept the genuine
# archive. (The subsequent symbol/`cp ../app-src` steps are expected to stop this
# isolated run after the digest gate.)
PIN_ARCHIVE_DIR="/data/amiller/dsmack/attested-runner-20261020/loop40-native-nat-repair2/.target-xbuild-final"
export ARCHIVE_DIR="$PIN_ARCHIVE_DIR"
run_build fix-genuine "$R4_BUILD" "pin" | sed 's/^/    /'
if grep -q "native provenance pinned" "$WORK/run-fix-genuine/out.log" \
   && grep -q "archive pinned" "$WORK/run-fix-genuine/out.log"; then
  pass "repair4_accepts_genuine_provenance_and_authoritative_digest"
else
  fail "repair4_accepts_genuine_provenance_and_authoritative_digest"
fi
unset ARCHIVE_DIR
echo
echo "######## SWIFT03 RESULT ########"
[ "$rc_all" -eq 0 ] && echo "SWIFT03 ARCHIVE-PIN NEGATIVE TEST: ALL EXPECTED" || echo "SWIFT03 ARCHIVE-PIN NEGATIVE TEST: UNEXPECTED OUTCOME(S)"
exit $rc_all
