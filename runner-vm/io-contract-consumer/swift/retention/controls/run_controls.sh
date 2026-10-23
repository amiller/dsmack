#!/bin/bash
# run_controls.sh — build + run the APP-RETENTION-CONTROLS package (SwiftPM, three
# retention modules + AppCleanup + driver). Refreshes the RepairedRetention and AppCleanup
# sources from the canonical app-src tree and HASH-VERIFIES all three retention copies:
#   * repaired copy  == app-src RetentionV3.swift (R3 single source of truth) == REPAIRED_PIN
#   * accepted copy  == reviewed original baseline b100ea54...
#   * rejectedR2 copy== R2 immutable baseline being repaired 7fe5ab0d...
# so the controls provably drive the EXACT accepted, rejected-R2 and repaired
# implementations (not hand-copied approximations). No signing, no VM, no network
# (pure Foundation/CryptoKit/Darwin; no external SPM deps).
set -euo pipefail
cd "$(dirname "$0")"
HERE="$PWD"
MAR="$HERE/../../../../app-src/Sources/mar"
ACCEPTED_PIN="b100ea540804490e64984bdc5f16b2392cd182c1a30415a7d361f58cdd1fe248"
REJECTEDR2_PIN="7fe5ab0d3f456769d63a690add9ad36fd279e87be13a415e1fc8afe922fc92be"
REPAIRED_PIN="ff4b5760e8066094cb76fdf4b82b2cb34c601d97993b2502db47ae918f9e83b1"

if ! command -v swift >/dev/null 2>&1; then
  echo "SKIP: no swift on this host (run on the Mini / a macOS Swift toolchain)." >&2
  exit 3
fi
sha() { shasum -a 256 "$1" | cut -d' ' -f1; }

# Refresh repaired + verbatim cleanup from the single source of truth, then verify all three.
cp "$MAR/RetentionV3.swift"    Sources/RepairedRetention/RetentionV3.swift
cp "$MAR/DeferredCleanup.swift" Sources/AppCleanup/DeferredCleanup.swift
REP_APP="$(sha "$MAR/RetentionV3.swift")"
REP_PKG="$(sha Sources/RepairedRetention/RetentionV3.swift)"
ACC_PKG="$(sha Sources/AcceptedRetention/RetentionV3.swift)"
R2_PKG="$(sha Sources/RejectedR2Retention/RetentionV3.swift)"
echo "repaired   app-src=$REP_APP  pkg=$REP_PKG  pin=$REPAIRED_PIN"
echo "accepted   pkg=$ACC_PKG  pin=$ACCEPTED_PIN"
echo "rejectedR2 pkg=$R2_PKG  pin=$REJECTEDR2_PIN"
[ "$REP_APP" = "$REP_PKG" ]     || { echo "refusing: repaired copy drift"; exit 2; }
[ "$REP_APP" = "$REPAIRED_PIN" ] || { echo "refusing: repaired copy is not the pinned R3 source"; exit 2; }
[ "$ACC_PKG" = "$ACCEPTED_PIN" ] || { echo "refusing: accepted copy is not the reviewed baseline"; exit 2; }
[ "$R2_PKG" = "$REJECTEDR2_PIN" ] || { echo "refusing: rejectedR2 copy is not the R2 immutable baseline"; exit 2; }

rm -rf .build
swift build -c release --disable-automatic-resolution 2>&1 | tee build-controls.log
set +e
.build/release/controls | tee controls-run.log
rc=${PIPESTATUS[0]}
set -e
# Count self-check: individual PASS/FAIL lines must equal the emitted ASSERTION-COUNT.
emitted="$(grep -Ec '^  (PASS|FAIL) \[#' controls-run.log)"
declared="$(sed -n 's/^ASSERTION-COUNT=\([0-9]*\).*/\1/p' controls-run.log | head -1)"
echo "assertion lines emitted=$emitted declared=$declared"
[ "$emitted" = "$declared" ] || { echo "refusing: assertion count mismatch (emitted $emitted != declared $declared)"; exit 4; }
echo "controls exit=$rc"
exit "$rc"
