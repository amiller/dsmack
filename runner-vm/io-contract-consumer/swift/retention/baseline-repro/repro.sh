#!/bin/bash
# repro.sh — FIRST, standalone reproduction of APP-SCOPE-02-R2-OUT-PATH-MAPPING against the
# EXACT R2 immutable baseline. Hash-verifies the baseline RetentionV3.swift (7fe5ab0d...),
# then compiles it with a Fail shim + ReproMain in ONE swiftc module (Swift language mode 5,
# matching the app manifest) and runs it. The baseline MUST incorrectly SUCCEED on all four
# injections; repro exits 0 iff the vulnerability was reproduced. No signing, no VM, no
# network (pure Foundation/CryptoKit/Darwin).
set -euo pipefail
cd "$(dirname "$0")"
HERE="$PWD"
# The pristine R2 baseline source lives in the RejectedR2Retention control module.
BASELINE="$HERE/../controls/Sources/RejectedR2Retention/RetentionV3.swift"
REJECTEDR2_PIN="7fe5ab0d3f456769d63a690add9ad36fd279e87be13a415e1fc8afe922fc92be"

if ! command -v swiftc >/dev/null 2>&1; then
  echo "SKIP: no swiftc on this host (run on the Mini / a macOS Swift toolchain)." >&2
  exit 3
fi
sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
GOT="$(sha "$BASELINE")"
echo "baseline RetentionV3.swift sha256=$GOT pin=$REJECTEDR2_PIN"
[ "$GOT" = "$REJECTEDR2_PIN" ] || { echo "refusing: baseline is not the R2 immutable source"; exit 2; }

rm -rf .build && mkdir -p .build/src
# swiftc requires the file holding top-level code to be named main.swift when building an
# executable from multiple files, so stage ReproMain.swift as main.swift (byte-identical).
cp "$BASELINE"      .build/src/RetentionV3.swift
cp ReproShim.swift  .build/src/ReproShim.swift
cp ReproMain.swift  .build/src/main.swift
swiftc -swift-version 5 -O \
  .build/src/RetentionV3.swift .build/src/ReproShim.swift .build/src/main.swift \
  -o .build/baseline-repro 2>&1 | tee .build/compile.log
set +e
.build/baseline-repro | tee baseline-repro.log
rc=${PIPESTATUS[0]}
set -e
echo "baseline-repro exit=$rc (0 == vulnerability reproduced on all four injections)"
exit "$rc"
