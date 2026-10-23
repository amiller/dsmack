#!/bin/bash
# RETENTION FAULT-INJECTION harness runner (SWIFT04 repair3). Compiles the REAL
# RetentionV3.swift (the production durable-retention mechanism) + a tiny shim
# (Fail / sha256File) + the fault-injection driver, and runs it. It links NO
# Darwin frameworks beyond Foundation/CryptoKit, no native archive and no HVF, so
# it is safe on any macOS Swift toolchain (the Mini). No signing, no VM, no network.
set -euo pipefail
cd "$(dirname "$0")"
HERE="$PWD"
MAR="$HERE/../../../app-src/Sources/mar"

if ! command -v swiftc >/dev/null 2>&1; then
  echo "SKIP: no swiftc on this host (run on the Mini / a macOS Swift toolchain)." >&2
  exit 3
fi

OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT
swiftc -O \
  "$MAR/RetentionV3.swift" \
  "$MAR/DeferredCleanup.swift" \
  "$HERE/RetentionFaultShim.swift" \
  "$HERE/main.swift" \
  -o "$OUT/retention-fault"
"$OUT/retention-fault"
