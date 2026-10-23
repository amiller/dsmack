#!/bin/bash
# PRODUCER-side golden check (SWIFT04 repair3). Compiles the REAL pure contract
# sources + a tiny shim + the main.swift driver and runs them against the committed
# vectors. Needs a Swift toolchain with CryptoKit (a Mac / the Mini). It does NOT
# build the mar app and links NO Darwin frameworks or the native archive, so it is
# safe to run anywhere a Swift+CryptoKit toolchain exists. No signing, no VM, no
# network. repair3: the driver is main.swift (repair2 named it GoldenMain.swift with
# top-level statements in a non-main file, which swiftc refuses to compile).
set -euo pipefail
cd "$(dirname "$0")"
HERE="$PWD"
MAR="$HERE/../../app-src/Sources/mar"
VECTORS="$HERE/../vectors"

if ! command -v swiftc >/dev/null 2>&1; then
  echo "SKIP: no swiftc on this host (run on the Mini / a macOS Swift toolchain)." >&2
  exit 3
fi

OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT
# The three REAL pure sources (no Darwin import) + the shim + the driver.
swiftc -O \
  "$MAR/CanonicalJSON.swift" \
  "$MAR/AssertionEvidence.swift" \
  "$MAR/RunResultEnvelopeV3.swift" \
  "$HERE/GoldenShim.swift" \
  "$HERE/main.swift" \
  -o "$OUT/golden"
"$OUT/golden" "$VECTORS"
