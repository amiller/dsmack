#!/usr/bin/env bash
set -euo pipefail
# No signing secrets, live relay or contract calls. New probe goes in local-data.
root=$(cd "$(dirname "$0")/../.." && pwd)
sw_vers
uname -m
xcodebuild -version
major=$(sw_vers -productVersion | cut -d. -f1)
if (( major < 27 )); then
  printf '%s\n' '{"result":"unsupported_os","macOS27Required":true}'
  exit 0
fi
out="$root/local-data/mac-app-attest-probe"
mkdir -p "$out"
xcrun swiftc -parse-as-library "$root/node/tests/MacAppAttestProbe.swift" -o "$out/capability"
"$out/capability"
