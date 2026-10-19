#!/bin/bash
# Ad-hoc build: hardened runtime + com.apple.security.virtualization only. Cannot App Attest (use --no-attest).
set -euo pipefail
cd "$(dirname "$0")"
swift build -c release
mkdir -p bin && cp .build/release/runner bin/runner
codesign --force --sign - --options runtime --entitlements entitlements.plist bin/runner
codesign -d --verbose=4 bin/runner 2>&1 | grep -E "CDHash=|flags="
otool -L bin/runner
