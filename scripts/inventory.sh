#!/bin/bash
# Read-only Mac inventory. Keep full device identifiers private.
set -euo pipefail
sw_vers
xcodebuild -version
xcrun --sdk iphoneos --show-sdk-version
security find-identity -v -p codesigning
echo 'Connected devices (contains personal identifiers; do not publish unredacted):'
xcrun devicectl list devices
