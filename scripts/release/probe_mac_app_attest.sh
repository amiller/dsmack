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
# Separate ad hoc bundle context; no borrowed team identity or signing secret.
# isSupported=false here still does not settle Developer ID provisioning.
app="$out/Probe.app"
mkdir -p "$app/Contents/MacOS"
cp "$out/capability" "$app/Contents/MacOS/Probe"
cat > "$app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>dev.dsmack.synthetic-app-attest-probe</string>
<key>CFBundleExecutable</key><string>Probe</string>
<key>CFBundlePackageType</key><string>APPL</string>
</dict></plist>
PLIST
cat > "$out/entitlements.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>com.apple.developer.devicecheck.app-attest-opt-in</key>
<array><string>CDhash</string></array>
</dict></plist>
PLIST
codesign --force --options runtime --sign - --entitlements "$out/entitlements.plist" "$app"
codesign --verify --strict "$app"
printf '%s\n' '{"context":"ad_hoc_bundle","genuineProvisioning":false}'
"$app/Contents/MacOS/Probe" --attest "$out/ad-hoc-evidence"
