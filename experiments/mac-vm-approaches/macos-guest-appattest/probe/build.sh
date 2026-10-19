#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
app="$PWD/build/VmAttestProbe.app"
rm -rf build; mkdir -p "$app/Contents/MacOS"
xcrun swiftc -sdk "$(xcrun --show-sdk-path)" -target arm64-apple-macos27.0 -framework DeviceCheck -framework IOKit Probe.swift -o "$app/Contents/MacOS/probe"
cp "$app/Contents/MacOS/probe" build/probe-adhoc && codesign -s - -f build/probe-adhoc
cp "${SIGNING_DIR:?directory holding provisioning profiles and probe-entitlements.plist}/embedded.provisionprofile" "$app/Contents/embedded.provisionprofile"
cp "${SIGNING_DIR:?directory holding provisioning profiles and probe-entitlements.plist}/probe-entitlements.plist" build/entitlements.plist
cat > "$app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>dev.dsmack.provider</string>
<key>CFBundleExecutable</key><string>probe</string>
<key>CFBundleName</key><string>VmAttestProbe</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleVersion</key><string>1</string>
<key>LSUIElement</key><true/>
<key>LSMinimumSystemVersion</key><string>27.0</string>
</dict></plist>
PLIST
codesign --force --options runtime --sign "${SIGN_IDENTITY:?Apple Development identity}" \
  --keychain "${KEYCHAIN:?signing keychain}" \
  --entitlements build/entitlements.plist --generate-entitlement-der --timestamp=none "$app"
codesign --verify --strict "$app"
