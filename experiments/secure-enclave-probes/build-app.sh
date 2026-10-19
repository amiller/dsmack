#!/bin/bash
# Build and sign a probe as <out-dir>/CodeBindingProbe.app with App Attest and keychain-access-group entitlements.
# Usage: build-app.sh <out-dir> [swiftc flags...] <source.swift>...
set -euo pipefail
: "${SIGN_ID:?set SIGN_ID, e.g. Apple Development: Name (CERTID)}" "${KEYCHAIN:?set KEYCHAIN to the signing keychain path}"
: "${KEYCHAIN_PW:?set KEYCHAIN_PW}" "${TEAM_ID:?set TEAM_ID}" "${BUNDLE_ID:?set BUNDLE_ID}"
: "${PROFILE:?set PROFILE to the development provisioning profile for TEAM_ID.BUNDLE_ID}"
out=${1:?output directory}; shift
app="$out/CodeBindingProbe.app"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS"
xcrun swiftc -sdk "$(xcrun --show-sdk-path)" -target arm64-apple-macos27.0 \
  -framework DeviceCheck "$@" -o "$app/Contents/MacOS/probe"
cp "$PROFILE" "$app/Contents/embedded.provisionprofile"
cat > "$out/entitlements.plist" <<ENT
<?xml version="1.0"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict>
<key>com.apple.application-identifier</key><string>$TEAM_ID.$BUNDLE_ID</string>
<key>com.apple.developer.team-identifier</key><string>$TEAM_ID</string>
<key>com.apple.developer.devicecheck.app-attest-opt-in</key><array><string>CDhash</string></array>
<key>keychain-access-groups</key><array><string>$TEAM_ID.*</string></array>
</dict></plist>
ENT
cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>$BUNDLE_ID</string>
<key>CFBundleExecutable</key><string>probe</string>
<key>CFBundleName</key><string>CodeBindingProbe</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleVersion</key><string>1</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
<key>LSUIElement</key><true/>
<key>LSMinimumSystemVersion</key><string>27.0</string>
</dict></plist>
PLIST
security unlock-keychain -p "$KEYCHAIN_PW" "$KEYCHAIN"
codesign --force --options runtime --sign "$SIGN_ID" --keychain "$KEYCHAIN" \
  --entitlements "$out/entitlements.plist" --generate-entitlement-der --timestamp=none "$app"
codesign --verify --strict --verbose=2 "$app"
codesign -d --verbose=4 "$app" 2> "$out/codesign.txt"
