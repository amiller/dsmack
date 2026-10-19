#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
: "${KEYCHAIN:?set KEYCHAIN to the signing keychain}" "${KEYCHAIN_PW:?set KEYCHAIN_PW}" "${SIGN_ID:?set SIGN_ID, e.g. Apple Development: Name (TEAMID)}"
APP=AppAttestProbe.app
SDK=$(xcrun --show-sdk-path)
echo "SDK=$SDK"
xcrun swiftc -sdk "$SDK" -target arm64-apple-macos27.0 \
  -framework DeviceCheck appattest-probe.swift -o appattest-probe
rm -rf "$APP"; mkdir -p "$APP/Contents/MacOS"
cp appattest-probe "$APP/Contents/MacOS/appattest-probe"
cp embedded.provisionprofile "$APP/Contents/embedded.provisionprofile"
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>dev.dsmack.provider</string>
  <key>CFBundleExecutable</key><string>appattest-probe</string>
  <key>CFBundleName</key><string>AppAttestProbe</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>LSUIElement</key><true/>
  <key>LSMinimumSystemVersion</key><string>27.0</string>
</dict></plist>
PLIST
cat > probe-entitlements.plist <<ENT
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>com.apple.application-identifier</key><string>DC9JH5DRMY.dev.dsmack.provider</string>
  <key>com.apple.developer.team-identifier</key><string>DC9JH5DRMY</string>
  <key>com.apple.developer.devicecheck.app-attest-opt-in</key><array><string>CDhash</string></array>
  <key>keychain-access-groups</key><array><string>DC9JH5DRMY.*</string></array>
  <key>get-task-allow</key><true/>
</dict></plist>
ENT
security unlock-keychain -p "$KEYCHAIN_PW" "$KEYCHAIN"
codesign --force --sign "$SIGN_ID" \
  --entitlements probe-entitlements.plist --keychain "$KEYCHAIN" --generate-entitlement-der \
  --timestamp=none "$APP"
echo "== entitlements in signature =="
codesign -d --entitlements - "$APP" 2>&1 | grep -iE "app-attest|application-identifier|team"
echo "== cdhash of binary =="
codesign -dvvv "$APP" 2>&1 | grep -iE "^CDHash|Identifier|Authority=Apple Dev"
