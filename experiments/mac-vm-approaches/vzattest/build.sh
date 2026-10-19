#!/bin/bash
# Bundle + sign the spike app. Requires KEYCHAIN, KEYCHAIN_PW, PROFILE (provisioning profile), ENTITLEMENTS and SIGN_IDENTITY.
set -euo pipefail
cd "$(dirname "$0")"
KC="${KEYCHAIN:?signing keychain path}"
app="$PWD/build/VZAttest.app"
security unlock-keychain -p "${KEYCHAIN_PW:?}" "$KC"
(cd app && swift build -c release)
rm -rf build; mkdir -p "$app/Contents/MacOS"
cp app/.build/release/vzattest "$app/Contents/MacOS/vzattest"
cp "${PROFILE:?provisioning profile}" "$app/Contents/embedded.provisionprofile"
cp "${ENTITLEMENTS:?entitlements plist}" build/entitlements.plist
/usr/libexec/PlistBuddy -c "Add :com.apple.security.virtualization bool true" build/entitlements.plist
cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>dev.dsmack.provider</string>
<key>CFBundleExecutable</key><string>vzattest</string>
<key>CFBundleName</key><string>VZAttest</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleVersion</key><string>1</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
<key>LSUIElement</key><true/>
<key>LSMinimumSystemVersion</key><string>27.0</string>
</dict></plist>
PLIST
codesign --force --options runtime --sign "${SIGN_IDENTITY:?Apple Development identity}" --keychain "$KC" \
  --entitlements build/entitlements.plist --generate-entitlement-der --timestamp=none "$app"
codesign --verify --strict --verbose=2 "$app"
codesign -d --verbose=4 "$app" 2> build/codesign.txt
codesign -d --entitlements - --xml "$app" > build/entitlements-signed.plist
grep -E "CDHash=|flags=|Authority=Apple Dev" build/codesign.txt
