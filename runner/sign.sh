#!/bin/bash
# Signed build for App Attest (mini). Requires KEYCHAIN_PW (dsmack keychain password).
# Writes build/Runner.app and build/cdhash.txt (full sha256 CDHash, the KMS allowlist entry).
set -euo pipefail
cd "$(dirname "$0")"
KC="$HOME/Library/Keychains/dsmack.keychain-db"
app="$PWD/build/Runner.app"
security unlock-keychain -p "${KEYCHAIN_PW:?}" "$KC"
swift build -c release
# App Attest omits the CDHash extension unless the binary says minos/sdk 27.
bv=$(otool -l .build/release/runner | awk '/LC_BUILD_VERSION/{f=1} f&&/minos|sdk/{print $1, $2} /ntools/{f=0}')
echo "$bv"
[ "$bv" = $'minos 27.0\nsdk 27.0' ] || { echo "sign.sh: binary is not minos 27.0 / sdk 27.0" >&2; exit 1; }
rm -rf build; mkdir -p "$app/Contents/MacOS"
cp .build/release/runner "$app/Contents/MacOS/runner"
cp "$HOME/dsmack-signing/embedded.provisionprofile" "$app/Contents/embedded.provisionprofile"
cp "$HOME/dsmack-signing/probe-entitlements.plist" build/entitlements.plist
/usr/libexec/PlistBuddy -c "Add :com.apple.security.virtualization bool true" build/entitlements.plist
cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>dev.dsmack.provider</string>
<key>CFBundleExecutable</key><string>runner</string>
<key>CFBundleName</key><string>Runner</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleVersion</key><string>1</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
<key>LSUIElement</key><true/>
<key>LSMinimumSystemVersion</key><string>27.0</string>
</dict></plist>
PLIST
codesign --force --options runtime --sign "Apple Development: Andrew Miller (QJUJ9F2UE4)" --keychain "$KC" \
  --entitlements build/entitlements.plist --generate-entitlement-der --timestamp=none "$app"
codesign --verify --strict --verbose=2 "$app"
codesign -d --verbose=4 "$app" 2> build/codesign.txt
codesign -d --entitlements - --xml "$app" > build/entitlements-signed.plist
grep -E "CandidateCDHashFull sha256=|VersionMin=|VersionSDK=|flags=|Authority=Apple Dev|TeamIdentifier=" build/codesign.txt
sed -n 's/^CandidateCDHashFull sha256=//p' build/codesign.txt > build/cdhash.txt
grep -qE '^[0-9a-f]{64}$' build/cdhash.txt || { echo "sign.sh: no full sha256 CDHash in codesign output" >&2; exit 1; }
echo "CDHASH $(cat build/cdhash.txt)"
