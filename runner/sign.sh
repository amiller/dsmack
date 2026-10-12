#!/bin/bash
# Signed build for App Attest (mini). KEYCHAIN_PW (dsmack keychain password) unlocks the keychain when set.
# Writes <out>/Runner.app and <out>/cdhash.txt (full sha256 CDHash: the node's sdkRunners entry, the dev KMS allowlist
# entry). usage: sign.sh [out (default build)]; BUNDLE_VERSION (default 1) only changes Info.plist, hence the CDHash.
set -euo pipefail
cd "$(dirname "$0")"
KC="$HOME/Library/Keychains/dsmack.keychain-db"
out="$PWD/${1:-build}"; app="$out/Runner.app"
[ -z "${KEYCHAIN_PW:-}" ] || security unlock-keychain -p "$KEYCHAIN_PW" "$KC"
swift build -c release
# App Attest omits the CDHash extension unless the binary says minos/sdk 27.
bv=$(otool -l .build/release/runner | awk '/LC_BUILD_VERSION/{f=1} f&&/minos|sdk/{print $1, $2} /ntools/{f=0}')
echo "$bv"
[ "$bv" = $'minos 27.0\nsdk 27.0' ] || { echo "sign.sh: binary is not minos 27.0 / sdk 27.0" >&2; exit 1; }
rm -rf "$out"; mkdir -p "$app/Contents/MacOS"
cp .build/release/runner "$app/Contents/MacOS/runner"
cp "$HOME/dsmack-signing/embedded.provisionprofile" "$app/Contents/embedded.provisionprofile"
cp "$HOME/dsmack-signing/probe-entitlements.plist" "$out/entitlements.plist"
/usr/libexec/PlistBuddy -c "Add :com.apple.security.virtualization bool true" "$out/entitlements.plist"
cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>dev.dsmack.provider</string>
<key>CFBundleExecutable</key><string>runner</string>
<key>CFBundleName</key><string>Runner</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleVersion</key><string>${BUNDLE_VERSION:-1}</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
<key>LSUIElement</key><true/>
<key>LSMinimumSystemVersion</key><string>27.0</string>
</dict></plist>
PLIST
codesign --force --options runtime --sign "Apple Development: Andrew Miller (QJUJ9F2UE4)" --keychain "$KC" \
  --entitlements "$out/entitlements.plist" --generate-entitlement-der --timestamp=none "$app"
codesign --verify --strict --verbose=2 "$app"
codesign -d --verbose=4 "$app" 2> "$out/codesign.txt"
codesign -d --entitlements - --xml "$app" > "$out/entitlements-signed.plist"
grep -E "CandidateCDHashFull sha256=|VersionMin=|VersionSDK=|flags=|Authority=Apple Dev|TeamIdentifier=" "$out/codesign.txt"
sed -n 's/^CandidateCDHashFull sha256=//p' "$out/codesign.txt" > "$out/cdhash.txt"
grep -qE '^[0-9a-f]{64}$' "$out/cdhash.txt" || { echo "sign.sh: no full sha256 CDHash in codesign output" >&2; exit 1; }
echo "CDHASH $(cat "$out/cdhash.txt")"
