#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
variant=${1:?honest or modified}
kind=${2:?persistent or volatile}
case "$kind" in persistent) kindflag=PERSISTENT;; volatile) kindflag=VOLATILE;; *) exit 64;; esac
case "$variant" in honest) flags=(-D HONEST);; modified) flags=(-D MODIFIED);; *) exit 64;; esac
app="$PWD/build/$kind-$variant/CodeBindingProbe.app"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS"
xcrun swiftc -sdk "$(xcrun --show-sdk-path)" -target arm64-apple-macos27.0 \
  -framework DeviceCheck -D "$kindflag" "${flags[@]}" main.swift NetworkKey.swift -o "$app/Contents/MacOS/probe"
cp "$HOME/dsmack-signing/embedded.provisionprofile" "$app/Contents/embedded.provisionprofile"
cp "$HOME/dsmack-signing/probe-entitlements.plist" "build/$kind-$variant/entitlements.plist"
/usr/libexec/PlistBuddy -c 'Set :keychain-access-groups:0 DC9JH5DRMY.dev.dsmack.provider' "build/$kind-$variant/entitlements.plist"
if [ -f "$app/Contents/entitlements-evidence.plist" ]; then rm "$app/Contents/entitlements-evidence.plist"; fi
cat > "$app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>dev.dsmack.provider</string>
<key>CFBundleExecutable</key><string>probe</string>
<key>CFBundleName</key><string>CodeBindingProbe</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleVersion</key><string>1</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
<key>LSUIElement</key><true/>
<key>LSMinimumSystemVersion</key><string>27.0</string>
</dict></plist>
PLIST
codesign --force --options runtime --sign 'Apple Development: Andrew Miller (QJUJ9F2UE4)' \
  --keychain "$HOME/Library/Keychains/dsmack.keychain-db" \
  --entitlements "build/$kind-$variant/entitlements.plist" \
  --generate-entitlement-der --timestamp=none "$app"
codesign --verify --strict --verbose=2 "$app"
codesign -d --verbose=4 "$app" 2> "build/$kind-$variant/codesign.txt"
