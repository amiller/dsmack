#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
variant=${1:?honest or modified}
case "$variant" in honest) flags=(-D HONEST);; modified) flags=(-D MODIFIED);; *) exit 64;; esac
app="$PWD/build/$variant/PaperDemo.app"
mkdir -p "$app/Contents/MacOS"
xcrun swiftc -sdk "$(xcrun --show-sdk-path)" -target arm64-apple-macos27.0 \
  -framework DeviceCheck "${flags[@]}" Protocol.swift Chain.swift main.swift -o "$app/Contents/MacOS/demo"
cp "$HOME/dsmack-signing/embedded.provisionprofile" "$app/Contents/embedded.provisionprofile"
cp "$HOME/dsmack-signing/probe-entitlements.plist" "build/$variant/entitlements.plist"
cat > "$app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>dev.dsmack.provider</string>
<key>CFBundleExecutable</key><string>demo</string>
<key>CFBundleName</key><string>PaperDemo</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleVersion</key><string>1</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
<key>LSUIElement</key><true/>
<key>LSMinimumSystemVersion</key><string>27.0</string>
</dict></plist>
PLIST
codesign --force --options runtime --sign 'Apple Development: Andrew Miller (QJUJ9F2UE4)' \
  --keychain "$HOME/Library/Keychains/dsmack.keychain-db" \
  --entitlements "build/$variant/entitlements.plist" --generate-entitlement-der --timestamp=none "$app"
codesign --verify --strict "$app"
codesign -d --verbose=4 "$app" 2>"build/$variant/codesign.txt"
