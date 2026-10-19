#!/bin/bash
# usage: build.sh honest|fake|provider2
set -euo pipefail
cd "$(dirname "$0")"
v=${1:?variant}; flags=(); bundle=dev.dsmack.provider; profile=embedded.provisionprofile
case "$v" in honest) ;; fake) flags=(-D FAKE);; provider2) bundle=dev.dsmack.provider2; profile=dsmack_provider2_dev.provisionprofile;; vm) profile=vm-test.provisionprofile;; *) exit 64;; esac
app="$PWD/build/$v/TagProbe.app"
rm -rf "build/$v"; mkdir -p "$app/Contents/MacOS"
xcrun swiftc -sdk "$(xcrun --show-sdk-path)" -target arm64-apple-macos27.0 -framework DeviceCheck -framework IOKit ${flags[@]+"${flags[@]}"} TagProbe.swift -o "$app/Contents/MacOS/probe"
cp "${SIGNING_DIR:?directory holding provisioning profiles and probe-entitlements.plist}/$profile" "$app/Contents/embedded.provisionprofile"
sed "s/dev\.dsmack\.provider</$bundle</" "${SIGNING_DIR:?directory holding provisioning profiles and probe-entitlements.plist}/probe-entitlements.plist" > "build/$v/entitlements.plist"
cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>$bundle</string>
<key>CFBundleExecutable</key><string>probe</string>
<key>CFBundleName</key><string>TagProbe</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleVersion</key><string>1</string>
<key>LSUIElement</key><true/>
<key>LSMinimumSystemVersion</key><string>27.0</string>
</dict></plist>
PLIST
codesign --force --options runtime --sign "${SIGN_IDENTITY:?Apple Development identity}" \
  --keychain "${KEYCHAIN:?signing keychain}" \
  --entitlements "build/$v/entitlements.plist" --generate-entitlement-der --timestamp=none "$app"
codesign --verify --strict "$app"
codesign -dvvv "$app" 2>&1 | grep -E "^(Identifier|CDHash|CandidateCDHashFull|TeamIdentifier|CodeDirectory)" > "build/$v/codesign.txt"
cat "build/$v/codesign.txt"
