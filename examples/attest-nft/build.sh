#!/bin/bash
# build.sh IDENTITY PROFILE TEAM BUNDLE_ID [EXECUTABLE]  ->  build/AttestNFT.app
# Compiles App.swift, or with EXECUTABLE re-signs an existing build's executable unchanged.
set -euo pipefail
cd "$(dirname "$0")"
identity=$1 profile=$2 team=$3 bundle=$4
app=build/AttestNFT.app
rm -rf build && mkdir -p "$app/Contents/MacOS"
if [ $# -ge 5 ]; then cp "$5" "$app/Contents/MacOS/attest-nft"
else xcrun swiftc -O -target arm64-apple-macos27.0 -framework DeviceCheck -framework IOKit App.swift -o "$app/Contents/MacOS/attest-nft"; fi
cp "$profile" "$app/Contents/embedded.provisionprofile"
cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>$bundle</string>
<key>CFBundleExecutable</key><string>attest-nft</string>
<key>CFBundleName</key><string>AttestNFT</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleVersion</key><string>1</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
<key>LSUIElement</key><true/>
<key>LSMinimumSystemVersion</key><string>27.0</string>
</dict></plist>
PLIST
# Same keys in the same order for every copy: CDRegistry pins this shape and lets only the identity values differ.
cat > build/entitlements.plist <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>com.apple.application-identifier</key><string>$team.$bundle</string>
<key>com.apple.developer.team-identifier</key><string>$team</string>
<key>com.apple.developer.devicecheck.app-attest-opt-in</key><array><string>CDhash</string></array>
<key>keychain-access-groups</key><array><string>$team.*</string></array>
</dict></plist>
PLIST
codesign --force --options runtime --timestamp --sign "$identity" ${KEYCHAIN:+--keychain "$KEYCHAIN"} --entitlements build/entitlements.plist --generate-entitlement-der "$app"
codesign --verify --strict "$app"
codesign -d --verbose=2 "$app" 2>&1 | grep CDHash
