#!/bin/bash
# Run on the Mac (macOS 27, Xcode 27). KEYCHAIN_PW = dsmack keychain password (unlock is per ssh session).
# honest|modified: compile + sign. resigned: codesign --force a copy of build/honest (same code, new signature).
set -euo pipefail
cd "$(dirname "$0")"
variant=${1:?honest|modified|resigned}
security unlock-keychain -p "${KEYCHAIN_PW:?}" "$HOME/Library/Keychains/dsmack.keychain-db"
app="$PWD/build/$variant/Node.app"
sign() { codesign --force --options runtime --sign 'Apple Development: Andrew Miller (QJUJ9F2UE4)' \
  --keychain "$HOME/Library/Keychains/dsmack.keychain-db" --entitlements entitlements.plist \
  --generate-entitlement-der "$@" "$app"; }
rm -rf "build/$variant"; mkdir -p "build/$variant"
cp "$HOME/dsmack-signing/probe-entitlements.plist" entitlements.plist
if [ "$variant" = resigned ]; then
  ditto build/honest/Node.app "$app"; sign --timestamp=none --signature-size 20000
else
  flag=HONEST; [ "$variant" = modified ] && flag=MODIFIED
  mkdir -p "$app/Contents/MacOS"
  xcrun swiftc -O -sdk "$(xcrun --show-sdk-path)" -target arm64-apple-macos27.0 -framework DeviceCheck -D $flag \
    ../shared/Protocol.swift ../shared/PersonalAccount.swift ../shared/BadgeClaim.swift ../shared/Upgrade.swift ../shared/Chain.swift ../shared/NativeAttestation.swift ../shared/Node.swift main.swift -o "$app/Contents/MacOS/node"
  cp "$HOME/dsmack-signing/embedded.provisionprofile" "$app/Contents/embedded.provisionprofile"
  cp Info.plist "$app/Contents/Info.plist"
  sign --timestamp=none
fi
codesign --verify --strict "$app"
codesign -d --verbose=4 "$app" 2> "build/$variant/codesign.txt"
grep CDHash= "build/$variant/codesign.txt"
