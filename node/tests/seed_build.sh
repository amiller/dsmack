#!/bin/bash
# Mac side of the seed resilience test: signed Node.app and SeedSealTests.app (same team and
# Keychain group, different CDHashes), an ad hoc unentitled copy of the test, and cd-args.json.
# usage: seed_build.sh <out>   env: KEYCHAIN (unlocked), IDENTITY, PROFILE, TEAM, BUNDLE_ID
set -euo pipefail
out=$(cd "${1:?out dir}" && pwd); src=$(cd "$(dirname "$0")/.." && pwd)
shared=(Protocol Measure NativeDirectory PersonalAccount BadgeClaim Upgrade Chain NativeAttestation Node)
shared=("${shared[@]/#/$src/shared/}"); shared=("${shared[@]/%/.swift}")
cat > "$out/entitlements.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>com.apple.application-identifier</key><string>$TEAM.$BUNDLE_ID</string>
<key>com.apple.developer.team-identifier</key><string>$TEAM</string>
<key>com.apple.developer.devicecheck.app-attest-opt-in</key><array><string>CDhash</string></array>
<key>keychain-access-groups</key><array><string>$TEAM.$BUNDLE_ID</string></array>
</dict></plist>
EOF
bundle() { # name executable sources...
  local app="$out/$1.app"; mkdir -p "$app/Contents/MacOS"
  xcrun swiftc -O -sdk "$(xcrun --show-sdk-path)" -target arm64-apple-macos27.0 -framework DeviceCheck "${@:3}" -o "$app/Contents/MacOS/$2"
  sed "s|<string>node</string>|<string>$2</string>|;s|dev.dsmack.provider|$BUNDLE_ID|" "$src/mac/Info.plist" > "$app/Contents/Info.plist"
  cp "$PROFILE" "$app/Contents/embedded.provisionprofile"
  codesign --force --options runtime --sign "$IDENTITY" --keychain "$KEYCHAIN" --entitlements "$out/entitlements.plist" \
    --generate-entitlement-der --timestamp=none "$app"
  codesign --verify --strict "$app"
}
bundle Node node -D HONEST "${shared[@]}" "$src/mac/main.swift"
bundle SeedSealTests test "${shared[@]}" "$src/tests/SeedSealTests.swift"
cp "$out/SeedSealTests.app/Contents/MacOS/test" "$out/seal-test-adhoc"
codesign --force --sign - "$out/seal-test-adhoc"
python3 "$src/../scripts/cd_args.py" "$out/Node.app/Contents/MacOS/node" > "$out/cd-args.json"
for f in Node.app SeedSealTests.app seal-test-adhoc; do codesign -dvvv "$out/$f" 2>&1 | grep -E '^(CDHash|TeamIdentifier)=' | sed "s|^|$f |"; done
