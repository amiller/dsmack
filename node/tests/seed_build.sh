#!/bin/bash
# Mac side of the seed resilience test: signed Node.app and SeedSealTests.app (same team and
# Keychain group, different CDHashes), an ad hoc unentitled copy of the test, and cd-args.json.
# usage: seed_build.sh <out>   env: KEYCHAIN (unlocked), IDENTITY, PROFILE, TEAM, BUNDLE_ID; optional NODE_FLAGS for
# Node.app only (sdk_e2e.py: -D SDK_TEST_TRUST), optional SDK_RUNNERS (space-separated runner measurements M_runner compiled into every
# build here, as scripts/release/build_mac.py --sdk-runner does; written to <out>/sdk-runners.txt)
set -euo pipefail
out=$(cd "${1:?out dir}" && pwd); src=$(cd "$(dirname "$0")/.." && pwd)
shared=(Protocol Measure NativeDirectory PersonalAccount BadgeClaim Upgrade Chain NativeAttestation Node SDK AppAttestVerify)
shared=("${shared[@]/#/$src/shared/}"); shared=("${shared[@]/%/.swift}")
runners=$(for c in ${SDK_RUNNERS:-}; do [[ $c =~ ^[0-9a-f]{64}$ ]] || { echo "SDK_RUNNERS: $c is not 64 hex" >&2; exit 1; }; printf '"%s",' "$c"; done)
mkdir -p "$out/sdk-runners"
sed "s/^let compiledSDKRunnerMeasurements: \[String\] = \[\]$/let compiledSDKRunnerMeasurements: [String] = [${runners%,}]/" "$src/shared/SDKRunners.swift" > "$out/sdk-runners/SDKRunners.swift"
echo "${SDK_RUNNERS:-}" > "$out/sdk-runners.txt"
shared+=("$out/sdk-runners/SDKRunners.swift")
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
bundle Node node -D HONEST ${NODE_FLAGS:-} "${shared[@]}" "$src/mac/main.swift"
bundle SeedSealTests test "${shared[@]}" "$src/tests/SeedSealTests.swift"
cp "$out/SeedSealTests.app/Contents/MacOS/test" "$out/seal-test-adhoc"
codesign --force --sign - "$out/seal-test-adhoc"
python3 "$src/../scripts/cd_args.py" "$out/Node.app/Contents/MacOS/node" > "$out/cd-args.json"
for f in Node.app SeedSealTests.app seal-test-adhoc; do codesign -dvvv "$out/$f" 2>&1 | grep -E '^(CDHash|TeamIdentifier)=' | sed "s|^|$f |"; done
