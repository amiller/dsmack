#!/bin/bash
# Run on the Mac: build the iOS shell for the simulator (ad hoc signed; App Attest is unavailable there).
set -euo pipefail
cd "$(dirname "$0")"
app="$PWD/build/sim/Node.app"
rm -rf build/sim; mkdir -p "$app"
xcrun --sdk iphonesimulator swiftc -parse-as-library -O -sdk "$(xcrun --sdk iphonesimulator --show-sdk-path)" -target arm64-apple-ios27.0-simulator \
  -framework DeviceCheck ../shared/Protocol.swift ../shared/PersonalAccount.swift ../shared/BadgeClaim.swift ../shared/Upgrade.swift ../shared/Chain.swift ../shared/NativeAttestation.swift ../shared/Node.swift NetworkConfig.swift CodeEvidence.swift NodeApp.swift -o "$app/node"
cp Info.plist "$app/Info.plist"
codesign --force --sign - "$app"
