#!/bin/bash
# Signed runner for App Attest (mini): scripts/release/build_mac.py --runner (the reproducible unsigned build), then
# sign_mac.py under the node's App ID with runner_entitlements (the node's template plus virtualization).
# Writes <out>/Runner.app, <out>/cdhash.txt (full sha256 CDHash) and <out>/measurement.txt (M_runner,
# scripts/release/measure.py: what the node compiles in, build_mac.py --sdk-runner), keeping <out>/unsigned and its manifest.
# usage: sign.sh [out (default build)]
# env: KEYCHAIN_PW unlocks the dsmack keychain when set. IDENTITY (default Apple Development: Andrew Miller (QJUJ9F2UE4)),
# PROFILE (default ~/dsmack-signing/embedded.provisionprofile), TEAM (default DC9JH5DRMY), CHANNEL development (default) or
# developer-id with NOTARY_PROFILE: the release runner is Developer ID-signed and notarized like the node (or exported with
# export_mac_xcode.py --app <out>/Runner.app). BUNDLE_VERSION (default 1) only changes Info.plist, hence the CDHash and
# not M_runner; MODIFIED=1 builds the negative-control variant (other code, another M_runner).
set -euo pipefail
cd "$(dirname "$0")"
KC="$HOME/Library/Keychains/dsmack.keychain-db"
out="$PWD/${1:-build}"
[ -z "${KEYCHAIN_PW:-}" ] || security unlock-keychain -p "$KEYCHAIN_PW" "$KC"
rm -rf "$out"
python3 ../scripts/release/build_mac.py --runner --out "$out/unsigned" --version 1.0 --build-number "${BUNDLE_VERSION:-1}" \
  ${MODIFIED:+--modified} > /dev/null
python3 ../scripts/release/sign_mac.py --build "$out/unsigned" --out "$out/signed" --keychain "$KC" \
  --profile "${PROFILE:-$HOME/dsmack-signing/embedded.provisionprofile}" --team "${TEAM:-DC9JH5DRMY}" \
  --identity "${IDENTITY:-Apple Development: Andrew Miller (QJUJ9F2UE4)}" --channel "${CHANNEL:-development}" \
  ${NOTARY_PROFILE:+--notary-profile "$NOTARY_PROFILE"} > /dev/null
mv "$out/signed/Runner.app" "$out/Runner.app"
codesign --verify --strict --verbose=2 "$out/Runner.app"
codesign -d --verbose=4 "$out/Runner.app" 2> "$out/codesign.txt"
codesign -d --entitlements - --xml "$out/Runner.app" > "$out/entitlements-signed.plist"
grep -E "CandidateCDHashFull sha256=|flags=|Authority=(Apple Dev|Developer ID)|TeamIdentifier=" "$out/codesign.txt"
sed -n 's/^CandidateCDHashFull sha256=//p' "$out/codesign.txt" > "$out/cdhash.txt"
grep -qE '^[0-9a-f]{64}$' "$out/cdhash.txt" || { echo "sign.sh: no full sha256 CDHash in codesign output" >&2; exit 1; }
python3 ../scripts/release/measure.py "$out/Runner.app/Contents/MacOS/runner" | python3 -c 'import json,sys; print(json.load(sys.stdin)["M"][2:])' > "$out/measurement.txt"
echo "CDHASH $(cat "$out/cdhash.txt")"
echo "M_RUNNER $(cat "$out/measurement.txt")"
