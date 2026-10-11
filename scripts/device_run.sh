#!/bin/bash
# Build, preserve, install, and launch one real-device experiment arm.
# Does not generate App Attest keys automatically or delete the app/key container.
set -euo pipefail
lab_root=$(cd "$(dirname "$0")/.." && pwd)
lab_run=${1:?Usage: device_run.sh UNIQUE_RUN_ID honest|modified [xcodebuild arguments...]}
lab_variant=${2:?Usage: device_run.sh UNIQUE_RUN_ID honest|modified [xcodebuild arguments...]}
shift 2
[[ "$lab_run" =~ ^[A-Za-z0-9_-]+$ ]] || { echo 'Use letters/digits/_/- in run ID' >&2; exit 2; }
[[ "$lab_variant" == honest || "$lab_variant" == modified ]] || exit 2
: "${LAB_DEVICE_ID:?Set LAB_DEVICE_ID from devicectl list devices}"
: "${LAB_BUNDLE_ID:?Set LAB_BUNDLE_ID}"
: "${LAB_ENDPOINT:?Set the HTTPS verifier URL reachable by the phone}"
[[ "$LAB_ENDPOINT" == https://* ]] || { echo 'HTTPS endpoint required' >&2; exit 2; }
lab_run_dir="$lab_root/captures/$lab_run"
mkdir -p "$lab_root/captures"
mkdir "$lab_run_dir"  # Deliberately refuses an existing run ID.
bash "$lab_root/scripts/build.sh" "$lab_variant" "$@" > "$lab_run_dir/build.log" 2>&1 || {
  tail -40 "$lab_run_dir/build.log" >&2; exit 1;
}
cp "$lab_root/build/$lab_variant/manifest.json" "$lab_run_dir/manifest.json"
ditto "$lab_root/build/$lab_variant/Build/Products/Release-iphoneos/AppAttestLab.app" "$lab_run_dir/AppAttestLab.app"
xcrun devicectl device install app --device "$LAB_DEVICE_ID" "$lab_run_dir/AppAttestLab.app" \
  --json-output "$lab_run_dir/install.json"
xcrun devicectl device process launch --device "$LAB_DEVICE_ID" --terminate-existing \
  --json-output "$lab_run_dir/launch.json" "$LAB_BUNDLE_ID" --endpoint "$LAB_ENDPOINT"
echo "Run saved at $lab_run_dir"
echo 'On the phone: Check setup, then enroll/assert as appropriate for this arm.'
echo 'For the update arm, try the existing key first; do not generate a replacement yet.'
