#!/bin/bash
# Build two source variants with explicit, caller-selected signing assets.
set -euo pipefail
lab_root=$(cd "$(dirname "$0")/.." && pwd)
variant=${1:-honest}
if [[ "$variant" != honest && "$variant" != modified ]]; then
  echo 'Usage: build.sh honest|modified [xcodebuild arguments...]' >&2
  exit 2
fi
if [[ $# -gt 0 ]]; then shift; fi
: "${LAB_TEAM_ID:?Set LAB_TEAM_ID}"
: "${LAB_BUNDLE_ID:?Set LAB_BUNDLE_ID}"
: "${LAB_SIGN_IDENTITY:?Set LAB_SIGN_IDENTITY to the signing certificate SHA-1 or exact name}"
: "${LAB_PROFILE:?Set LAB_PROFILE to an installed provisioning profile name or UUID}"
lab_environment=${LAB_ENVIRONMENT:-development}
[[ "$lab_environment" == development || "$lab_environment" == production ]] || exit 2
python3 "$lab_root/scripts/make_project.py"
lab_flags=''
if [[ "$variant" == modified ]]; then lab_flags=MODIFIED; fi
xcodebuild -project "$lab_root/app/AppAttestLab.xcodeproj" -scheme AppAttestLab \
  -configuration Release -destination 'generic/platform=iOS' \
  -derivedDataPath "$lab_root/build/$variant" \
  "DEVELOPMENT_TEAM=$LAB_TEAM_ID" "PRODUCT_BUNDLE_IDENTIFIER=$LAB_BUNDLE_ID" \
  "CODE_SIGN_IDENTITY=$LAB_SIGN_IDENTITY" "PROVISIONING_PROFILE_SPECIFIER=$LAB_PROFILE" \
  "APP_ATTEST_ENVIRONMENT=$lab_environment" "CURRENT_PROJECT_VERSION=${LAB_BUILD_VERSION:-1}" \
  "SWIFT_ACTIVE_COMPILATION_CONDITIONS=$lab_flags" "$@" build
lab_app="$lab_root/build/$variant/Build/Products/Release-iphoneos/AppAttestLab.app"
codesign --verify --deep --strict "$lab_app"
python3 "$lab_root/scripts/manifest.py" "$lab_app" --output "$lab_root/build/$variant/manifest.json"
echo "Built $lab_app"
