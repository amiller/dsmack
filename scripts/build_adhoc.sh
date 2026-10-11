#!/bin/bash
# Archive and export one ad hoc variant with Xcode automatic (cloud-managed) signing.
set -euo pipefail
lab_root=$(cd "$(dirname "$0")/.." && pwd)
variant=${1:?honest or modified}
: "${LAB_ENVIRONMENT:?Set LAB_ENVIRONMENT to the environment the ad hoc profile grants}"
: "${LAB_DEFAULT_ENDPOINT:?Set LAB_DEFAULT_ENDPOINT}"
case "$variant" in honest) flags='';; modified) flags=MODIFIED;; *) exit 64;; esac
out="$lab_root/build/adhoc/$variant"
rm -rf "$out"
python3 "$lab_root/scripts/make_project.py"
xcodebuild -project "$lab_root/app/AppAttestLab.xcodeproj" -scheme AppAttestLab \
  -configuration Release -destination 'generic/platform=iOS' -derivedDataPath "$out/dd" \
  -archivePath "$out/AppAttestLab.xcarchive" -allowProvisioningUpdates \
  DEVELOPMENT_TEAM=DC9JH5DRMY PRODUCT_BUNDLE_IDENTIFIER=dev.dsmack.provider CODE_SIGN_STYLE=Automatic \
  "APP_ATTEST_ENVIRONMENT=$LAB_ENVIRONMENT" "LAB_DEFAULT_ENDPOINT=$LAB_DEFAULT_ENDPOINT" \
  CURRENT_PROJECT_VERSION=1 "SWIFT_ACTIVE_COMPILATION_CONDITIONS=$flags" \
  "OTHER_CODE_SIGN_FLAGS=--keychain $HOME/Library/Keychains/dsmack.keychain-db" archive
cat > "$out/export.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>method</key><string>release-testing</string>
<key>signingStyle</key><string>automatic</string>
<key>teamID</key><string>DC9JH5DRMY</string>
<key>compileBitcode</key><false/>
<key>thinning</key><string>&lt;none&gt;</string>
</dict></plist>
PLIST
xcodebuild -exportArchive -archivePath "$out/AppAttestLab.xcarchive" \
  -exportOptionsPlist "$out/export.plist" -exportPath "$out/export" -allowProvisioningUpdates
mv "$out/export/App Attest Lab.ipa" "$out/export/AppAttestLab.ipa"
echo "Exported $out/export/AppAttestLab.ipa"
