#!/bin/bash
# Signs build/DsmackRunner.app produced by build.sh.
# Requires KEYCHAIN, SIGN_IDENTITY, ENTITLEMENTS and PROFILE (unless build.sh embedded one).
set -euo pipefail
cd "$(dirname "$0")"
app="$PWD/build/DsmackRunner.app"
KC="${KEYCHAIN:?signing keychain path}"
if [ ! -f "$app/Contents/embedded.provisionprofile" ]; then
  cp "${PROFILE:?provisioning profile}" "$app/Contents/embedded.provisionprofile"
fi
cp "${ENTITLEMENTS:?entitlements plist}" build/entitlements.plist
python3 -c "from signing_policy import check_entitlements; check_entitlements(open('build/entitlements.plist','rb').read())"

codesign --force --options runtime --sign "${SIGN_IDENTITY:?Apple Development identity}" --keychain "$KC" \
  --entitlements build/entitlements.plist --generate-entitlement-der --timestamp=none "$app"
codesign --verify --strict --verbose=2 "$app"
codesign -d --verbose=4 "$app" 2> build/codesign.txt
codesign -d --entitlements - --xml "$app" > build/entitlements-signed.plist

python3 - <<'PY'
from signing_policy import check_entitlements, check_metadata
import json
entitlements = check_entitlements(open('build/entitlements-signed.plist', 'rb').read())
metadata = check_metadata(open('build/codesign.txt', encoding='utf-8', errors='replace').read())
with open('build/admission.json', 'w') as f:
    json.dump({'entitlements': entitlements, **metadata}, f, indent=2)
    f.write('\n')
PY
grep -E "CandidateCDHashFull sha256=|flags=|Authority=Apple Dev" build/codesign.txt
