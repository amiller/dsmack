#!/bin/bash
# sign.sh — SEPARATE signing step for DsmackRunner.app (SWIFT03 repair3).
#
# This is split out of the old build.sh so the compile/package workflow
# (packaging/build.sh) is fully UNSIGNED and needs no credentials. Signing is an
# INDEPENDENTLY-REVIEWED step and only runs here, explicitly. It consumes the
# unsigned bundle build/DsmackRunner.app that build.sh produced; it does NOT
# compile or re-link. The keychain is unlocked by the configured unlock-existing.py
# in the same Mini SSH process before signing; Andrew does not know the
# agent-created password; there is no keychain password handling here and no
# keychain ACL changes.
#
# Preserved EXACTLY from endgame-signing-corrections: signing_policy.py checks
# (HVF v2 entitlement profile), DsmackRunner.entitlements, com.apple.security.hypervisor
# (NOT com.apple.vm.hypervisor / NOT com.apple.security.virtualization / NO
# com.apple.security.cs.* key — library validation stays enabled), the production/
# category3 identity, and the post-sign admission.json over the SIGNED bytes.
set -euo pipefail
cd "$(dirname "$0")"
HERE="$PWD"
app="$HERE/build/DsmackRunner.app"
if [ ! -d "$app" ]; then
  echo "refusing: $app not found — run packaging/build.sh (unsigned) first" >&2
  exit 1
fi
if [ ! -f "$HERE/build/UNSIGNED-BUILD.json" ]; then
  echo "refusing: build/UNSIGNED-BUILD.json missing — sign only an artifact build.sh produced" >&2
  exit 1
fi
KC="${KEYCHAIN:?signing keychain path}"
SIGNING_POLICY_DIR="${SIGNING_POLICY_DIR:-.}"   # signing_policy.py lives beside this packager
if [ ! -f "$app/Contents/embedded.provisionprofile" ]; then
  cp "${PROFILE:?provisioning profile}" "$app/Contents/embedded.provisionprofile"
fi
cp "${ENTITLEMENTS:?entitlements plist}" build/entitlements.plist
# com.apple.security.hypervisor is the Hypervisor.framework (HVF) entitlement the
# linked backend actually uses, idempotent (no-op when already present).
/usr/libexec/PlistBuddy -c "Set :com.apple.security.hypervisor true" build/entitlements.plist 2>/dev/null \
  || /usr/libexec/PlistBuddy -c "Add :com.apple.security.hypervisor bool true" build/entitlements.plist

# Policy check BEFORE signing (trusted team/app identity fixed in signing_policy.py).
PYTHONPATH="$SIGNING_POLICY_DIR" python3 -c "import sys; from signing_policy import check_entitlements_version, POLICY_VERSION_HVF; check_entitlements_version(open('build/entitlements.plist','rb').read(), POLICY_VERSION_HVF)"

codesign --force --options runtime --sign "${SIGN_IDENTITY:?Apple Development identity}" --keychain "$KC" \
  --entitlements build/entitlements.plist --generate-entitlement-der --timestamp=none "$app"
codesign --verify --strict --verbose=2 "$app"
codesign -d --verbose=4 "$app" 2> build/codesign.txt
codesign -d --entitlements - --xml "$app" > build/entitlements-signed.plist

# Policy check on what was ACTUALLY signed: entitlements (HVF v2 profile) + metadata.
# admission.json records the SIGNED artifact's own checks — the signed bytes and
# CDHash differ from the unsigned build and are gated separately.
PYTHONPATH="$SIGNING_POLICY_DIR" python3 - <<'PY'
from signing_policy import check_entitlements_version, POLICY_VERSION_HVF, check_metadata
import json
with open('build/entitlements-signed.plist', 'rb') as f:
    entitlements = check_entitlements_version(f.read(), POLICY_VERSION_HVF)
with open('build/codesign.txt', encoding='utf-8', errors='replace') as f:
    metadata = check_metadata(f.read())
with open('build/admission.json', 'w') as f:
    json.dump({'entitlements': entitlements, **metadata}, f, indent=2)
    f.write('\n')
PY
grep -E "CandidateCDHashFull sha256=|flags=|Authority=Apple Dev" build/codesign.txt
