#!/bin/bash
# Hosts the approved runner from your own Apple team: re-signs APP under PROFILE and SIGN_IDENTITY
# into OUT/DsmackRunner.app, registers the copy in CDRegistry, enrolls its App Attest key into
# OUT/enrollment and, when AUTHORIZATION is set, links the key to its operator.
# Requires APP, PROFILE, SIGN_IDENTITY, OUT, RPC, CDS, ATTEST, INTERMEDIATE and ACCOUNT; see
# docs/own-team.md. A step the chain already shows done is skipped, so a failed run can be repeated.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
py="${PYTHON:-python3}"
die() { echo "own-team: $*" >&2; exit 1; }
call() { cast call --rpc-url "${RPC:?RPC URL}" "$@"; }
send() { cast send --rpc-url "$RPC" --account "${ACCOUNT:?cast keystore account}" "$@"; }
measure() { "$py" "$root/contracts/cd_args.py" --measure "$1" | grep -v entitlements_der; }

mkdir -p "${OUT:?output directory}"
out="$(cd "$OUT" && pwd)"
app="$out/DsmackRunner.app"
bin="$app/Contents/MacOS/dsmack-runner"
src="${APP:?approved DsmackRunner.app}/Contents/MacOS/dsmack-runner"

# Re-sign. The entitlements are the approved app's own with the three values AMFI checks against the
# profile replaced; CDRegistry compares every other entitlement byte for byte.
security cms -D -i "${PROFILE:?provisioning profile}" > "$out/profile.plist"
codesign -d --entitlements - --xml "$APP" 2>/dev/null > "$out/approved-entitlements.plist"
app_id="$("$py" - "$out" <<'PY'
import plistlib, sys
out = sys.argv[1]
profile = plistlib.load(open(out + '/profile.plist', 'rb'))['Entitlements']
ents = plistlib.load(open(out + '/approved-entitlements.plist', 'rb'))
app_id = profile['com.apple.application-identifier']
ents['com.apple.application-identifier'] = app_id
ents['com.apple.developer.team-identifier'] = profile['com.apple.developer.team-identifier']
ents['keychain-access-groups'] = [app_id]
plistlib.dump(ents, open(out + '/entitlements.plist', 'wb'))
print(app_id)
PY
)"
rm -rf "$app"
# --noqtn: Gatekeeper refuses a quarantined app that is not notarized, and this copy is yours.
ditto --noqtn "$APP" "$app"
cp "$PROFILE" "$app/Contents/embedded.provisionprofile"
plutil -replace CFBundleIdentifier -string "${app_id#*.}" "$app/Contents/Info.plist"
codesign --force --options runtime --sign "${SIGN_IDENTITY:?codesigning identity}" ${KEYCHAIN:+--keychain "$KEYCHAIN"} \
  --entitlements "$out/entitlements.plist" --generate-entitlement-der --timestamp=none "$app"
codesign --verify --strict "$app"
# registerBuild refuses a well-formed copy only with "not an approved build"; this names the pinned
# field codesign changed.
approved_measure="$(measure "$src")"
diff <(echo "$approved_measure") <(measure "$bin") || die "the re-signed copy differs from APP in a field CDRegistry pins"
"$py" "$root/contracts/cd_args.py" "$bin" > "$out/build.json"
b() { "$py" -c 'import json,sys;print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$out/build.json" "$1"; }
cdhash="$(b cdhash)"
rp="0x$(printf %s "$app_id" | shasum -a 256 | cut -d' ' -f1)"
echo "app id $app_id, cdhash $cdhash"

# Register. A copy of a superseded build registers too but never resolves, so check APP first.
approved="$("$py" "$root/contracts/cd_args.py" "$src" | "$py" -c 'import json,sys;print(json.load(sys.stdin)["cdhash"])')"
current="$(call "${CDS:?CDRegistry}" 'buildId()(bytes32)')"
[ "$(call "$CDS" 'buildOf(bytes32)(bytes32)' "$approved")" = "$current" ] ||
  die "APP ($approved) is not a registered copy of the registry's current build $current"
if [ "$(call "$CDS" 'rpIdHash(bytes32)(bytes32)' "$cdhash")" != "$rp" ]; then
  [ "$(call "$CDS" 'registerBuild(bytes,bytes,bytes)(bytes32)' "$(b cd)" "$(b page0)" "$(b ent)")" = "$cdhash" ] ||
    die "CDRegistry does not admit the re-signed copy"
  send "$CDS" 'registerBuild(bytes,bytes,bytes)' "$(b cd)" "$(b page0)" "$(b ent)"
  [ "$(call "$CDS" 'rpIdHash(bytes32)(bytes32)' "$cdhash")" = "$rp" ] || die "rpIdHash($cdhash) is not sha256($app_id)"
fi

# Enroll. Apple's leaf certificate lasts three days: remove OUT/enrollment to enroll a fresh key.
if [ ! -f "$out/enrollment/attestation.cbor" ]; then
  rm -rf "$out/enrollment"
  head -c 32 /dev/urandom > "$out/challenge.bin"
  open -n -W --stderr "$out/enroll.stderr" "$app" --args enroll "$out/enrollment" "$out/challenge.bin"
  # open(1) exits 0 whatever the app did; the attestation is the evidence that enroll worked.
  [ -f "$out/enrollment/attestation.cbor" ] || die "enroll failed: $(cat "$out/enroll.stderr")"
fi
kid="0x$(base64 -d < "$out/enrollment/keyId.txt" | xxd -p -c 32)"
enrolled() { call "${ATTEST:?App Attest verifier}" 'keys(bytes32)(uint256,uint256,uint64,uint32,bool)' "$kid" | tail -1; }
if [ "$(enrolled)" != true ]; then
  read -r leaf auth < <(PYTHONPATH="$root" "$py" -c 'import sys
from verifier.core import decode
a = decode(open(sys.argv[1], "rb").read())
print("0x" + a["attStmt"]["x5c"][0].hex(), "0x" + a["authData"].hex())' "$out/enrollment/attestation.cbor")
  args=("$leaf" "$auth" "0x$(xxd -p "$out/enrollment/clientData.bin" | tr -d '\n')" "${INTERMEDIATE:?Apple intermediate entry id}")
  [ "$(call "$ATTEST" 'enroll(bytes,bytes,bytes,bytes32)(bytes32)' "${args[@]}")" = "$kid" ] ||
    die "the verifier does not accept this enrollment"
  send "$ATTEST" 'enroll(bytes,bytes,bytes,bytes32)' "${args[@]}" --gas-limit 16000000
  [ "$(enrolled)" = true ] || die "keys($kid) is not enrolled"
fi
echo "kid $kid"

if [ -n "${AUTHORIZATION:-}" ]; then
  "$py" "$root/applications/mac-ownership/ownership.py" link --kid "$kid" --authorization "$AUTHORIZATION" \
    --provisioner-key "${PROVISIONER_KEY:?provisioner key}" ${PUBLISHER_KEY:+--publisher-key "$PUBLISHER_KEY"} \
    ${BROKER:+--broker "$BROKER"}
fi
