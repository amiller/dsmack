#!/bin/bash
# M_runner is signer-independent: sign one runner executable under two throwaway self-signed teams (each with its own
# App ID, as another Apple team would) and require one M_runner and two CDHashes; the MODIFIED build (sign.sh MODIFIED=1)
# must give another M_runner. M is scripts/release/measure.py, the node's definition.
# The Runner.apps may be unsigned (scripts/release/build_mac.py --runner, as in CI) or signed (runner/sign.sh).
# Writes OUT_DIR/m_runner.txt: the M_runner to compile into the node (scripts/release/measure_two_teams.sh RUNNER_M).
# usage: runner/measure_two_teams.sh <runner build>/Runner.app <runner build-modified>/Runner.app OUT_DIR (must not exist)
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
mkdir "$3"; OUT=$(cd "$3" && pwd); KC="$OUT/throwaway.keychain-db"
trap 'security delete-keychain "$KC" 2>/dev/null || true' EXIT
security create-keychain -p throwaway "$KC"; security unlock-keychain -p throwaway "$KC"
printf '[req]\ndistinguished_name=dn\n[dn]\n[ext]\nbasicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,codeSigning\n' > "$OUT/cert.cnf"
for team in TEAMAAAAAA TEAMBBBBBB; do
  /usr/bin/openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout "$OUT/$team.key" -out "$OUT/$team.pem" \
    -subj "/CN=Throwaway $team/OU=$team/O=Throwaway" -config "$OUT/cert.cnf" -extensions ext 2>/dev/null
  /usr/bin/openssl pkcs12 -export -inkey "$OUT/$team.key" -in "$OUT/$team.pem" -out "$OUT/$team.p12" -passout pass:throwaway
  security import "$OUT/$team.p12" -k "$KC" -P throwaway -T /usr/bin/codesign >/dev/null
  rm "$OUT/$team.key" "$OUT/$team.p12"
done
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k throwaway "$KC" >/dev/null
sign() {  # name app team bundle-id signature-size
  local ent="$OUT/$1.entitlements.plist"
  cat > "$ent" <<PLIST
<?xml version="1.0"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict>
<key>com.apple.application-identifier</key><string>$3.$4</string>
<key>com.apple.developer.team-identifier</key><string>$3</string>
<key>com.apple.developer.devicecheck.app-attest-opt-in</key><array><string>CDhash</string></array>
<key>keychain-access-groups</key><array><string>$3.*</string></array>
<key>com.apple.security.virtualization</key><true/>
</dict></plist>
PLIST
  ditto "$2" "$OUT/$1/Runner.app"
  rm -f "$OUT/$1/Runner.app/Contents/embedded.provisionprofile"
  codesign --force --sign "$(/usr/bin/openssl x509 -in "$OUT/$3.pem" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d :)" --keychain "$KC" \
    --options runtime --entitlements "$ent" --generate-entitlement-der --timestamp=none --signature-size "$5" "$OUT/$1/Runner.app"
  python3 "$ROOT/scripts/release/measure.py" "$OUT/$1/Runner.app/Contents/MacOS/runner" \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print(sys.argv[1], d["M"], d["cdhash"])' "$1" | tee -a "$OUT/summary.txt"
}
sign team-a "$1" TEAMAAAAAA org.example.alpha.runner 12000
sign team-b "$1" TEAMBBBBBB net.example.beta.runner 16000
sign modified "$2" TEAMAAAAAA org.example.alpha.runner 12000
python3 - "$OUT/summary.txt" "$OUT/m_runner.txt" <<'PY'
import sys
r = {n: (m, c) for n, m, c in (l.split() for l in open(sys.argv[1]))}
assert r['team-a'][0] == r['team-b'][0] != r['modified'][0], r
assert len({v[1] for v in r.values()}) == 3, r
print('runner measure-two-teams: pass, M_runner', r['team-a'][0])
open(sys.argv[2], 'w').write(r['team-a'][0].removeprefix('0x') + '\n')
PY
