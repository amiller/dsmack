#!/bin/bash
# Build the CLI node from two checkout paths under two throwaway teams, plus a MODIFIED build;
# sign each with a fresh self-signed identity and compare measurements.
# macOS LibreSSL (/usr/bin/openssl) writes PKCS#12 that security(1) can import; OpenSSL 3 does not.
# Usage: scripts/release/measure_two_teams.sh OUT_DIR   (OUT_DIR must not exist)
set -euo pipefail
ROOT=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
mkdir -p "$(dirname "$1")" && mkdir "$1"
OUT=$(cd "$1" && pwd)
KC="$OUT/throwaway.keychain-db"
trap 'security delete-keychain "$KC" 2>/dev/null || true' EXIT

security create-keychain -p throwaway "$KC"
security set-keychain-settings -t 3600 "$KC"
security unlock-keychain -p throwaway "$KC"
printf '[req]\ndistinguished_name=dn\n[dn]\n[ext]\nbasicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,codeSigning\n' > "$OUT/cert.cnf"
for team in TEAMAAAAAA TEAMBBBBBB; do
  /usr/bin/openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout "$OUT/$team.key" -out "$OUT/$team.pem" \
    -subj "/CN=Throwaway $team/OU=$team/O=Throwaway" -config "$OUT/cert.cnf" -extensions ext 2>/dev/null
  /usr/bin/openssl pkcs12 -export -inkey "$OUT/$team.key" -in "$OUT/$team.pem" -out "$OUT/$team.p12" -passout pass:throwaway
  security import "$OUT/$team.p12" -k "$KC" -P throwaway -T /usr/bin/codesign >/dev/null
  rm "$OUT/$team.key" "$OUT/$team.p12"
done
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k throwaway "$KC" >/dev/null

git clone --quiet --no-hardlinks "$ROOT" "$OUT/src/a"
git clone --quiet --no-hardlinks "$ROOT" "$OUT/src/b-checkout-at-a-deliberately-different-length-path"
build() { python3 "$1/scripts/release/build_mac.py" --out "$OUT/build/$2" --team "$3" --bundle-id "$4" "${@:5}" >/dev/null; }
# Every build compiles in one runner measurement; other-runner differs only in that compiled-in M_runner, so it must move M.
R1=$(printf 'a%.0s' {1..64}); R2=$(printf 'b%.0s' {1..64})
build "$OUT/src/a" honest-a TEAMAAAAAA org.example.alpha.node --sdk-runner "$R1"
build "$OUT/src/b-checkout-at-a-deliberately-different-length-path" honest-b TEAMBBBBBB net.example.beta.peer --sdk-runner "$R1"
build "$OUT/src/a" modified TEAMAAAAAA org.example.alpha.node --sdk-runner "$R1" --modified
build "$OUT/src/a" other-runner TEAMAAAAAA org.example.alpha.node --sdk-runner "$R2"
cmp "$OUT/build/honest-a/Node.app/Contents/MacOS/node" "$OUT/build/honest-b/Node.app/Contents/MacOS/node"
echo "unsigned executables identical: $(shasum -a 256 "$OUT/build/honest-a/Node.app/Contents/MacOS/node" | cut -d' ' -f1)"

sign() {  # name team signature-size
  local identity
  identity=$(/usr/bin/openssl x509 -in "$OUT/$2.pem" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d :)
  ditto "$OUT/build/$1/Node.app" "$OUT/signed/$1/Node.app"
  codesign --sign "$identity" --keychain "$KC" --team-identifier "$2" --options runtime \
    --entitlements "$OUT/build/$1/entitlements.plist" --generate-entitlement-der \
    --timestamp=none --signature-size "$3" "$OUT/signed/$1/Node.app"
  codesign --verify --strict "$OUT/signed/$1/Node.app"
}
sign honest-a TEAMAAAAAA 12000
sign honest-b TEAMBBBBBB 16000
sign modified TEAMAAAAAA 12000
sign other-runner TEAMAAAAAA 12000

exe() { echo "$1=$OUT/signed/$1/Node.app/Contents/MacOS/node"; }
python3 "$ROOT/scripts/release/measure_two_teams.py" --out "$OUT/vectors" "$(exe honest-a)" "$(exe honest-b)" "$(exe modified)" "$(exe other-runner)"
xcrun swiftc "$ROOT/node/shared/Protocol.swift" "$ROOT/node/shared/Measure.swift" "$ROOT/node/tests/MeasureVectors.swift" -o "$OUT/measure-vectors"
for n in honest-a honest-b modified other-runner; do
  swift=$("$OUT/measure-vectors" --file "$OUT/signed/$n/Node.app/Contents/MacOS/node" | python3 -c 'import json,sys; print(json.load(sys.stdin)["M"])')
  python=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["M"])' "$OUT/vectors/$n.json")
  [ "$swift" = "$python" ] || { echo "Swift M $swift != Python M $python for $n"; exit 1; }
done
echo "Swift and Python M agree"
