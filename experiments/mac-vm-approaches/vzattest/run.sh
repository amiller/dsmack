#!/bin/bash
# run.sh enroll|assert <capture-name>: launch the signed bundle via LaunchServices, as the 0916 rig did.
set -euo pipefail
cd "$(dirname "$0")"
mode=${1:?enroll|assert}; name=${2:?capture name}
out="$PWD/captures/$name"
[ -e "$out" ] && { echo "refusing to overwrite $out"; exit 1; }
mkdir -p "$out"
app="$PWD/build/VZAttest.app"
codesign --verify --strict "$app"
codesign -d --verbose=4 "$app" 2> "$out/codesign.txt"
cp "$app/Contents/MacOS/vzattest" "$out/vzattest"
cp build/entitlements-signed.plist compose.yaml "$out/"
head -c 32 /dev/urandom > "$out/challenge.bin"
open -n -W --stdout "$out/stdout.txt" --stderr "$out/stderr.txt" "$app" --args "$mode" "$out" "$PWD" "$out/challenge.bin" "$PWD/key.keyId.txt"
cat "$out/stderr.txt"
test -f "$out/done.txt"
ls "$out"
