#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
step=${1:?step name}
case "$step" in
  a-enroll) variant=honest; mode=enroll; key=a;;
  a-assert) variant=honest; mode=assert; key=a;;
  b-old-key) variant=modified; mode=assert; key=a;;
  b-enroll) variant=modified; mode=enroll; key=b;;
  b-assert) variant=modified; mode=assert; key=b;;
  a-restored) variant=honest; mode=assert; key=a;;
  *) exit 64;;
esac
out="$PWD/captures/$step"
if [ -e "$out" ]; then echo 'Refusing to overwrite a previous capture'; exit 1; fi
mkdir -p "$PWD/active" "$out"
app="$PWD/active/CodeBindingProbe.app"
ditto "build/$variant/CodeBindingProbe.app" "$app"
codesign --verify --strict "$app"
codesign -d --verbose=4 "$app" 2> "$out/codesign.txt"
cp "$app/Contents/MacOS/probe" "$out/probe"
cp "$app/Contents/Info.plist" "$out/Info.plist"
cp "build/$variant/entitlements.plist" "$out/entitlements.plist"
open -n -W "$app" --args "$mode" "$out" "$PWD/$step.challenge" "$PWD/$key.keyId.txt"
if [ -f "$out/error.txt" ]; then cat "$out/error.txt"; exit 1; fi
test -f "$out/done.txt"
cat "$out/runtime.json"
