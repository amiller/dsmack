#!/bin/bash
# Laptop side: copy the three Mac builds from the mini into <out>/builds and write CDRegistry args
# (contracts/network/cd-args-macos.json = honest; contracts/fixtures/resign/node-*.json for the unit test).
set -euo pipefail
cd "$(dirname "$0")/../.."
out=${1:?run dir}
for v in honest resigned modified; do
  mkdir -p "$out/builds/$v"
  scp -q "mini-mesh:apple-attest-p2p/node/mac/build/$v/Node.app/Contents/MacOS/node" "mini-mesh:apple-attest-p2p/node/mac/build/$v/codesign.txt" "$out/builds/$v/"
  python3 scripts/cd_args.py "$out/builds/$v/node" > "$out/builds/$v/cd-args.json"
  cp "$out/builds/$v/cd-args.json" "contracts/fixtures/resign/node-$v.json"
done
cp "$out/builds/honest/cd-args.json" contracts/network/cd-args-macos.json
grep -h cdhash "$out"/builds/*/cd-args.json
