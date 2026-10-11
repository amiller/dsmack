#!/bin/bash
# Usage: render.sh https://host/unguessable-path  → writes ./out ready to serve at that URL
set -euo pipefail
cd "$(dirname "$0")"; base=${1:?base URL}
rm -rf out; mkdir out; for v in honest modified; do cp ../$v/export/AppAttestLab.ipa out/$v.ipa; done
for f in index.html honest.plist modified.plist; do sed "s#__BASE_URL__#$base#g" $f > out/$f; done
