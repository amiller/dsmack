#!/bin/bash
# Usage: run.sh <fresh-work-dir>. Needs a Mac with a Secure Enclave and the build-app.sh signing variables.
# Leaves one permanent synthetic SEP key (unique tag) in the data-protection keychain, as the recorded run did.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
work=${1:?fresh work directory}
mkdir -m 700 "$work"
work=$(cd "$work" && pwd)

# 1. Wrapped CryptoKit blob: ad hoc binaries A and B with different CDHashes.
xcrun swiftc "$here/wrapped-blob.swift" -o "$work/A"
xcrun swiftc -D VARIANT_B "$here/wrapped-blob.swift" -o "$work/B"
codesign --force --sign - "$work/A"
codesign --force --sign - "$work/B"
codesign -d --verbose=4 "$work/A" 2>&1 | grep '^CDHash='
codesign -d --verbose=4 "$work/B" 2>&1 | grep '^CDHash='
mkdir -m 700 "$work/state"
"$work/A" create "$work/state"
"$work/B" reopen "$work/state"

# 2. Persistent Security-framework SEP key: signed A creates, signed modified B looks it up and signs.
tag="dsmack.synthetic.sep-caller.$(date -u +%Y%m%dT%H%M%SZ)"
"$here/../build-app.sh" "$work/honest" "$here/persistent-sep.swift"
"$here/../build-app.sh" "$work/modified" -D MODIFIED "$here/persistent-sep.swift"
mkdir "$work/capture-honest" "$work/capture-modified"
"$work/honest/CodeBindingProbe.app/Contents/MacOS/probe" "$work/capture-honest" "$tag"
"$work/modified/CodeBindingProbe.app/Contents/MacOS/probe" "$work/capture-modified" "$tag"
grep '^CDHash=' "$work/honest/codesign.txt" "$work/modified/codesign.txt"
cat "$work/capture-honest/signature.json" "$work/capture-modified/signature.json" "$work/capture-honest/legacy-combination.json"
