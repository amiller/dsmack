#!/bin/bash
# Usage: run.sh <fresh-work-dir>. Mac with App Attest and the build-app.sh signing variables (runner-attest part);
# the quote-helper part needs only Xcode command line tools.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
work=${1:?fresh work directory}
mkdir -m 700 "$work"
work=$(cd "$work" && pwd)

# 1. Runner /attest: an unrelated host process asks the approved app to assert host-chosen operation bytes.
"$here/../build-app.sh" "$work/runner-attest" "$here/runner-attest/Probe.swift"
mkdir "$work/capture"
open -n "$work/runner-attest/CodeBindingProbe.app" --args "$work/capture"
c="$work/capture"
until [ -f "$c/ready.txt" ] || [ -f "$c/error.txt" ]; do sleep 0.2; done
test -f "$c/ready.txt"
nc -U "$work/capture/deputy.sock" < "$here/runner-attest/host-request.http" > "$work/capture/host-response.http"
until [ -f "$c/done.txt" ] || [ -f "$c/error.txt" ]; do sleep 0.2; done
test -f "$c/done.txt"
python3 -c 'import json,base64,sys; r=json.load(open(sys.argv[1])); print(base64.b64decode(r["assertClientData"]).decode())' \
  "$work/capture/response.json"

# 2. QuoteHelper: a caller-selected "node" executable receives the NEAR key on stdin.
mkdir "$work/quote-helper"
xcrun swiftc -parse-as-library "$here/quote-helper/Probe.swift" -o "$work/quote-helper/Probe"
"$work/quote-helper/Probe" "$work/quote-helper"
