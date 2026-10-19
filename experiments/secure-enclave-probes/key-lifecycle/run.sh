#!/bin/bash
# Usage: run.sh <fresh-work-dir>. Mac with a Secure Enclave; the SecKey part also needs the build-app.sh signing variables.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
work=${1:?fresh work directory}
mkdir -m 700 "$work"
work=$(cd "$work" && pwd)

# 1. CryptoKit receiving key: does process exit revoke a captured wrapped blob? Does a changed binary matter?
xcrun swiftc "$here/sep-lifecycle-probe.swift" -o "$work/probe"
{ cat "$here/sep-lifecycle-probe.swift"; echo 'print("changed_code_variant=true")'; } > "$work/variant.swift"
xcrun swiftc "$work/variant.swift" -o "$work/variant"
codesign --force --sign - "$work/probe"
codesign --force --sign - "$work/variant"
"$work/probe" capture "$work/captured-record"
"$work/probe" restore "$work/captured-record"
"$work/variant" restore "$work/captured-record"
"$work/probe" memory-only "$work/unpersisted-record"
if "$work/probe" restore "$work/unpersisted-record"; then echo 'memory-only restore unexpectedly succeeded'; exit 1; fi

# 2. Security-framework SEP key: does SecItemDelete or a nonpersistent key end use of a captured token reference?
"$here/../build-app.sh" "$work/seckey" "$here/seckey-delete-probe.swift"
p="$work/seckey/CodeBindingProbe.app/Contents/MacOS/probe"
d="$work/delete-$(openssl rand -hex 6)"
"$p" create "$d"
"$p" hold "$d" > "$work/hold.log" &
holder=$!
until [ -f "$d/holder-ready" ]; do kill -0 "$holder"; sleep 0.1; done
"$p" delete "$d"
wait "$holder"
cat "$work/hold.log"
"$p" reopen "$d"
"$p" tokenrestore "$d"
t="$work/transient-$(openssl rand -hex 6)"
"$p" transient "$t"
"$p" tokenrestore "$t"
