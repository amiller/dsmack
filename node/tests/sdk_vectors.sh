#!/bin/bash
# SDKVectors in its three builds: -D SDK_TEST_TRUST (runner CDHashes from config); release mode with the fixture runner
# (5a..5a) compiled in, which also refuses config sdkRunners; release mode with the committed empty list, whose SDK refuses
# to start. usage: node/tests/sdk_vectors.sh <out dir>
set -euo pipefail
cd "$(dirname "$0")/../.."
out=$1; mkdir -p "$out/compiled"
shared=$(ls node/shared/*.swift | grep -v SDKRunners.swift)
sed 's/^let compiledSDKRunners: \[String\] = \[\]$/let compiledSDKRunners: [String] = ["'"$(printf '5a%.0s' {1..32})"'"]/' \
  node/shared/SDKRunners.swift > "$out/compiled/SDKRunners.swift"
build() { xcrun swiftc -framework DeviceCheck "${@:2}" $shared node/tests/SDKVectors.swift -o "$out/$1"; }
build test-trust -D SDK_TEST_TRUST node/shared/SDKRunners.swift
build release-compiled "$out/compiled/SDKRunners.swift"
build release-empty node/shared/SDKRunners.swift
for b in test-trust release-compiled release-empty; do echo "== $b"; "$out/$b" node/tests/sdk_runner_fixture.json; done
