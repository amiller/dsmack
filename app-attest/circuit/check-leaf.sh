#!/usr/bin/env bash
set -euo pipefail
fixture=$(realpath "$1")
cd "$(dirname "$0")"
. ./env.sh
python3 check-versions.py
run="$PWD/../../tools/attest-build/leaf"
mkdir -p "$run"
exec 9>"$run/.check.lock"
flock 9
rm -rf "$run/core" "$run/leaf"
cp -r core leaf "$run/"
printf '[workspace]\nmembers = ["leaf"]\n' > "$run/Nargo.toml"
python3 prepare-leaf.py "$fixture" --out "$run/leaf/Prover.toml"
cd "$run"
status=0
nargo execute --package attest_leaf attest_leaf || status=$?
python3 "$LANE_Z_ROOT/app-attest/circuit/fingerprint.py" "$run"
exit "$status"
