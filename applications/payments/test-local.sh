#!/usr/bin/env bash
# Execute the receipt/contract boundary in Foundry's in-memory EVM; no RPC sends.
set -euo pipefail
[[ $# == 3 ]] || { echo 'usage: test-local.sh USAGE_ESCROW_SOL GUEST_INTEROP_JSON EVIDENCE_DIR' >&2; exit 2; }
source_file=$(realpath "$1")
interop=$(realpath "$2")
evidence=$(realpath "$3")
app=$(cd "$(dirname "$0")" && pwd)
scratch=$(mktemp -d "$evidence/evm.XXXXXX")
cleanup() {
  du -sb "$scratch" | awk '{print "retired local Foundry scratch bytes: " $1}' >> "$evidence/cleanup.log"
  rm -rf "$scratch"
}
trap cleanup EXIT
mkdir -p "$scratch/src" "$scratch/test"
cp "$source_file" "$scratch/src/UsageEscrow.sol"
cp "$app/loop.t.sol" "$scratch/test/Loop.t.sol"
cp "$interop" "$scratch/guest-interop.json"
cp "$(dirname "$interop")/compute-cutoff.json" "$(dirname "$interop")/compute-unused.json" "$scratch/"
cat > "$scratch/foundry.toml" <<'CONFIG'
[profile.default]
solc_version = "0.8.21"
optimizer = true
via_ir = true
remappings = ["usage/=src/"]
fs_permissions = [{ access = "read", path = "./" }]
CONFIG
forge test --root "$scratch" -vvvv > "$evidence/contract-loop.log" 2>&1
cat "$evidence/contract-loop.log"
