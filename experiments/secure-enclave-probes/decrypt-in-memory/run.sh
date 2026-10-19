#!/bin/bash
# Usage: run.sh <fresh-work-dir>. Mac with a Secure Enclave (macOS 26+ for ML-KEM/ML-DSA); ad hoc signing.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
work=${1:?fresh work directory}
mkdir -m 700 "$work" "$work/run-contract" "$work/run-auction" "$work/run-seckey"
work=$(cd "$work" && pwd)
for n in se_contract_probe se_auction_envelope_probe seckey_ecies_probe; do
  xcrun swiftc -O -parse-as-library -sdk "$(xcrun --show-sdk-path)" -target arm64-apple-macos27.0 "$here/$n.swift" -o "$work/$n"
done
cd "$work/run-contract"
../se_contract_probe full
../se_contract_probe reuse
../se_contract_probe cleanup
cd "$work/run-auction"
for mode in gen-bidder gen-auctioneer exchange-bidder exchange-auctioneer cleanup; do ../se_auction_envelope_probe "$mode"; done
cd "$work/run-seckey"
../seckey_ecies_probe
