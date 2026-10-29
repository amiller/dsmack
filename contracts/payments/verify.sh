#!/usr/bin/env bash
set -euo pipefail
[[ $# == 1 && $1 =~ ^0x[0-9a-fA-F]{40}$ ]] || { echo 'usage: bash verify.sh CONTRACT_ADDRESS' >&2; exit 2; }
contracts=$(cd "$(dirname "$0")/.." && pwd)
# Foundry reads the API key from the environment; no key appears in argv or logs.
export ETHERSCAN_API_KEY
ETHERSCAN_API_KEY=$(cat "$HOME/.config/basescan/api-key")
owner=0x1FBe7a7b3f7a37A967F3d927Abd6f04DB2766c5b
args=$(cast abi-encode 'constructor(address)' "$owner")
exec forge verify-contract --root "$contracts" --chain 84532 --watch \
  --verifier-url 'https://api.etherscan.io/v2/api?chainid=84532' \
  --constructor-args "$args" "$1" src/UsageEscrow.sol:UsageEscrow
