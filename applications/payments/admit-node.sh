#!/usr/bin/env bash
set -euo pipefail
[[ $# == 1 ]] || { echo 'usage: bash admit-node.sh /path/to/payments/funding-wallet.key' >&2; exit 2; }
root=$(cd "$(dirname "$0")" && pwd)
exec deno run --allow-read --allow-net --allow-env "$root/admit-node.mjs" "$1"
