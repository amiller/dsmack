#!/usr/bin/env bash
# Deploy from the Base Sepolia sprint funding wallet.
set -euo pipefail
[[ $# == 3 ]] || { echo 'usage: bash deploy-and-fund.sh FUNDING_WALLET_KEY PAYMENTS_DIR TOKEN_ADDRESS' >&2; exit 2; }
here=$(cd "$(dirname "$0")" && pwd)
exec python3 "$here/deploy.py" "$1" "$2" "$3"
