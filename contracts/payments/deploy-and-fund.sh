#!/usr/bin/env bash
# Andrew runs this locally; the raw key is read only inside the signing process.
set -euo pipefail
[[ $# -ge 1 && $# -le 2 ]] || { echo 'usage: bash deploy-and-fund.sh RAW_OWNER_KEY_FILE [PAYMENTS_DIR]' >&2; exit 2; }
here=$(cd "$(dirname "$0")" && pwd)
exec python3 "$here/deploy.py" "$1" "${2:-local-data/payments-20261028}"
