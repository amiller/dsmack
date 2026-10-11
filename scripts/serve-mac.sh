#!/bin/bash
# Use OpenSSL 3 rather than macOS's default LibreSSL.
set -euo pipefail
lab_root=$(cd "$(dirname "$0")/.." && pwd)
for lab_ssl in /opt/homebrew/opt/openssl@3/bin /usr/local/opt/openssl@3/bin; do
  if [[ -x "$lab_ssl/openssl" ]]; then export PATH="$lab_ssl:$PATH"; break; fi
done
cd "$lab_root"
exec .venv/bin/python -m verifier.server "$@"
