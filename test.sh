#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
python3 -m pytest -q tests
. app-attest/circuit/env.sh
forge test --root contracts --offline --use "$SOLC"
forge test --root app-attest/contracts --offline --use "$SOLC"
app-attest/circuit/prove-leaf.sh
python3 app-attest/circuit/negative-leaf.py
python3 app-attest/circuit/test-leaf.py
forge build --root app-attest/contracts/verifier --offline --use "$ATTEST_TOOLS/bin/solc-0.8.27"
FOUNDRY_PROFILE=real forge test --root app-attest/contracts --offline --use "$SOLC"
