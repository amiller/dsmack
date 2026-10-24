#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
# Same-named test modules live in different directories, so collect each separately.
for d in tests tools base-vm runner-vm applications/{bounties,bounty-dashboard,pilot-client}; do
    python3 -m pytest -q -p no:cacheprovider "$d"
done
node --test $(find applications -name node_modules -prune -o -name primary-original -prune -o \( -name '*.test.mjs' -o -name '*.test.cjs' -o -name 'test_*.mjs' \) -print)
. app-attest/circuit/env.sh
forge test --root contracts --offline --use "$SOLC"
forge test --root contracts/work-escrow --offline --use "$SOLC"
forge test --root app-attest/contracts --offline --use "$SOLC"
app-attest/circuit/prove-leaf.sh
python3 app-attest/circuit/negative-leaf.py
python3 app-attest/circuit/test-leaf.py
forge build --root app-attest/contracts/verifier --offline --use "$ATTEST_TOOLS/bin/solc-0.8.27"
FOUNDRY_PROFILE=real forge test --root app-attest/contracts --offline --use "$SOLC"
