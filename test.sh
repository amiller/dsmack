#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
# Same-named test modules live in different directories, so collect each separately.
for d in tests tools base-vm runner-vm applications/{agent-turns,bounties,bounty-dashboard,browser-p2p,pilot-client,compute-node,libp2p-attest,mac-ownership} contracts/payments dstack-compat; do
    python3 -m pytest -q -p no:cacheprovider "$d"
done
python3 -m pytest -q -p no:cacheprovider applications/private-agent-web/test_heartbeat_watch.py
node --test $(find applications dstack-compat \( -name node_modules -o -name primary-original -o -path applications/relay-broker -o -path applications/payments -o -path applications/private-agent-web -o -path applications/operator-fleet/chain.test.mjs \) -prune -o \( -name '*.test.mjs' -o -name '*.test.cjs' -o -name 'test_*.mjs' \) -print)
for d in applications/{compute-node,egress-relay,libp2p-attest}/peer applications/{egress-policy,payments/guest}; do
    (cd "$d" && go test ./...)
done
deno test --allow-read --allow-write --allow-net --allow-env applications/relay-broker applications/payments/payments.test.mjs applications/operator-fleet/chain.test.mjs applications/private-agent-web/{chain-directory,directory-health}.test.mjs
. app-attest/circuit/env.sh
forge test --root contracts --offline --use "$SOLC"
forge test --root contracts/work-escrow --offline --use "$SOLC"
forge test --root app-attest/contracts --offline --use "$SOLC"
app-attest/circuit/prove-leaf.sh
forge build --root app-attest/contracts/verifier --offline --use "$ATTEST_TOOLS/bin/solc-0.8.27"
FOUNDRY_PROFILE=real forge test --root app-attest/contracts --offline --use "$SOLC"
