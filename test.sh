#!/usr/bin/env bash
# ./test.sh [suite...]: install missing dependencies, then run every suite (or the named ones):
# python node private-agent-web go deno contracts. contracts needs ATTEST_TOOLS (CONTRIBUTING.md).
set -euo pipefail
cd "$(dirname "$0")"
WEB=applications/private-agent-web
# A test whose module graph reaches an npm:/jsr: specifier, or that calls Deno APIs, runs under deno; the rest under node.
deno_only() { for f; do grep -q 'Deno\.' "$f" || deno info -q --json "$f" | grep -q '"\(npm\|jsr\):' && echo "$f"; done; true; }
node_tests() { find applications dstack-compat \( -name node_modules -o -name primary-original -o -path applications/relay-broker -o -path applications/payments -o -path $WEB -o -path applications/operator-fleet/chain.test.mjs \) -prune -o \( -name '*.test.mjs' -o -name '*.test.cjs' -o -name 'test_*.mjs' \) -print; }

deps() {
    for d in applications/{browser-p2p,compute-node,private-agent-web}; do
        [ "$d/node_modules/.package-lock.json" -nt "$d/package-lock.json" ] || (cd "$d" && npm ci --no-audit --no-fund)
    done
    (cd $WEB && npx playwright install chromium firefox)
    deno cache applications/relay-broker/*.test.mjs applications/payments/payments.test.mjs applications/operator-fleet/chain.test.mjs $(deno_only $WEB/*.test.mjs $(node_tests))
}

suite_python() {
    # Same-named test modules live in different directories, so collect each separately.
    for d in tests tools base-vm runner-vm applications/{agent-turns,bounties,bounty-dashboard,browser-p2p,pilot-client,compute-node,libp2p-attest,mac-ownership} contracts/payments dstack-compat; do
        python3 -m pytest -q -p no:cacheprovider "$d"
    done
}

suite_node() {
    local deno=$(deno_only $(node_tests))
    node --test $(node_tests | grep -vxF -f <(echo "$deno"))
    deno test --allow-read --allow-write --allow-net --allow-env $deno
}

suite_private-agent-web() {
    python3 -m pytest -q -p no:cacheprovider $WEB/test_heartbeat_watch.py
    forge build --root contracts --offline contracts/src/PageBundleRegistry.sol   # trust-browser reads its ABI
    cd $WEB
    npm run build
    # boundary.test.mjs drives the built page through dev.py; artifacts.test.mjs crashes the headless shell, so full Chromium.
    python3 dev.py --port 18731 & trap "kill $!" EXIT
    sleep 1; kill -0 $!   # dev.py exits at once if the port is taken
    CHROMIUM_PATH=$(node -e "import('playwright').then(p => console.log(p.chromium.executablePath()))") \
        node --test --test-concurrency=1 $(ls *.test.mjs | grep -vxF -f <(deno_only *.test.mjs))
    deno test --allow-read --allow-write --allow-net --allow-env $(deno_only *.test.mjs)
}

suite_go() {
    for d in applications/{compute-node,egress-relay,libp2p-attest}/peer applications/{egress-policy,payments/guest}; do
        (cd "$d" && go test ./...)
    done
}

suite_deno() {
    deno test --allow-read --allow-write --allow-net --allow-env applications/relay-broker applications/payments/payments.test.mjs applications/operator-fleet/chain.test.mjs
}

suite_contracts() {
    . app-attest/circuit/env.sh
    forge test --root contracts --offline --use "$SOLC"
    forge test --root contracts/work-escrow --offline --use "$SOLC"
    forge test --root app-attest/contracts --offline --use "$SOLC"
    app-attest/circuit/prove-leaf.sh
    forge build --root app-attest/contracts/verifier --offline --use "$ATTEST_TOOLS/bin/solc-0.8.27"
    FOUNDRY_PROFILE=real forge test --root app-attest/contracts --offline --use "$SOLC"
}

[ $# -gt 0 ] || set -- python node private-agent-web go deno contracts
for s in "$@"; do declare -F "suite_$s" >/dev/null || { echo "unknown suite $s" >&2; exit 2; }; done
deps
for s in "$@"; do ( "suite_$s" ); done
