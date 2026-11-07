#!/bin/bash
# Rehearse LAYC issuance on an anvil fork of Base mainnet: IssuanceLaunch, one day, advance, a minion-signed book and two
# paid units, the refusals (duplicate, operator cap, foreign signature, early advance, non-controller), then the controller
# (CONTROLLER, impersonated) upgrades to a fresh implementation, renounces upgrades, and a further upgrade is refused.
# usage: BASE_RPC=https://... contracts/script/issuance-fork.sh [block]   (from the repository root; forge/anvil/cast on PATH)
set -euo pipefail
cd "$(dirname "$0")/.."
: "${BASE_RPC:?Base mainnet RPC}"
BLOCK=${1:-$(cast block-number --rpc-url "$BASE_RPC")}
PORT=${PORT:-8548}; RPC=http://127.0.0.1:$PORT
anvil --fork-url "$BASE_RPC" --fork-block-number "$BLOCK" --port "$PORT" --silent &
ANVIL=$!; trap 'kill $ANVIL' EXIT
until cast chain-id --rpc-url $RPC >/dev/null 2>&1; do sleep 1; done
DEPLOYER_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
export CONTROLLER=${CONTROLLER:-0x55A07f257d07986026dD6e39488954C5aCD2cd5D} MINION=0x14dC79964da2C08b23698B3D3cc7Ca32193d9955
echo "fork of Base mainnet at block $BLOCK; controller $CONTROLLER minion $MINION (anvil 7)"

forge script script/IssuanceLaunch.s.sol --force --rpc-url $RPC --broadcast --private-key $DEPLOYER_KEY --slow
OUT=broadcast/IssuanceLaunch.s.sol/8453/run-latest.json
export LRB=$(jq -r '[.transactions[] | select(.contractName == "ERC1967Proxy")][0].contractAddress' $OUT)
LAYC=$(cast call --rpc-url $RPC $LRB 'token()(address)')
echo "LAYC $LAYC owner $(cast call --rpc-url $RPC $LAYC 'owner()(address)') totalSupply $(cast call --rpc-url $RPC $LAYC 'totalSupply()(uint256)')"

cast rpc --rpc-url $RPC evm_increaseTime 86400 >/dev/null && cast rpc --rpc-url $RPC evm_mine >/dev/null
forge script script/IssuanceSmoke.s.sol --sig 'pay()' --rpc-url $RPC --broadcast --slow
forge script script/IssuanceSmoke.s.sol --sig 'refusals()' --rpc-url $RPC

NEW=$(forge script script/IssuanceSmoke.s.sol --sig 'newImpl()' --rpc-url $RPC --broadcast --slow | awk '/NEW_IMPL/ {print $2}')
IMPL_SLOT=0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
echo "implementation before: $(cast storage --rpc-url $RPC $LRB $IMPL_SLOT)"
cast rpc --rpc-url $RPC anvil_impersonateAccount $CONTROLLER >/dev/null
cast rpc --rpc-url $RPC anvil_setBalance $CONTROLLER 0x16345785D8A0000 >/dev/null
csend() { local h=$(cast send --rpc-url $RPC --unlocked --from $CONTROLLER --async "$@")
  [ "$(cast receipt --rpc-url $RPC "$h" --json | jq -r .status)" = 0x1 ] || { echo "controller $2 failed: $h" >&2; exit 1; }
  echo "controller $2: $h gas $(cast receipt --rpc-url $RPC $h gasUsed)"; }
csend $LRB 'upgradeTo(address)' $NEW
echo "implementation after:  $(cast storage --rpc-url $RPC $LRB $IMPL_SLOT) (new $NEW)"
echo "state kept: paid(unit-1) $(cast call --rpc-url $RPC $LRB 'paid(bytes32)(bool)' $(cast format-bytes32-string unit-1)), totalSupply $(cast call --rpc-url $RPC $LAYC 'totalSupply()(uint256)')"
csend $LRB 'renounceUpgrades()'
if out=$(cast call --rpc-url $RPC --from $CONTROLLER $LRB 'upgradeTo(address)' $NEW 2>&1); then echo "upgrade after renounce went through" >&2; exit 1; fi
echo "refused: upgrade after renounce ($(grep -o 'upgrades renounced' <<<"$out"))"
[ "$(grep -c 'upgrades renounced' <<<"$out")" -ge 1 ]
echo "upgradesRenounced $(cast call --rpc-url $RPC $LRB 'upgradesRenounced()(bool)'); LAYC owner $(cast call --rpc-url $RPC $LAYC 'owner()(address)')"
