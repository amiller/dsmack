#!/bin/bash
# Rehearse the Base mainnet launch on an anvil fork: deploy (MainnetLaunch), the owner transactions (setBuild as BUILD_OWNER),
# the permissionless registerBuild and both App Attest enrolls of the Mini's key, then the escrow smoke (MainnetSmoke).
# Owners are anvil dev accounts standing in for the Safes. Prints every transaction's gas and its cost at the fork block's fees.
# usage: BASE_RPC=https://... contracts/script/mainnet-fork.sh [block]   (from the repository root; forge/anvil/cast on PATH)
set -euo pipefail
cd "$(dirname "$0")/.."
: "${BASE_RPC:?Base mainnet RPC}"
BLOCK=${1:-$(cast block-number --rpc-url "$BASE_RPC")}
PORT=${PORT:-8547}; RPC=http://127.0.0.1:$PORT
anvil --fork-url "$BASE_RPC" --fork-block-number "$BLOCK" --port "$PORT" --silent &
ANVIL=$!; trap 'kill $ANVIL' EXIT
until cast chain-id --rpc-url $RPC >/dev/null 2>&1; do sleep 1; done
acct() { cast wallet address --mnemonic "test test test test test test test test test test test junk" --mnemonic-index "$1"; }
DEPLOYER_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
export BUILD_OWNER=$(acct 1) ESCROW_OWNER=$(acct 2) MINT_OWNER=$(acct 3) USAGE_OWNER=$(acct 6) GENESIS=${GENESIS:-25000000000}
echo "fork of Base mainnet at block $BLOCK; owners build=$BUILD_OWNER escrow=$ESCROW_OWNER mint=$MINT_OWNER usage=$USAGE_OWNER genesis=$GENESIS"

forge script script/MainnetLaunch.s.sol --force --rpc-url $RPC --broadcast --private-key $DEPLOYER_KEY --gas-estimate-multiplier 105 --slow
OUT=broadcast/MainnetLaunch.s.sol/8453/run-latest.json
addr() { jq -r --arg n "$1" --argjson i "${2:-0}" '[.transactions[] | select(.contractName == $n and .transactionType == "CREATE")][$i].contractAddress' $OUT; }
CDS=$(addr CDRegistry) DIRECTORY=$(addr AppleAttestRegistryV1 0) VERIFIER=$(addr AppleAttestRegistryV1 1)
export LAYC=$(addr LayoverCredit) GUEST_ESCROW=$(addr GuestEscrow)

TXS=$(mktemp)
log() { jq -r --arg p "$2" '.transactions[] | "\($p)\(.contractName // "-") \(.function // "constructor")\t\(.hash)"' "$1" >> $TXS; }
log $OUT ""
send() { local what=$1 from=$2 to=$3 data=$4
  local h=$(cast send --rpc-url $RPC --unlocked --from "$from" --gas-limit 16000000 --async "$to" "$data")
  [ "$(cast receipt --rpc-url $RPC "$h" --json | jq -r .status)" = 0x1 ] || { echo "$what failed: $h" >&2; exit 1; }
  printf '%s\t%s\n' "$what" "$h" >> $TXS; }
cast rpc --rpc-url $RPC anvil_impersonateAccount $BUILD_OWNER >/dev/null
send "CDRegistry setBuild(BUILD_OWNER)" $BUILD_OWNER $CDS "$(cat fixtures/mainnet/setBuild-runner.calldata)"
send "CDRegistry registerBuild(0c3d3c90)" $(acct 0) $CDS "$(cat fixtures/mainnet/registerBuild-0c3d3c90.calldata)"
send "CDRegistry registerBuild(b98b6aba)" $(acct 0) $CDS "$(cat fixtures/mainnet/registerBuild-b98b6aba.calldata)"
send "directory enroll(e3a6e561)" $(acct 0) $DIRECTORY "$(cat fixtures/mainnet/enroll-e3a6e561.calldata)"
send "verifier enroll(e3a6e561)" $(acct 0) $VERIFIER "$(cat fixtures/mainnet/enroll-e3a6e561.calldata)"
for r in $DIRECTORY $VERIFIER; do
  cast call --rpc-url $RPC $r 'keys(bytes32)(uint256,uint256,uint64,uint32,bool)' 0xe3a6e5614999084a848e3eed83b3f2a91193c1ce6100d9eb806a557922a93046 | tail -3 | tr '\n' ' '; echo " <- keys(e3a6e561) expires, counter, enrolled on $r"
done

forge script script/MainnetSmoke.s.sol --sig 'open()' --rpc-url $RPC --broadcast --slow
SOUT=broadcast/MainnetSmoke.s.sol/8453/open-latest.json
export STUB_ESCROW=$(jq -r '[.transactions[] | select(.contractName == "GuestEscrow")][0].contractAddress' $SOUT)
cast rpc --rpc-url $RPC evm_increaseTime 86401 >/dev/null && cast rpc --rpc-url $RPC evm_mine >/dev/null
forge script script/MainnetSmoke.s.sol --sig 'settle()' --rpc-url $RPC --broadcast --slow
log $SOUT "smoke open: "; log broadcast/MainnetSmoke.s.sol/8453/settle-latest.json "smoke settle: "

# Cost at the fork block: L2 gas x (base fee + 0.001 gwei priority) plus the L1 data fee upper bound for the signed size.
BASEFEE=$(cast base-fee --rpc-url "$BASE_RPC" $BLOCK) PRIO=1000000
echo; echo "Base mainnet block $BLOCK: base fee $BASEFEE wei, priority $PRIO wei"
printf '%-58s %11s %8s %16s %16s\n' transaction gas bytes "L2 fee (ETH)" "L1 fee (ETH)"
while IFS=$'\t' read -r what h; do
  gas=$(cast receipt --rpc-url $RPC $h gasUsed); size=$(( $(cast tx --rpc-url $RPC $h input | wc -c) / 2 + 110 ))
  l1=$(cast call --rpc-url "$BASE_RPC" --block $BLOCK 0x420000000000000000000000000000000000000F 'getL1FeeUpperBound(uint256)(uint256)' $size | cut -d' ' -f1)
  printf '%-58s %11s %8s %16s %16s\n' "$what ${h:0:10}" $gas $size $(cast from-wei $(( gas * (BASEFEE + PRIO) ))) $(cast from-wei $l1)
done < $TXS
echo; echo "addresses:"; jq -r '.transactions[] | select(.transactionType == "CREATE") | "\(.contractName) \(.contractAddress)"' $OUT
echo "stub GuestEscrow $STUB_ESCROW"
