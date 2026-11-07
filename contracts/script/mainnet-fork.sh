#!/bin/bash
# Rehearse the Base mainnet launch on an anvil fork, as OWNER (impersonated; no key needed): IssuanceLaunch (the issuance
# lane) deploys LAYC with no supply and LastResortBuyer as its sole minter, MainnetLaunch deploys the rest, OWNER sends
# setBuild, anyone sends registerBuild and both App Attest enrolls of the Mini's key, MainnetLP seeds the USDC bid, then a
# day later MainnetSmoke runs the economy end to end. Prints every transaction's gas and its cost at the fork's fees.
# usage: BASE_RPC=https://... OWNER=0x... contracts/script/mainnet-fork.sh [block]   (forge/anvil/cast/jq on PATH)
set -euo pipefail
cd "$(dirname "$0")/.."
: "${BASE_RPC:?Base mainnet RPC}" "${OWNER:?owner address}"
BLOCK=${1:-$(cast block-number --rpc-url "$BASE_RPC")}
PORT=${PORT:-8547}; RPC=http://127.0.0.1:$PORT
anvil --fork-url "$BASE_RPC" --fork-block-number "$BLOCK" --port "$PORT" --compute-units-per-second 10 --silent &
ANVIL=$!; trap 'kill $ANVIL' EXIT
until cast chain-id --rpc-url $RPC >/dev/null 2>&1; do
  kill -0 "$ANVIL" 2>/dev/null || { echo "anvil failed to start" >&2; exit 1; }
  sleep 1
done
acct() { cast wallet address --mnemonic "test test test test test test test test test test test junk" --mnemonic-index "$1"; }
USDC=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 LP_USDC=${LP_USDC:-300000000}
export OWNER LP_USDC
cast rpc --rpc-url $RPC anvil_impersonateAccount $OWNER >/dev/null
echo "fork of Base mainnet at block $BLOCK; owner $OWNER holds $(cast balance --rpc-url $RPC --ether $OWNER) ETH"

TXS=$(mktemp)
log() { jq -r --arg p "$2" '.transactions[] | "\($p)\(.contractName // "-") \(.function // "constructor")\t\(.hash)"' "$1" >> $TXS; }
send() { local what=$1 from=$2 to=$3 data=$4
  local h=$(cast send --rpc-url $RPC --unlocked --from "$from" --gas-limit 16000000 --async "$to" "$data")
  [ "$(cast receipt --rpc-url $RPC "$h" --json | jq -r .status)" = 0x1 ] || { echo "$what failed: $h" >&2; exit 1; }
  printf '%s\t%s\n' "$what" "$h" >> $TXS; }

forge build --force >/dev/null
# The KMS root is a test key (Minions.KMS_PK = 0x6B35 in test/LastResortBuyer.t.sol) so the smoke can sign a minion's chain.
KMS_ROOT_UNCHECKED=1 CONTROLLER=$OWNER KMS_ROOT=$(cast wallet address --private-key 0x$(printf "%064x" 0x6B35)) forge script script/IssuanceLaunch.s.sol --rpc-url $RPC --broadcast --unlocked --sender $OWNER --slow
IOUT=broadcast/IssuanceLaunch.s.sol/8453/run-latest.json
export LAYC=$(jq -r '[.transactions[] | select(.contractName == "LayoverCredit")][0].contractAddress' $IOUT)
export LRB=$(jq -r '[.transactions[] | select(.contractName == "ERC1967Proxy")][0].contractAddress' $IOUT)
echo "LayoverCredit $LAYC owner $(cast call --rpc-url $RPC $LAYC 'owner()(address)') totalSupply $(cast call --rpc-url $RPC $LAYC 'totalSupply()(uint256)'); LastResortBuyer proxy $LRB"
log $IOUT "issuance: "

forge script script/MainnetLaunch.s.sol --rpc-url $RPC --broadcast --unlocked --sender $OWNER --gas-estimate-multiplier 105 --slow
OUT=broadcast/MainnetLaunch.s.sol/8453/run-latest.json
addr() { jq -r --arg n "$1" --argjson i "${2:-0}" '[.transactions[] | select(.contractName == $n and .transactionType == "CREATE")][$i].contractAddress' $OUT; }
CDS=$(addr CDRegistry) DIRECTORY=$(addr AppleAttestAnyBuildV1 0) VERIFIER=$(addr AppleAttestRegistryV1 0)
export GUEST_ESCROW=$(addr GuestEscrow)
log $OUT "launch: "

send "CDRegistry setBuild (OWNER)" $OWNER $CDS "$(cat fixtures/mainnet/setBuild-runner.calldata)"
send "CDRegistry registerBuild(0c3d3c90)" $(acct 0) $CDS "$(cat fixtures/mainnet/registerBuild-0c3d3c90.calldata)"
send "CDRegistry registerBuild(b98b6aba)" $(acct 0) $CDS "$(cat fixtures/mainnet/registerBuild-b98b6aba.calldata)"
send "directory enroll(e3a6e561)" $(acct 0) $DIRECTORY "$(cat fixtures/mainnet/enroll-e3a6e561.calldata)"
send "verifier enroll(e3a6e561)" $(acct 0) $VERIFIER "$(cat fixtures/mainnet/enroll-e3a6e561.calldata)"
for r in $DIRECTORY $VERIFIER; do
  cast call --rpc-url $RPC $r 'keys(bytes32)(uint256,uint256,uint64,uint32,bool)' 0xe3a6e5614999084a848e3eed83b3f2a91193c1ce6100d9eb806a557922a93046 | tail -3 | tr '\n' ' '; echo " <- keys(e3a6e561) expires, counter, enrolled on $r"
done

# No real guest assertion exists for mainnet yet: GuestEscrow's verifier becomes MockGuestAttest bound to the same escrow.
MOCK=$(forge create test/GuestEscrow.t.sol:MockGuestAttest --rpc-url $RPC --unlocked --from $(acct 0) --broadcast --json --constructor-args $GUEST_ESCROW | jq -r .deployedTo)
cast rpc --rpc-url $RPC anvil_setCode $VERIFIER $(cast code --rpc-url $RPC $MOCK) >/dev/null

# USDC for the owner (the LP seed) and the buyer: FiatToken balances are mapping slot 9.
for a in "$OWNER $LP_USDC" "$(acct 4) 10000000"; do set -- $a
  cast rpc --rpc-url $RPC anvil_setStorageAt $USDC $(cast index address $1 9) $(cast to-uint256 $2) >/dev/null
  echo "USDC $(cast call --rpc-url $RPC $USDC 'balanceOf(address)(uint256)' $1) set for $1"
done
forge script script/MainnetLP.s.sol --rpc-url $RPC --broadcast --unlocked --sender $OWNER --slow
log broadcast/MainnetLP.s.sol/8453/run-latest.json "LP: "

cast rpc --rpc-url $RPC evm_increaseTime 86401 >/dev/null && cast rpc --rpc-url $RPC evm_mine >/dev/null
forge script script/MainnetSmoke.s.sol --sig 'open()' --rpc-url $RPC --broadcast --unlocked --sender $(acct 0) --slow
cast rpc --rpc-url $RPC evm_increaseTime 86401 >/dev/null && cast rpc --rpc-url $RPC evm_mine >/dev/null
forge script script/MainnetSmoke.s.sol --sig 'settle()' --rpc-url $RPC --broadcast --unlocked --sender $(acct 0) --slow
log broadcast/MainnetSmoke.s.sol/8453/open-latest.json "smoke open: "; log broadcast/MainnetSmoke.s.sol/8453/settle-latest.json "smoke settle: "

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
echo "LayoverCredit $LAYC"; echo "LastResortBuyer proxy $LRB"
