#!/bin/bash
# The p2p bounty stack on Base: AppleEndorsements (+ Apple intermediate), CDRegistry with the runner build (the Mini's
# 0c3d3c90) approved and the Developer ID alpha.3 copy (b98b6aba) registered, an AppleAttestAnyBuildV1 verifier bound to
# the Bounty, the Bounty, and one posted entry. The deployer owns CDRegistry.
# usage: RPC=... SIGN="--private-key 0x.. | --account name" AMOUNT=<wei> IMAGE=0x.. MANIFEST=0x.. DAYS=30 script/bounty-launch.sh
set -euo pipefail
cd "$(dirname "$0")/.."
: "${RPC:?}" "${SIGN:?}" "${AMOUNT:?}" "${IMAGE:?}" "${MANIFEST:?}" "${DAYS:?}"
export FOUNDRY_DISABLE_NIGHTLY_WARNING=1
create() { forge create --rpc-url "$RPC" $SIGN --broadcast --json "$@" | jq -r .deployedTo; }
send() { cast send --rpc-url "$RPC" $SIGN --gas-limit 16000000 --json "$@" | jq -e -r 'select(.status == "0x1") | .transactionHash'; }
ENDORSE=$(create ../app-attest/contracts/src/AppleEndorsements.sol:AppleEndorsements)
send $ENDORSE 'endorseIntermediate(bytes)' 0x$(xxd -p ../app-attest/contracts/fixtures/apple-intermediate.der | tr -d '\n') >/dev/null
CDS=$(create src/CDRegistry.sol:CDRegistry)
send $CDS "$(cat fixtures/mainnet/setBuild-runner.calldata)" >/dev/null
send $CDS "$(cat fixtures/mainnet/registerBuild-b98b6aba.calldata)" >/dev/null
ME=$(cast wallet address $SIGN)
BOUNTY_AT=$(cast compute-address --nonce $(( $(cast nonce --rpc-url "$RPC" $ME) + 1 )) $ME | awk '{print $NF}')
VERIFIER=$(create src/AppleAttestRegistryV1.sol:AppleAttestAnyBuildV1 --constructor-args $ENDORSE $BOUNTY_AT $CDS 0x$(printf appattest | xxd -p)00000000000000 3 false)
BOUNTY=$(create src/Bounty.sol:Bounty --constructor-args $VERIFIER)
[ "${BOUNTY,,}" = "${BOUNTY_AT,,}" ] && [ "$(cast call --rpc-url "$RPC" $VERIFIER 'registry()(address)')" = "$BOUNTY" ]
UNTIL=$(( $(cast block --rpc-url "$RPC" latest -f timestamp) + DAYS * 86400 ))
send --value $AMOUNT $BOUNTY 'post(bytes32,bytes32,bytes32,bytes32,uint64)' $(cast call --rpc-url "$RPC" $CDS 'buildId()(bytes32)') \
  $IMAGE $MANIFEST 0x$(printf checker | sha256sum | cut -c1-64) $UNTIL >/dev/null
echo "AppleEndorsements $ENDORSE"; echo "CDRegistry $CDS"; echo "verifier $VERIFIER"; echo "Bounty $BOUNTY (entry 0)"
cast call --rpc-url "$RPC" $BOUNTY 'entries(uint256)(bytes32,bytes32,bytes32,bytes32,address,uint64,uint256,bool)' 0
