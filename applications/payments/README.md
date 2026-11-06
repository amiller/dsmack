# Prepaid compute

`UsageEscrow` holds USDC deposits per wallet on Base Sepolia. One USDC base unit
is 1,000 nano-USD. The broker credits finalized lifetime deposit counters to its
durable nano-USD ledger, then debits guest seconds and provider inference costs
without session transactions. Repeated balance refreshes cannot credit a deposit
twice. Starter/gift credit is separate from deposited principal and cannot create
claims against another user's funds.

S1 costs 15,000 nano-USD per active second with a 60 second minimum, charged when
the guest's first authenticated receipt is accepted. An unused grant costs zero.
Set `payments.prices.S1.nanoUsdPerSecond` and `minimumSeconds: 60` in broker config.
`payments.inferenceOperator` receives claims for provider inference costs.

Set `payments.rpcs` to an ordered list of Base Sepolia RPC URLs. One healthy
provider supplies a finalized snapshot. State reads use its EIP-1898 block hash;
a replacement provider checks the same block number and hash before serving it.
HTTP 429 and RPC quota errors put that provider on exponential backoff (1–60
seconds, extended by `Retry-After`). Chain ID, freshness and deployed code pins
are checked before credit is issued. `PAYMENTS_RPC_URLS`, a comma-separated list,
selects providers when generating configuration with `configure.mjs`.

The owner pins the broker once with `registerBroker` and registers immutable
operator, unit, compose and image measurements with `registerNode`. The guest's
in-memory secp256k1 receipt public key is bound by the fresh Apple assertion and
broker NodeBinding. Agent metering and paid-grant metering share one receipt:

```text
Receipt(uint256 purchaseId,uint64 sequence,uint8 unit,uint128 used,uint64 endedAt,bool finalReceipt)
```

Its EIP-712 domain is `{name:"dsmack.receipt",version:"5",chainId:84532,
verifyingContract:escrow}`. Unit 1 is active guest seconds; unit 0 is bytes.
Agent purchase IDs are the unsigned decimal encoding of the grant's 16-byte ID.
Sequences and usage increase monotonically. The broker retains each accepted
signed receipt in its session ledger; the guest exports the originals in
`agent-receipts`. NodeBinding and paid Grant signatures use the existing
`DsmackUsageEscrow/2` admission domain.

The broker aggregates funded debits per user/operator/week. Get a completed week's
cumulative authorization with `GET /payments/claim?user=0xUSER&operator=0xOPERATOR`
(optionally `&period=WEEK`, where week is Unix seconds divided by 604800).
It signs `Claim(address operator,uint256 cumulativeOwed,uint64 period)` using
`{name:"DsmackPrepaid",version:"1",chainId:84532,verifyingContract:escrow,
salt:USER_ADDRESS_LEFT_PADDED_TO_BYTES32}`. Cumulative amounts are in USDC base
units; sub-unit dust carries forward. Submit each user's authorization once a
week. The contract pays only the increment, directly to the operator, and caps
all operators combined at that user's remaining deposits.

`requestExit()` permanently closes a user's account to new spending. Existing
stays stop at their next receipt checkpoint. Operators have 14 days to submit
outstanding claims. Then the user calls `withdraw()` without a broker signature
to recover the remaining USDC; all subsequent claims and deposits are refused.

## Run

Deploy as described in [contracts/payments](../../contracts/payments/README.md).
Generate broker config with `configure.mjs DEPLOYMENT_JSON BROKER_SECP_ADDRESS
DESTINATION_POLICY_HASH OUTPUT_JSON`, set its classes and posted prices, and use
it as the broker's `payments` block. Set `inferenceOperator` to the provider's
reimbursement wallet. The ledger is persisted in `payments-ESCROW_ADDRESS.json`.

Build the Linux compute peer and OCI workload using the
[compute node instructions](../compute-node/README.md#build). Pack `PAYMENTS_CONFIG`
with the new escrow, broker signer, operator, node, build ID, policy hash and run
lifetime. It names no App Attest key: the guest binds its run to the key that
signs its attestation (`runId = keccak(kid, runNonce)`), and the broker admits
the run only if that key is enrolled on AppleAttestRegistry and has a MacLink to
the class operator. A key rotation is a new `enroll` plus a new MacLink under the
same class. Register each packed class using
`register-class.mjs CONFIG FUNDING_KEY MANIFEST` before offering its new guest
image. The macOS native runner uses the existing binding protocol.

Top up a user's wallet (amount in six-decimal USDC base units), then refresh its
signed `/inference/credit` request:

```sh
deno run -A applications/payments/submit.mjs CONFIG WALLET_KEY deposit 1000000 --send
curl "$BROKER/payments/claim?user=$USER_ADDRESS&operator=$OPERATOR" -o claim.json
deno run -A applications/payments/submit.mjs CONFIG OPERATOR_KEY claim claim.json --send
deno run -A applications/payments/submit.mjs CONFIG WALLET_KEY request-exit --send
# After 14 days:
deno run -A applications/payments/submit.mjs CONFIG WALLET_KEY withdraw --send
```

## Test

```sh
forge test --root contracts
(cd applications/payments/guest && go test ./...)
(cd applications/compute-node/peer && go test ./...)
deno test -A applications/relay-broker applications/payments/payments.test.mjs
anvil --chain-id 84532 --port 18545 --silent
# In another terminal, from the repository root:
deno run -A applications/payments/anvil-e2e.mjs
```

Set `PAYMENTS_EVIDENCE` for the Go receipt tests and Deno tests to the same local
directory to check Go/Ethers receipt interoperability.
