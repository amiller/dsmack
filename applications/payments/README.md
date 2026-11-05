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

Set `payments.rpcs` to at least three independent RPC hosts. Every quorum read
requires `floor(N / 2) + 1` matching replies from the configured list, even when
some hosts are unavailable. `PAYMENTS_RPC_URLS`, a comma-separated list, selects
providers when generating configuration with `configure.mjs`.

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

The broker accrues Layover lease statements per user and terms hash.
`POST /payments/lease-statement {statement, attestation}` takes a statement the
guest attested (`sha256(canonical(statement))` as the first half of
`report_data`) from a build listed in broker config `leaseWorkloads`
(`manifest_sha256`, `os_image_hash`, `cdhash`, `service`). The statement must
carry `kind: "layover-lease-statement/2"`, `lease_id`, `buyer_wallet`,
`operator`, `terms_hash`, `owed` (token base units, decimal string),
`chain_id: 84532` and `escrow`. The broker refuses terms the buyer has not
accepted on chain for that operator, totals over the cap, and a second
statement for the same `lease_id`. `GET /payments/claim?user=0xUSER&terms=0xTERMS`
returns the cumulative authorization. It signs
`Claim(address operator,bytes32 termsHash,uint256 cumulativeOwed,uint64 period)`
with `period` the current week (Unix seconds / 604800), using
`{name:"DsmackPrepaid",version:"1",chainId:84532,verifyingContract:escrow,
salt:USER_ADDRESS_LEFT_PADDED_TO_BYTES32}`. The contract pays only the
increment, directly to the accepted operator, and caps it at the terms' cap and
the user's remaining deposits.

Inference and agent-session debits still accrue per user/operator/week
(`operatorAccruals`), but they have no terms hash, so the broker cannot sign
claims for them against this escrow until those rails adopt terms.

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
with the new escrow, broker signer, linked operator, node, enrollment/build IDs,
policy hash and run lifetime. Register each packed class using
`register-class.mjs CONFIG FUNDING_KEY MANIFEST BROKER PUBLISHER` before offering
its new guest image. The macOS native runner uses the existing binding protocol.

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
