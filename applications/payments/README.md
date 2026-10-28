# Paid compute

`UsageEscrow` sells Base Sepolia testnet ETH allowances for persistent node
classes. Each class pins its operator, unit (bytes or seconds), floor price,
capacity, compose hash and OS image hash. Its bounded reservation price rises
with funded purchases and decays in empty epochs. The owner pins the broker's
secp256k1 address once with `registerBroker`, then registers classes with
`registerNode`. Purchases snapshot their class, buyer key, price and payout.

Buy and obtain the broker’s finalized purchase confirmation before starting the VM. All chain reads use matching replies from two of
three independent RPCs at one common finalized block hash, with pinned code
and a 30-minute staleness limit. After finality, launch the node, verify its
Apple assertion and obtain the broker's signed run binding. Execute within the
runner's 900-second watchdog, retain the final receipt, stop the VM and then
settle. Neither admission nor grant activation requires an on-chain transaction.

The EIP-712 domain is `{name:"DsmackUsageEscrow",version:"2",chainId:84532,
verifyingContract:escrow}`. The broker signs:

```
NodeBinding(bytes32 node,address operator,address receiptSigner,bytes32 composeHash,bytes32 imageHash,bytes32 runId,uint64 expires)
Grant(uint256 purchaseId,bytes32 node,bytes32 runId,bytes32 buyerKey,uint8 unit,uint128 amount,uint64 issuedAt,uint64 serviceUntil,bytes32 destinationPolicyHash)
```

`node` identifies the class; `runId=keccak256(abi.encode(enrollmentKeyId,runNonce))`
identifies one fresh guest. The guest generates its receipt key only in memory.
Its Apple-attested statement binds both IDs, operator, receipt key, guest PeerId,
compose, image, build, expiry and a fresh broker challenge. The broker checks
App Attest enrollment, approved CDRegistry build, unburned image/build and class
measurements before signing the binding. Binding expiry is fixed on first
admission and at most ten minutes later; renewal never extends it.

Receipt format remains:

```
Receipt(uint256 purchaseId,uint64 sequence,uint128 used,uint64 endedAt,bool finalReceipt)
```

`settle(receipts,signatures,binding,brokerSignature)` verifies both signatures,
class measurements and payout, receipt bounds, and monotonic cumulative usage.
The first settlement pins the binding digest for that purchase. Binding expiry
limits the receipt's service timestamp; settlement may occur after the VM exits.
Final settlement credits unused principal immediately. After purchase expiry
plus one hour, anyone can trigger a timeout refund. Payees pull ETH with
`withdraw()`. Operators earn only the floor component; premiums have no
withdrawal path.

## Run

Deploy with `contracts/payments/deploy-and-fund.sh`, then use
`applications/payments/configure.mjs` to create operational configuration. Its
`classes` array lists registered class IDs. Configure the broker with this
payment configuration, allowed workloads and enrolled Apple public keys; deploy
only relay-broker using `applications/relay-broker/deploy.sh`.

The measured guest `PAYMENTS_CONFIG` contains `node`, `escrow`, `operator`,
`grantSigner`, `enrollmentKeyId`, `buildId`, `destinationPolicyHash` and
`runExpires`. Set the workload/session lifetime below 900 seconds. Publish the
class's compose and image hashes on chain before buying; wait for finalized
registration before offering that class. Run `register-class.mjs CONFIG FUNDING_KEY
MANIFEST` after the deployment is finalized to pin the broker and register the
measured compute class.

```
dsmack-agent run-remote --payments-config CONFIG --funding-key FUNDING_KEY \
  --send-payments --launch-node 'operator-launch-command' \
  --stop-node 'operator-stop-and-wait-command' \
  --binary ./dsmack-compute --broker BROKER --broker-key ED25519_KEY \
  --cdhash CDHASH --manifest MANIFEST --enrollment ENROLLMENT \
  --repo REPO --prompt 'Fix the issue' --credential LOCAL_TOKEN \
  --seconds 90 --out paid-job
```

The launch command runs after purchase finality. The stop command returns only
when the VM has exited; settlement and refund confirmation follow. For multiple
buyers sharing a run, use `--prepare-only` for each purchase, launch once, execute
each with `--resume-payment --defer-settlement`, stop the VM, then invoke
`--finish-only` for each retained receipt. Prepared output preserves buyer keys
and transaction hashes for recovery. Each purchase gets fresh EVM and libp2p
keys, funded from one testnet wallet.

For a Mac-local inference token, replace `--funding-key` with
`--payment-service http://127.0.0.1:18455`. Run
`service.py CONFIG FUNDING_KEY STATE_DIR 18455` on the wallet machine and forward
that loopback port over the existing SSH master. Keys and token stay on their
respective machines. The helper refuses funding-wallet transactions below
0.02 testnet ETH.

`GET /payments/classes` exposes prices before a VM exists. `/payments/nodes`
lists live attested runs. `/payments/confirm` records the finalized Purchase event and immutable allowance
before VM launch. Grant activation uses that saved confirmation and the live
attested binding, with no new purchase lookup. `/payments/grant` requires proof of the purchase's
buyer libp2p key and persists one deterministic grant per purchase.
`/payments/receipts` retains signed usage plus its independently submittable
broker binding. `submit.mjs` settles a batch from one run, triggers timeout
refunds and withdraws credits; transaction commands require `--send`.

## Trust boundaries

| Actor/action | Effect and bound |
|---|---|
| Dishonest broker | Can authorize an arbitrary receipt key, fabricate admission, censor grants/receipts, or double-authorize service. With its chosen key it can claim the full purchased allowance without real work, eliminating that buyer's refund. It cannot charge beyond escrowed principal, change class measurements or the snapshotted operator, divert premiums, or withdraw buyer credits. Operator payout remains used × floor. Buyers also verify the original Apple evidence and grant/run binding before releasing credentials. |
| Dishonest operator | Cannot replace the class payout or receipt key without a broker-signed binding. A compromised admitted meter can overreport up to the purchased amount; payments cannot prove useful work. |
| Buyer replay or concurrent jobs | Authenticated buyer PeerId, run-specific grant, one cumulative guest cap and final closure; on-chain monotonic sequence/usage and a pinned binding prevent duplicate settlement or changing meters. |
| Forged RPC funding/revocation | Finalized quorum, code pins and staleness bound; a colluding provider majority remains trusted. |
| Missing broker or guest | Retained signed receipts can be settled by anyone; unserved principal refunds after expiry plus grace. |
| Owner | Trusted to select the broker and immutable class parameters. Broker selection cannot be changed after registration. |

## Test

Run Go guest and compute tests on the builder with `PAYMENTS_EVIDENCE` pointing
to the evidence directory. Deno tests in `payments.test.mjs` check quorum,
canonical purchase events, buyer authorization, grant persistence and receipt
storage. `test-local.sh` settles original Go and compute receipt signatures in
Solidity and exercises payout, refunds, price increase and decay. Contract tests
are `forge test --root contracts --match-contract UsageEscrowTest --offline`.
