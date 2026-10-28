# Paid compute

Base Sepolia testnet ETH buys a bounded allowance from `UsageEscrow`. The broker
confirms the Purchase event and immutable terms with a finalized 2/3 RPC quorum,
then persists an EIP-712 grant. The compute guest checks the authenticated buyer
PeerId, meters seconds and signs cumulative receipts with a memory-only
secp256k1 key. Final receipts settle the operator's floor price and refund unused
principal immediately. Congestion premiums stay locked in escrow. Timeout
refunds open one hour after purchase expiry.

## Configure and admit a node

P1's `contracts/payments/deploy-and-fund.sh` deploys the escrow from the
single test wallet and makes that wallet the owner. Its `deployment.json` supplies the address and runtime hash.
Create local configuration with Deno 2:

```sh
deno run --allow-read --allow-write --allow-net --allow-env applications/payments/configure.mjs \
  /path/to/payments/contract/deployment.json 0xBROKER_GRANT_SIGNER 0xPOLICY_HASH \
  local-data/payments-config.json
```

The grant signer is the broker's project-scoped secp256k1 key, derived under
`payments-grants-v1` and published at `GET /payments/key`, including before the
payment configuration is enabled. Deploy the broker code first to obtain that
address. Add the configuration
as `payments` in the broker configuration, then package it with
`applications/relay-broker/deploy.sh`. The deployment script bundles ethers for
the shared Deno handler. `/payments/nodes` returns live nodes and finalized
prices; `/payments/receipts` stores and lists signed cumulative receipts.

Build `applications/compute-node/peer` on the Linux builder. The existing compute
workload packer's optional final argument is a JSON file containing:

```json
{
  "escrow": "0xESCROW",
  "operator": "0xOPERATOR",
  "grantSigner": "0xBROKER_GRANT_SIGNER",
  "enrollmentKeyId": "0xENROLLMENT_KEY_ID",
  "buildId": "0xAPPROVED_BUILD_ID",
  "destinationPolicyHash": "0xPOLICY_HASH",
  "runExpires": 1800000000
}
```

The packer measures it as `PAYMENTS_CONFIG` in the compose environment. Set the
run duration and expiry to allow chain finality plus service time, for example
three hours. The guest publishes its registration before owner admission. The
broker's approved `workloads` entry pins that compose, image, CDHash and service.
The destination policy hash identifies the canonical policy enforced by those
measured egress rules.

Before registering, obtain a fresh owner challenge and signed registration:

```sh
python3 - <<'PY'
import json, secrets, time
from pathlib import Path
Path('local-data/payment-challenge.json').write_text(json.dumps({
  'challenge': secrets.token_hex(32), 'createdAt': int(time.time())}))
PY
python3 -c 'import json; p=json.load(open("local-data/payment-challenge.json")); print(json.dumps({"challenge":p["challenge"]}))' | \
  ./dsmack-compute paid-discover /NODE_CIRCUIT owner-libp2p.key > local-data/payment-node.json
bash applications/payments/admit-node.sh /path/to/payments/funding-wallet.key
```

Generate the temporary transport identity with `dsmack-compute keygen` first.
`admit-node.sh` uses the sprint funding wallet as owner. It first verifies its
address, then verifies the fresh Apple assertion, enrollment, approved build,
compose/image, payment signer binding and finalized contract code. It registers
that immutable run with a floor of 10^10 wei/second and target of 30 seconds per
epoch. The default local files are `payments-config.json`, `broker-config.json`,
`payment-node.json` and `payment-challenge.json` under `local-data/`; their paths
can be supplied through `PAYMENTS_CONFIG`, `BROKER_CONFIG`, `PAYMENTS_NODE` and
`PAYMENTS_CHALLENGE`.

## Run one paid job

```sh
applications/agent-turns/skill/dsmack-agent run-remote \
  --payments-config local-data/payments-config.json \
  --funding-key /path/to/payments/funding-wallet.key --send-payments \
  --binary ./dsmack-compute --broker https://pod.dstack.soc1024.com/relay-broker \
  --broker-key ED25519_BROKER_PUBLIC_KEY --cdhash APPROVED_CDHASH \
  --manifest compose-manifest.json --enrollment enrollment \
  --credential /path/to/local/inference-token --seconds 60 \
  --repo ./job-repo --prompt 'Fix the issue' --out ./paid-job
```

Each invocation creates fresh EVM and libp2p buyer keys in `paid-job/payment-state/`
with private permissions. It verifies the node and quote, funds the payer from
the configured funding wallet, buys, waits for finalized confirmation, requests
the grant, releases the encrypted job and settles the returned receipt. The
printed summary and `job/payments.json` contain paid, used, operator settlement,
locked premium and refunded ETH after the transactions reach finalized quorum confirmation. The buyer withdraws the refund. If the funding
wallet is also the node operator, it withdraws the operator credit too; otherwise
the operator pulls its credit separately. A cutoff still saves and settles its
final receipt before reporting the job failure. The VM exports all final originals in the append-only `payment-receipts` artifact. Preserve the buyer state for
recovery until refunds are withdrawn.

## Submit receipts and expire purchases

Any relayer can use the test funding wallet for settlement/refund gas:

```sh
deno run --allow-read --allow-net --allow-env applications/payments/submit.mjs \
  local-data/payments-config.json /path/to/funding-wallet.key settle receipts.json --send
deno run --allow-read --allow-net --allow-env applications/payments/submit.mjs \
  local-data/payments-config.json /path/to/funding-wallet.key refund PURCHASE_ID --send
deno run --allow-read --allow-net --allow-env applications/payments/submit.mjs \
  local-data/payments-config.json /path/to/operator.key withdraw --send
```

`receipts.json` is an array of `{receipt,signature}` envelopes, obtainable from
`GET /payments/receipts`. Buyer refunds and operator earnings are pull credits;
`refund()` closes an expired purchase and `withdraw()` transfers the credit.

## Test

```sh
PAYMENTS_EVIDENCE=/absolute/evidence/dir go test -race -v ./...  # in compute-node/peer
PAYMENTS_EVIDENCE=/absolute/evidence/dir go test -v ./...        # in payments/guest
PAYMENTS_EVIDENCE=/absolute/evidence/dir deno test --allow-read --allow-env --allow-net \
  applications/payments/payments.test.mjs
applications/payments/test-local.sh /path/to/UsageEscrow.sol \
  /absolute/evidence/dir/guest-interop.json /absolute/evidence/dir
```

The local EVM tests settle original Go/compute signatures, exercise operator and
buyer withdrawals, timeout refunds and price rise/decay after two funded buyers.
The compute tests exercise actual worker termination, final receipt retention,
unused time, replay closure and cancellation on receipt-storage failure.

For a Mac with its own inference token, use `--payment-service http://127.0.0.1:18455`
in place of `--funding-key`. Run `applications/payments/service.py CONFIG FUNDING_KEY
STATE_DIR 18455` on the wallet machine and forward that loopback port over the
existing SSH control master. Payment keys and the inference token stay on their
respective machines.
