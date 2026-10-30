# Relay broker

The shared Deno broker verifies Mac relay and compute attestations, issues
Ed25519 byte/time grants, and authorizes Base Sepolia payments. Private inference
forwards browser-encrypted NEAR requests and charges provider-reported costs.
Agent sessions reserve guest seconds from the same wallet credit.

Live: <https://pod.dstack.soc1024.com/relay-broker>.

`GET /network` returns each ownership-linked Mac's signed, reported capacity:
operator address, optional coarse region, chip/RAM, logical guest slots,
ready/busy counts and last heartbeat. Network totals include Macs whose signed
heartbeat and broker receipt are both less than 60 seconds old. Rotation can
report multiple guests for one logical slot; each slot counts once and busy
takes precedence over ready.

`GET /network/history` returns minute samples of ready slots, busy slots, total
slots and online Macs from an in-memory 24-hour ring buffer. It starts when the
broker loads, samples independently of readers and is lost on broker restart.
Both endpoints allow public CORS reads.

## Configure and run

Start with `config.example.json`; set the RPC, App Attest registries and approved
workload tuples (`manifest_sha256`, `os_image_hash`, `cdhash`, `service`). Compute
the manifest SHA-256 from the exact compose bytes and obtain the image hash from
its `base_vm.os_image_hash`. For off-chain enrollment, `enroll.py ENROLLMENT
CDHASH` verifies the Apple chain and emits a public enrollment entry for the
config's `enrollments` array.

Keep the existing `payments` block to serve the current escrow. Add the
`inference` block from `config.inference.example.json`, including approved NEAR
gateway/model compose hashes and allowed browser origins. Amounts are integer
nano-USD: 1,000,000,000 equals $1.00. The browser receives starter credit and
requests an attested model session before encrypting its messages. A dispatch
reserves its maximum cost; billing evidence reconciles that reservation.

For the free Mac pool, configure `sandboxDiagnosticWorkloads` with its approved
compute tuples. `sandbox_backhaul_peers` identifies Mac peers permitted to open
the in-process libp2p backhaul.

Run against a local dstack simulator from this directory:

```sh
python3 dev.py /absolute/path/to/dstack.sock /absolute/path/to/broker-data
# http://127.0.0.1:18270/
```

Set `NEAR_ENCRYPTED_ENV` to the encrypted provider envelope for local inference.
`dev.py SOCKET DATA HOST PORT` chooses the listener. The broker derives the
existing `egress-grants-v1` and `payments-grants-v1` signing identities from the
project-scoped dstack socket. Quotas and payment/inference ledgers persist in
`ctx.dataDir`; registrations renew every 25–30 seconds and expire after 60.

## Provider environment and deployment

For initial configuration, fetch the broker's public environment key, then
create an encrypted envelope on the machine holding the provider key. Run from
the repository root:

```sh
curl --fail --silent --show-error \
  https://pod.dstack.soc1024.com/relay-broker/inference/environment-key \
  --output environment-key.json

deno run --allow-read --allow-write \
  --allow-env=WS_NO_BUFFER_UTIL,WS_NO_UTF_8_VALIDATE \
  applications/relay-broker/encrypt-provider-env.mjs \
  environment-key.json "$EXPECTED_PAYMENT_SIGNER" \
  "$HOME/.config/near-key" near-encrypted-env.json
```

The helper authenticates the encryption key using the existing payment signer's
signature and encrypts `NEAR_API_KEY` with ephemeral ECDH and AES-GCM. The broker
decrypts it in CVM memory using project key `inference-env-v1`. Reuse the active
envelope when updating an existing deployment.

Prepare and apply a source update:

```sh
python3 applications/relay-broker/deploy-inference.py prepare \
  --config /absolute/path/broker-config.json \
  --operator-token-sha256 "$EXISTING_OPERATOR_TOKEN_SHA256" \
  --encrypted-env /absolute/path/near-encrypted-env.json \
  --out /absolute/path/prepared-upload

python3 applications/relay-broker/deploy-inference.py deploy \
  --prepared /absolute/path/prepared-upload \
  --url https://pod.dstack.soc1024.com \
  --evidence /absolute/path/deployment-evidence --apply
```

Preparation bundles the npm dependencies with Deno. Apply uses the configured
webhost admin credential, updates only `relay-broker`, and promotes shared Deno.
Deployment waits up to ten minutes for `/network` busy slots and
`/inference/status` `inFlightStreams` to reach zero before upload and promotion.
Set `--wait-idle-minutes N` to change the wait. Disconnected browser requests
count until their provider streams have drained. Interrupted requests with a
known NEAR billing ID settle once against that exact provider cost record;
missing token totals remain explicitly unreported.

The deployment manifest contains the operator hash and ciphertext envelope.

## HTTP API

- `GET /key`, `/payments/key`: signing public keys.
- `GET /relays`, `/nodes`: live attested registrations; `POST` renews them.
- `POST /grant`: signed Ed25519 request for byte/time credit.
- `/payments/challenge`, `/classes`, `/nodes`, `/confirm`, `/grant`, `/receipts`:
  payment admission and signed usage receipts under `/payments`.
- `GET /inference/quote`, `/status`, `/environment-key`: public configuration.
- `POST /inference/credit`, `/prepare`, `/chat`, `/usage`: EIP-191 wallet requests
  to claim credit, attest the model, dispatch ciphertext and reconcile costs.
- `POST /agent/open`, `/status`, `/end`: wallet-signed guest sessions;
  `POST /agent/receipt` accepts guest-signed usage.
- `GET /sandbox/nodes/PEER/attestation?challenge=HEX`: fresh node evidence.
- `/sandbox/p2p/*`: bounded HTTPS backhaul to the native libp2p transport.
- `GET/POST /tunnels`: discover and publish expiring browser tunnel hints.
- `GET /fleet`: signed Mac capacity, slots and errors, filtered with
  `?operator=ADDRESS`. Operators come from signed ownership links; capacity is
  labeled `reported`. A Mac becomes offline after 60 seconds without a heartbeat.
  `POST /fleet` accepts EIP-191 messages signed by the Mac publisher key over
  `dsmack-fleet/1\n` and the recursively sorted JSON payload. Heartbeats contain
  neither `operator` nor `payout`.
- `GET /fleet/ownership`: EIP-712 domain, active links, provisioner revocations
  and nonce highwaters. Filter links with `?publisher=ADDRESS&kid=BYTES32`.
- `POST /fleet/link`: `{link, publisherSignature, operatorSignature}` or
  `{link, publisherSignature, authorization: {authorization, signature},
  provisionerSignature}`. `link` is `MacLink(bytes32 kid,address publisher,
  address operator,uint64 nonce)`. The operator signs either the link or
  `ProvisioningAuthorization(address operator,address provisioner,uint64 nonce)`;
  its provisioner then signs the same MacLink as the publisher. A higher Mac
  nonce supersedes the previous publisher link; an exact replay is idempotent.
- `POST /fleet/revoke-provisioner`: `{revocation,signature}`, operator-signed
  `ProvisionerRevocation(address operator,address provisioner,uint64 nonce)`.
  Revocation permanently retires that provisioner for the operator. Existing Mac
  links remain active; authorize a fresh provisioner key to add more Macs.
- `POST /fleet/unlink`: `{unlink,publisherSignature}`, Mac-signed
  `MacUnlink(bytes32 kid,address publisher,address operator,uint64 nonce)`.
  The higher nonce is retained after removal to refuse stale links.

Ownership uses domain `DsmackMacOwnership`, version `1`, chain ID `84532`, and
`payments.escrow` as the verifying contract. Nonces are uint64 decimal strings.
Links, revocations and heartbeat records persist atomically in `fleet.json`.
The CLI is documented under [Add a Mac](../mac-ownership/README.md#add-a-mac).


See [the compute protocol](../compute-node/PROTOCOL.md) for admission and wire
formats. `verify-grant.py` independently verifies an HTTP grant with Python
`cryptography`.

## Test

From the repository root:

```sh
deno check applications/relay-broker/server.ts
deno test --allow-read --allow-net \
  --allow-env=WS_NO_BUFFER_UTIL,WS_NO_UTF_8_VALIDATE \
  applications/relay-broker applications/payments/payments.test.mjs
```

## Encrypted conversation sync

Configure `continuity.anchor` with the Base Sepolia `SyncHeads` contract and
`continuity.rpc` with the RPC URL. The contract writer is the existing payment
signer; fund it with test ETH for head commits. The page pins the contract address
and runtime code hash in `syncAnchor` and `syncAnchorCodeHash`.

Wallet-signed POST requests at `/sync/blob`, `/sync/read`, `/sync/head` and
`/sync/commit` retain ciphertext by raw CIDv1 and update a signed head after an
on-chain compare-and-swap commit. The broker stores the blocks under its persistent
`continuity-blocks` directory. The encrypted manifest merges session IDs by union
and selects the newest counter per session. `/sync/wrap/put` stores wallet-signed
passkey envelopes; `/sync/wrap/get` retrieves an envelope by its credential ID.

Run the network boundary tests with:

```sh
deno test --allow-read --allow-write --allow-net --allow-env continuity.test.mjs
```

## Saved workspaces

Set `workspaces.stores` to a map from Mac publisher addresses to their workspace
store HTTPS URLs. Wallet-signed `/workspaces/{head,begin,chunk,commit,read,history}`
POSTs use `action: "workspace-OP"` and a conversation `workspaceId`. The guest can
use its stay ID and attested Ed25519 receipt key to seal before its final receipt;
its conversation ID selects the workspace and its recorded placement selects the
Mac. The broker retains version/hash pointers in `workspaces.json`.

`begin` takes `version`, `previousHash`, `hash`, `size`, and optionally `mac`, and
returns `uploadId` and `offset`. `chunk` takes that upload ID, a byte offset and
at most 512 KiB of standard base64 ciphertext. `commit` returns the new `head`.
A head contains `workspaceId`, `version`, `previousHash`, `hash`, `size`, `cid`,
and `mac`. `read` takes the trusted version/hash and a bounded byte range;
`history` returns ascending heads after `afterVersion`. Identical uploads and
commits can resume after interrupted responses.
