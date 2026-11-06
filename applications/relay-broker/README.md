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

Set `rpcs` to an ordered list of Base Sepolia RPCs for chain verification and
continuity. It defaults to `rpc` followed by the public Base Sepolia providers.
`continuity.rpcs` selects a separate ordered list for the sync anchor.

Start with `config.example.json`; set the RPC, App Attest registries and approved
workload tuples (`manifest_sha256`, `os_image_hash`, `cdhash`, `service`). Compute
the manifest SHA-256 from the exact compose bytes and obtain the image hash from
its `base_vm.os_image_hash`. App Attest keys are read only from
AppleAttestRegistry (`keys(kid)`); the broker refuses a config with
`enrollments`, so a rotated key needs an on-chain `enroll` and a MacLink, never a
broker change. A paid guest is admitted only if the key that signed its
attestation has a verified MacLink (`/fleet/link`) to its class operator.
Guest admission (paid and unpaid), `/payments/classes` and deposit credit read App Attest
keys, CDRegistry, Canary, deployed code, the UsageEscrow class and `deposits` only
through `chainRead`, the layover-chain service
(Helios OP-stack light client): every read is pinned to one verified block hash and a
reply not marked `helios-opstack` is refused (`payments/helios-reader.mjs`). The
continuity anchor still uses its own RPC provider.

Configure the prepaid USDC `payments` block as in `../payments/README.md`. Add the
`inference` block from `config.inference.example.json`, including allowed
browser origins. NEAR gateway and model evidence must satisfy `near-policy.mjs`,
which mirrors 13rac1/teep's nearcloud policy (commit in `TEEP_COMMIT`):
MRCONFIGID binds `app_compose`, each digest-pinned image is an approved
repository with a Rekor entry from its expected Fulcio identity or key (SET and
inclusion proof verified), and MRSEAM/MRTD/RTMR1/RTMR2 match known values.
Values teep lacks are marked `LOCAL`. Amounts are integer
nano-USD: 1,000,000,000 equals $1.00. The browser receives starter credit and
requests an attested model session before encrypting its messages. A dispatch
reserves its maximum cost; billing evidence reconciles that reservation.

The example's `inference.dailyStarterBudgetNanoUsd` defaults to $5 of starter
grants per UTC day; a new wallet gets the full $0.25 only if it fits the remaining
budget. The counter persists with the credit ledger. `agent.maxActiveSessionsPerWallet`
defaults to one held guest; a refused claim names the existing session.

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
python3 applications/relay-broker/deploy-inference.py prepare --target production \
  --config /absolute/path/broker-config.json \
  --operator-token-sha256 "$EXISTING_OPERATOR_TOKEN_SHA256" \
  --encrypted-env /absolute/path/near-encrypted-env.json \
  --out /absolute/path/prepared-upload

python3 applications/relay-broker/deploy-inference.py deploy --target production \
  --prepared /absolute/path/prepared-upload \
  --url https://pod.dstack.soc1024.com \
  --evidence /absolute/path/deployment-evidence --apply
```

To create staging, use `--target staging` on both commands, a separate preparation
and evidence directory, and the staging broker config and encrypted provider
environment. The upload creates `relay-broker-staging`; its API is
`https://pod.dstack.soc1024.com/relay-broker-staging`. Preparation sets the allowed
browser origins to `https://private-agent-staging.dstack.soc1024.com`. Configure
staging payment, provider and storage resources in the input config. Production
preparation and deployment require clean source contained in locally recorded
main; deployment also requires the prepared ref to equal HEAD. Neither command
fetches refs. Staging accepts a preparation from any commit.

For a staging page served at the webhost's project path, prepare with
`--staging-origin https://pod.dstack.soc1024.com` so browser requests from
`https://pod.dstack.soc1024.com/private-agent-staging/` use that allowed origin.

Bootstrap a new staging project without a provider envelope first, on the
coordinator's deployment machine:

```sh
python3 applications/relay-broker/deploy-inference.py prepare --target staging \
  --config "$STAGING_BROKER_CONFIG" --operator-token-sha256 "$OPERATOR_HASH" \
  --out "$STAGING_BOOTSTRAP"
python3 applications/relay-broker/deploy-inference.py deploy --target staging \
  --prepared "$STAGING_BOOTSTRAP" --evidence "$STAGING_BOOTSTRAP_EVIDENCE" --apply
curl --fail --silent --show-error \
  https://pod.dstack.soc1024.com/relay-broker-staging/key
curl --fail --silent --show-error \
  https://pod.dstack.soc1024.com/relay-broker-staging/payments/key
curl --fail --silent --show-error \
  https://pod.dstack.soc1024.com/relay-broker-staging/inference/environment-key \
  --output "$STAGING_ENVIRONMENT_KEY"
deno run --allow-read --allow-write \
  --allow-env=WS_NO_BUFFER_UTIL,WS_NO_UTF_8_VALIDATE \
  applications/relay-broker/encrypt-provider-env.mjs \
  "$STAGING_ENVIRONMENT_KEY" "$STAGING_PAYMENT_SIGNER" \
  "$PROVIDER_KEY_PATH" "$STAGING_ENCRYPTED_ENV"
python3 applications/relay-broker/deploy-inference.py prepare --target staging \
  --config "$STAGING_BROKER_CONFIG" --operator-token-sha256 "$OPERATOR_HASH" \
  --encrypted-env "$STAGING_ENCRYPTED_ENV" --out "$STAGING_PREPARED"
python3 applications/relay-broker/deploy-inference.py deploy --target staging \
  --prepared "$STAGING_PREPARED" --evidence "$STAGING_EVIDENCE" --apply
```

Use the new broker's public keys in the staging page config; set
`STAGING_PAYMENT_SIGNER` to that staged payment identity. Preparation and evidence
paths name fresh directories. Build the page with the commands in its README,
then create its project:

```sh
python3 applications/private-agent-web/deploy.py --target staging \
  --config "$STAGING_PAGE_CONFIG" --smtp-env "$STAGING_SMTP_ENV" \
  --operator-token-sha256 "$OPERATOR_HASH" --evidence "$STAGING_PAGE_EVIDENCE"
```

Preparation bundles the npm dependencies with Deno. Apply uses the configured
webhost admin credential and updates only `relay-broker`, which runs in its own
container (`isolation: container`), so deploys of other projects never restart it.
Apply first drains the broker: `POST /drain` with the operator token
(`--operator-token FILE`) stops offering new stays, running stays continue, and
the upload waits up to 65 minutes for `/network` busy slots and `/inference/status`
`inFlightStreams` to reach zero. If the wait times out or the upload fails, it
sends `DELETE /drain` so the broker offers stays again, and exits with the error.
The new process starts undrained. Disconnected browser requests
count until upstream cancellation finishes; queued ciphertext stays counted
until the HTTP consumer reaches EOF. Interrupted requests with a
known NEAR billing ID settle once against that exact provider cost record;
missing token totals remain explicitly unreported.

The deployment manifest contains the operator hash and ciphertext envelope.

## HTTP API

- `GET /key`, `/payments/key`: signing public keys.
- `GET /relays`, `/nodes`: live attested registrations; `POST` renews them.
- `POST /grant`: signed Ed25519 request for byte/time credit.
- `/payments/challenge`, `/classes`, `/nodes`, `/claim`:
  payment admission, posted S1 prices and weekly cumulative USDC claims.
- `GET /inference/quote`, `/status`, `/environment-key`: public configuration.
- `POST /inference/credit`, `/prepare`, `/chat`, `/usage`: EIP-191 wallet requests
  to claim credit, attest the model, dispatch ciphertext and reconcile costs.
- `POST /agent/open`, `/status`, `/end`: wallet-signed guest sessions;
  `POST /agent/receipt` accepts v5 EIP-712 usage signed by the attested secp256k1 key.
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


See [the compute protocol](../../docs/protocol.md) for admission and wire
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

## Operator credit gifts

The configured `payments.fundingAddress` can add NanoUSD credit to a new or existing
wallet with a signed gift. Include the broker's pinned Ed25519 `brokerKey` in the
full broker configuration, then run:

```sh
deno run --allow-read --allow-write --allow-net \
  applications/payments/grant-credit.mjs FULL_BROKER_CONFIG FUNDING_KEY \
  BROKER_URL RECIPIENT_ADDRESS NANO_USD VOUCHER_JSON --send
```

The CLI saves the signed voucher before submitting it. Repeat the same command
and voucher file to recover an interrupted response. The broker applies each
nonce once; the recipient refreshes credit to continue its saved conversation.
A new wallet starts with its gifted amount; refreshing credit preserves it.
Existing grants and spending survive broker restarts unchanged.
