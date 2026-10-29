# Private chat and the inference broker

`relay-broker` runs in shared Deno on dstack-webhost. The browser signs requests
with its Ethereum wallet and receives one $0.01 starter grant. Chat credit is
separate from the existing ETH sandbox escrow. The broker accounts in integer
nano-USD: 1,000,000,000 equals $1.00.

The broker runs as shared Deno in the existing `relay-broker` project.
`applications/private-agent-web/deploy.py` deploys the separate `private-agent`
page. This tool updates only `relay-broker`.
The existing CVM, persistent data directory, escrow and signing key identities
remain in place. It performs no chain transaction or substrate update.

Before a prompt is sent, the broker verifies fresh NEAR CPU/GPU evidence and
approved compose measurements, then pins its upstream TLS connection. The browser
checks the model, nonce and model-key address and encrypts messages with NEAR's
SDK. The broker forwards ciphertext using its encrypted-environment API key.
Replies are decrypted only by the browser. Usage and cost come from NEAR's
request ID and billing API; the broker never persists prompts or replies.

## Configure

Copy `config.inference.example.json` into the existing broker config's `inference`
block. Fill the approved gateway/model compose hashes. `maxNanoUsdPerToken` must
cover the configured model's highest input/output token rate. Each request
reserves `(encryptedBodyBytes + 256 + 64*messageCount + max_tokens)` times this
rate before dispatch, then debits the actual provider cost. Only one request per
wallet can remain unreconciled. Replays, plaintext bodies and insufficient credit
are refused before dispatch.

Keep the existing payment configuration and escrow unchanged. Wallet starter
credit needs no transaction or separate escrow deployment.

## Encrypted provider environment

The existing key stays on its laptop and inside the broker CVM. For a new setup,
first deploy the broker without an envelope and fetch its public environment key:

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

Pin `EXPECTED_PAYMENT_SIGNER` to the existing verified broker payment address.
The helper verifies that signer's EIP-191 signature over the project, purpose and
public encryption key. It uses ephemeral secp256k1 ECDH, HKDF-SHA256 and AES-GCM
and writes only a ciphertext envelope, mode 0600. The broker decrypts in CVM
memory with project-scoped dstack key `inference-env-v1`. Existing signing key
names `egress-grants-v1` and `payments-grants-v1` retain their identities.

For later updates, reuse the active encrypted envelope. No provider value belongs
in source, logs, shell arguments, page files or ordinary configuration. No
webhost substrate or secret-release update is needed.

## Deploy

Wait for the coordinating lane to finish its broker work, merge its branch, then
prepare the combined source and the existing public configuration:

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

Preparation bundles dependencies locally. The upload manifest stores only the
encrypted envelope and existing operator hash. Apply updates and promotes only
`relay-broker`, checks shared Deno, and compares the broker identities, escrow
and secret-release metadata/key. The persistent payments filename remains
`payments-<lowercase-escrow>.json`. Source preparation never submits a transaction.
Serialize shared-runtime project deployments; promote a verified stored revision
before retrying an upload whose response was interrupted.

Build the page on zed, then use `applications/private-agent-web/deploy.py` with
its compiled `dist` directory. It updates only the existing `private-agent`
shared Deno project and preserves broker and secret-release identities.

## HTTP and checks

`GET /inference/quote` returns the model and starter limits. Signed wallet POSTs
`/inference/credit`, `/inference/prepare`, `/inference/chat`, and `/inference/usage`
claim credit, verify a fresh model session, forward SDK ciphertext and reconcile
provider costs. The wallet signs top-level sorted JSON without `sig` using
EIP-191; every request has a fresh 16-byte hex nonce and an `issuedAt` timestamp
within 120 seconds. Prepare also includes the browser's 32-byte attestation nonce.

`GET /inference/status` returns the same public model/credit configuration.
`POST /inference/provider-check` is a fixed, small operator diagnostic using the
existing Bearer operator token. It never creates user credit.

```sh
deno test --allow-read --allow-net \
  --allow-env=WS_NO_BUFFER_UTIL,WS_NO_UTF_8_VALIDATE \
  applications/relay-broker applications/payments/payments.test.mjs
```

Run browser builds and Playwright on zed under `/data`, using `ssh zed-mesh`.
After the live journey, preserve screenshots, request-cost evidence and test logs,
then remove owned installs and compiled rehearsal output.

Use `dev.py DSTACK_SOCKET DATA_DIRECTORY` with a local dstack simulator. Recorded
NEAR fixtures cover allocation/accounting before management credentials exist.
Docker and heavy work run on zed under `/data`, reached as `ssh zed-mesh`.

The old immutable escrow accepts bytes and seconds only. Full inference credit
needs a separate Base Sepolia deployment of the updated `UsageEscrow`, a unit-2
class and confirmed purchases. Its local Solidity tests run in an in-memory EVM:

```sh
forge test --root contracts --match-contract UsageEscrowTest -vv
```

The live update command deliberately preserves the current escrow. A later
escrow switch is separate: finish all old purchase/settlement/refund consumers
and register needed classes before switching, or implement multi-escrow support.
Preserving an old state file alone does not serve its outstanding purchases.


## Connect an operator relay to shared Deno

A relay on a private operator network opens an outbound authenticated libp2p
connection through finite HTTPS frames. Set `sandbox_backhaul_peers` to its
existing PeerId in the broker configuration before preparing the package. The
broker accepts Noise connections only from those relay identities. Its internal
WebSocket listener stays on loopback; the public path uses ordinary HTTPS.

After each broker promotion, obtain its new transport PeerId:

```sh
curl --fail --silent --show-error \
  https://pod.dstack.soc1024.com/relay-broker/sandbox/transport
```

Build the relay on zed under `/data`, then run it there with its existing local
key and the returned `peer_id`:

```sh
(cd applications/libp2p-attest/peer && go build -o /data/OPERATOR/dsmack-relay .)
/data/OPERATOR/dsmack-relay relay /ip4/0.0.0.0/tcp/4033 \
  /data/OPERATOR/relay.key \
  https://pod.dstack.soc1024.com/relay-broker/sandbox/p2p BROKER_TRANSPORT_PEER_ID
```

The relay prints a connection confirmation. A configured `sandbox_probe`
containing that relay's public multiaddress makes `/sandbox/transport` also
check reachability before launching nodes. Keep the relay key on zed. A broker
promotion changes its ephemeral transport identity; restart the owned relay
with that new identity before starting the next job.

The backhaul opens `POST /sandbox/p2p/open`, then uses bounded binary
`POST /sandbox/p2p/:channel/send` and `GET /sandbox/p2p/:channel/recv` frames,
closing with `DELETE /sandbox/p2p/:channel`. The random channel capability is
transport state. Noise authenticates and encrypts the libp2p connection; job
payloads retain their separate browser-to-node encryption.
