# Deploy inference and the private-agent page

`deploy-inference.py` prepares upload tarballs without contacting a service.
Run from this checkout after committing the intended source:

```sh
python3 applications/relay-broker/deploy-inference.py prepare \
  --config /absolute/path/broker-config.json \
  --operator-token-sha256 "$EXISTING_OPERATOR_TOKEN_SHA256" \
  --private-agent-source /absolute/path/w3-prepared-source \
  --out /absolute/path/prepared-upload
```

The operator hash is the existing public hash; do not generate a replacement
operator token. The W3 directory contains a `project.json` selecting `static`
or `deno` and its complete served files. No npm install runs during preparation.
The broker package contains the bundled payments schema, configuration, and
inference modules. Provider credential values do not belong in either package.

## Local checks

```sh
deno test --allow-read --allow-write --allow-net --allow-env=WS_NO_BUFFER_UTIL,WS_NO_UTF_8_VALIDATE applications/relay-broker
deno test --allow-read --allow-write --allow-net --allow-env=WS_NO_BUFFER_UTIL,WS_NO_UTF_8_VALIDATE applications/payments/payments.test.mjs
```

The token-contract tests use an in-memory EVM and send no transactions:

```sh
forge test --root contracts --match-contract UsageEscrowTest -vv
```

Run the handler using `dev.py DSTACK_SOCKET DATA_DIRECTORY` with a local dstack
simulator. Point the page at this local broker. Use recorded NEAR schema
fixtures for inference: live provider calls require Andrew's credentials.
Docker or heavier integration runs belong on zed under `/data`, reached only
with `ssh zed-mesh`. This preparation script works on zed too.

## Provider credentials

Copy `config.inference.example.json` into the broker config's `inference` block,
set the funded workspace/organization, approved model context ceiling and
reviewed compose hashes. The example's 1,048,576-token reservation is the full
published context of its canonical model. A request reserves that entire context,
so its purchase needs at least that many tokens; set a lower ceiling only for a
model whose provider-enforced maximum context is lower. The nanoUSD/token tariff
must cover the model's maximum input/output/cache rate. Set the matching inference class in the payments config.
The adapter consumes **`ctx.env.NEAR_MANAGEMENT_TOKEN`** (Cloud management access
JWT) and **`ctx.env.NEAR_REPORTING_TOKEN`** (organization usage reporting token).
Workspace and organization IDs belong in ordinary inference configuration.
An inference `sk-` key cannot replace the management JWT. The browser receives
neither credential. Never put the values in `manifest.env`, `config.json`, the
W3 source, shell history, or an evidence log.

For the dstack encrypted-environment route, Andrew supplies these two names in
the CVM's existing encrypted environment using its established Phala deployment
workflow. The tee-daemon compose must pass them into the daemon service:

```yaml
environment:
  - NEAR_MANAGEMENT_TOKEN=${NEAR_MANAGEMENT_TOKEN}
  - NEAR_REPORTING_TOKEN=${NEAR_REPORTING_TOKEN}
```

The supplied upload manifest declares those same names in `env_passthrough`.
Use the same CVM/app and persistent disk, without replacing its existing
environment, key derivation identity, or volumes.

The inspected webhost source (`ce952df9`) resolves
`env_passthrough` for container projects (`proxy/runtimes.py:634–643`), while
the shared Deno router loads only `manifest.env` (`:179`). Prepare a narrow,
unapplied bridge patch from that source:

```sh
python3 applications/relay-broker/deploy-inference.py prepare-env-bridge \
  --webhost-source /absolute/path/dstack-webhost \
  --out /absolute/path/shared-env-bridge.patch
```

The patch forwards only requested variable names from the daemon to the
shared Deno container and resolves each project's declared names into `ctx.env`.
It never embeds values in generated router code or project manifests. Shared
projects retain the webhost's existing mutual trust boundary. Apply and test
the patch in a separate webhost checkout before Andrew decides to update that
substrate; it preserves project data paths and key derivation names.

**Needs Andrew:** approve and deploy that webhost change with the encrypted
environment values before enabling provider calls, or choose an attestation-bound
secret-release loader instead. The existing Mac `/v1/GetSecret` flow is not a
generic CVM loader. Do not replace this bridge with secrets in a project manifest
or a change to broker isolation/data volumes.

## Token escrow

The existing deployed escrow is immutable and accepts only bytes and seconds.
Inference uses the updated contract with `unit=2`, measured in provider-reported
total tokens. A separate Base Sepolia deployment and inference class registration
are needed; they are separate from the existing paid sandbox classes. Keep the
old escrow configuration and state files for their outstanding purchases.
The broker configuration selects one escrow at a time. Before a live switch,
finish all old purchases and settlement/refund consumers, and register every
still-needed relay/sandbox class in the new escrow. Otherwise use a separately
designed multi-escrow broker; retaining an old state file alone does not serve
its purchases. Do not change the old escrow while it has outstanding consumers.

After Andrew authorizes those testnet transactions, the existing deployment
tool can deploy the updated source (the funding wallet stays on its machine):

```sh
python3 contracts/payments/deploy.py \
  /absolute/path/payments-20261028/funding-wallet.key \
  /absolute/path/new-inference-payments
```

The new payments directory must contain `funding-wallet.address` with
`0x1FBe7a7b3f7a37A967F3d927Abd6f04DB2766c5b`. The tool pins chain 84532,
checks the owner, persists transaction intent before submission and refuses to
repeat a partially submitted deployment. Preserve its evidence, register the
existing broker payment signer with `registerBroker(address)`, and register a
class with `registerNode(node,operator,2,floorPrice,target,composeHash,imageHash)`.
The hashes must match the approved broker inference configuration. Record the
deployed runtime code hash and add the class to the matching payment config.
Neither the package script nor the inference HTTP endpoints submit transactions.

## Live update, only when Andrew chooses

Set `UPLOAD` to the prepared directory and `ADMIN_HEADER_FILE` to an existing
mode-600 file containing the webhost admin Authorization header. These commands
are the explicit live steps; package preparation never executes them.

```sh
CVM=https://pod.dstack.soc1024.com
python3 applications/relay-broker/deploy-inference.py snapshot \
  --url "$CVM" --out "$UPLOAD/before.json"
curl --fail-with-body --silent --show-error "$CVM/_api/projects" \
  --header @"$ADMIN_HEADER_FILE" --output "$UPLOAD/projects-before.json"
curl --fail-with-body --silent --show-error "$CVM/_api/projects" \
  --header @"$ADMIN_HEADER_FILE" \
  --form "manifest=@$UPLOAD/relay-broker.manifest.json;type=application/json" \
  --form "files=@$UPLOAD/relay-broker.tgz;type=application/gzip" \
  --output "$UPLOAD/relay-deploy.json"
curl --fail-with-body --silent --show-error --request POST \
  "$CVM/_api/projects/relay-broker/promote" \
  --header @"$ADMIN_HEADER_FILE" --output "$UPLOAD/relay-promote.json"
python3 applications/relay-broker/deploy-inference.py snapshot \
  --url "$CVM" --out "$UPLOAD/after-broker.json"
python3 applications/relay-broker/deploy-inference.py compare \
  "$UPLOAD/before.json" "$UPLOAD/after-broker.json" \
  --expected-escrow "$NEW_TOKEN_ESCROW"
curl --fail-with-body --silent --show-error "$CVM/_api/projects" \
  --header @"$ADMIN_HEADER_FILE" \
  --form "manifest=@$UPLOAD/private-agent.manifest.json;type=application/json" \
  --form "files=@$UPLOAD/private-agent.tgz;type=application/gzip" \
  --output "$UPLOAD/page-deploy.json"
curl --fail-with-body --silent --show-error --request POST \
  "$CVM/_api/projects/private-agent/promote" \
  --header @"$ADMIN_HEADER_FILE" --output "$UPLOAD/page-promote.json"
python3 applications/relay-broker/deploy-inference.py snapshot \
  --url "$CVM" --out "$UPLOAD/after-page.json"
python3 applications/relay-broker/deploy-inference.py compare \
  "$UPLOAD/after-broker.json" "$UPLOAD/after-page.json"
```

Keep the project name **relay-broker** and the key names/paths
`egress-grants-v1` and `payments-grants-v1` under
`/tee-daemon/projects/relay-broker/`. Preserve the persistent data directory:
`payments-<lowercase-escrow>.json` remains the filename for each escrow.
The comparison requires stable Ed25519/secp256k1 identities and unchanged
secret-release public key and deployed source. Do not redeploy secret-release.
Check the public quote and page after upload, then exercise a small delegated
key, streaming call, per-key usage and final settlement with Andrew's injected
credentials before recording a live user journey.
