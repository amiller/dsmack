# Update the inference broker

The broker runs as shared Deno in the existing `relay-broker` project. W3 owns
`private-agent` and its deployment. This tool updates only `relay-broker`.
The existing CVM, persistent data directory, escrow and signing key identities
remain in place. It performs no chain transaction or substrate update.

## Encrypt provider credentials on the laptop

First deploy the committed broker without a provider envelope, using the
preparation and explicit apply commands below. Fetch its public environment key:

```sh
curl --fail --silent --show-error \
  https://pod.dstack.soc1024.com/relay-broker/inference/environment-key \
  --output environment-key.json
```

Pin `EXPECTED_PAYMENT_SIGNER` to the previously verified broker payment address
from `/relay-broker/payments/key`. Encrypt the existing key on its owning laptop:

```sh
deno run --allow-read --allow-write \
  --allow-env=WS_NO_BUFFER_UTIL,WS_NO_UTF_8_VALIDATE \
  applications/relay-broker/encrypt-provider-env.mjs \
  environment-key.json "$EXPECTED_PAYMENT_SIGNER" \
  "$HOME/.config/near-key" near-encrypted-env.json
```

The helper verifies the broker's EIP-191 signature over the project/purpose and
public encryption key, creates an ephemeral secp256k1 key, and encrypts with
ECDH, HKDF-SHA256 and AES-GCM. It writes only the ciphertext envelope, mode 0600,
without replacing an existing file. The provider key stays on its laptop and
inside the broker CVM. The helper reads no shell secrets file.

A raw key becomes `NEAR_API_KEY` for the operator-only provider check. For
credit-backed delegated keys, use an explicitly prepared local JSON object with
`NEAR_MANAGEMENT_TOKEN` and `NEAR_REPORTING_TOKEN` instead. A NEAR inference
`sk-` key does not authorize delegated-key creation. Management requires the
funded Cloud user's access JWT; reporting requires its organization usage token.
No provider value belongs in configuration, source, evidence, shell arguments,
or the page bundle.

The deployment manifest contains only
`env.NEAR_ENCRYPTED_ENV = JSON.stringify(ciphertextEnvelope)`. The shared handler
decrypts it in CVM memory with the project-scoped dstack key
`/tee-daemon/projects/relay-broker/inference-env-v1`. No native environment
passthrough bridge, credential copy to zed/Mac, or secret-release change is used.

## Prepare the broker package

Copy `config.inference.example.json` into the existing broker configuration's
`inference` block. Set the funded workspace/organization IDs, approved model and
compose hashes. Preserve the existing `payments.escrow`, `payments.codeHash`,
classes, admission settings and operator token hash. The model's full maximum
context is `requestTokenCeiling`; its nanoUSD/token tariff must cover the maximum
input/output/cache rate. Normal delegated-key allocation also needs a confirmed
token-unit purchase.

```sh
python3 applications/relay-broker/deploy-inference.py prepare \
  --config /absolute/path/broker-config.json \
  --operator-token-sha256 "$EXISTING_OPERATOR_TOKEN_SHA256" \
  --encrypted-env /absolute/path/near-encrypted-env.json \
  --out /absolute/path/prepared-upload
```

Omit `--encrypted-env` for the first deployment that exposes the environment key.
The argument accepts only the exact ciphertext fields
`v`, `ephemeralPublicKey`, `iv` and `ciphertext`; plaintext credential objects are
rejected. Source, schema and the NEAR verifier are packaged locally with Deno's
bundler. The helper that reads the laptop key is excluded from the server archive.
The prepared manifest has no `env_passthrough` setting.

## Apply the prepared update

Inspect the package, then explicitly apply it:

```sh
python3 applications/relay-broker/deploy-inference.py deploy \
  --prepared /absolute/path/prepared-upload \
  --url https://pod.dstack.soc1024.com \
  --evidence /absolute/path/deployment-evidence \
  --apply
```

Without `--apply`, the command validates the package and returns without network
requests or credential reads. With it, the tool reads `TEE_DAEMON_TOKEN` from its
process environment or parses its one static assignment in the existing laptop
`~/.oauth3-prod-secrets.env`, without sourcing that file. It sends the tarball and
manifest to `POST /_api/projects`, then promotes only
`POST /_api/projects/relay-broker/promote`.

Evidence contains whitelisted project metadata and public keys, never environment
values or raw API responses. The tool checks shared Deno, preserves the current
escrow/code hash, polls readiness for at most 30 seconds, and compares the broker
Ed25519 key, payment identity, and secret-release public key/project metadata.
The persistent file remains `payments-<lowercase-escrow>.json`. Existing key names
`egress-grants-v1` and `payments-grants-v1` and their project paths stay unchanged.
Secret-release receives no deployment or mutation request.

## Local checks and token escrow

```sh
deno test --allow-read --allow-write --allow-net \
  --allow-env=WS_NO_BUFFER_UTIL,WS_NO_UTF_8_VALIDATE \
  applications/relay-broker
```

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
