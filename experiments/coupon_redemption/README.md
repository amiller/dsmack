# Coupon redemption and accounting experiment

A local service reference and synthetic demonstration of a NEAR-backed coupon claim,
recipient-encrypted credential delivery, and a dsmack observer that queries
provider accounting independently of the inference path. The [peer mount](SERVICE.md)
adds a protected Node/Python bridge exercised on actual local Noise peers.
Demonstrations use synthetic data; this milestone makes no live provider request,
deploys no service and implements no contract.

From the repository root, using Python 3.10+ and the repository's pinned
`cryptography` dependency:

```sh
python3 -m unittest experiments.coupon_redemption.test_spike -v
python3 -m experiments.coupon_redemption.demo
python3 -m unittest discover -s experiments/coupon_redemption -t . -p 'test_*.py'
node --test experiments/coupon_redemption/test_peer_bridge.mjs
```

The demo uses a temporary database, generated local keys, synthetic provider
responses and no external network. It emits status/accounting only, never the
coupon bearer token or decrypted inference credential.
The bridge tests require Node and POSIX process/filesystem facilities. The
existing Python-only diagnostics container does not package the Node peer host;
it is not a deployment image for this mount.

## State and authority

An issuer generates a random coupon and stores its digest and budget. The first
redeemer binds the coupon to an X25519 recipient key. SQLite commits `issuing`
before calling the provider. The returned secret is immediately encrypted using
an ephemeral X25519 key, HKDF-SHA256 and AES-256-GCM; authenticated context binds
coupon digest and provider key ID. Only the encrypted envelope is persisted.
A successful retry returns that same envelope to the same recipient key.

A provider timeout, malformed response or failed delivery persistence quarantines
the coupon. Process death can leave `issuing`; both states block further creation.
The operator uses `pending()` and the deterministic upstream key name to
investigate/revoke stranded credentials. There is deliberately no reset/retry
button: upstream creation has no documented idempotency support, and its
one-time secret cannot be recovered after a crash. Losing the recipient private
key also has no recovery path in this slice.

NEAR keys are workspace siblings, not cryptographic children. Creation requires
a management session JWT and uses `spendLimit.amount` in nano-USD ($5 is
5000000000). Limits are cumulative admission checks and can overshoot during a
request or concurrent requests. They do not reserve funds. The account owner
retains revoke/limit-change powers; this is acceptable for the proposed sponsor
contract, whose deposit is returned only after qualifying evidence.

## Observer and settlement boundary

`Near.usage_rows` fetches key-filtered organization reporting exports with a
separate organization-wide read-only reporting token. A filter is not a narrower
credential scope. It includes service and inference charges, follows opaque
pagination with fixed filters, and rejects mixed key/workspace attribution.
`Store.ingest` deduplicates `(source,id)` and rejects conflicting values atomically.
A correction durably blocks accounting/signing, even after restart or an empty
subsequent export, until an explicit reconciliation procedure is implemented.
It is an internal trusted-observer API, never a recipient-upload endpoint.

`observe_and_sign` fetches through the provider adapter and signs an observation
with Ed25519. Evidence binds coupon digest, provider key, recipient, encrypted
delivery digest, threshold, provider-reported usage, challenge and observation
window. This establishes local signature integrity only: all generated evidence
is explicitly `local-unattested`. `authorize_deposit_release` fails closed.
The optional rational reward preview is hypothetical and never authorizes money.

The accepted deployment architecture is an approved attested dsmack issuer and
observer interacting with NEAR over authenticated HTTPS. Its contract verifier
must check attestation/approved code and signing-key binding, coupon-specific key
and private-issuance evidence, challenge/freshness, unique deposit/evidence IDs,
and a provisional **reported charge >= the deposit's exact threshold** rule, not a provider
"limit reached" flag. Eligible charge categories, correction/finality policy and
the final release predicate are unresolved. Provider accounting remains trusted. A native provider
signature over debit data is not required by this design.

Production still needs that attestation verifier and on-chain verifier/replay
state, live qualification of the bounded provider HTTPS transport, secure management
session provisioning, observation completeness and correction policy, sealing
and rollback protection, issuance evidence linking custody to measured code,
recipient authentication/recovery and reconciliation operations. The signed
observation currently reports all locally ingested rows, not only its latest
fetch window; start/end describe that fetch, not completeness. A signature cannot
prove the recipient never subsequently shared its secret, or defeat manufactured
usage/self-dealing. This experiment makes no such guarantee.

The SQLite file and WAL contain coupon/account metadata. Provision private
permissions and encryption before persistent use. Local SQLite and Python memory
are not TEE-protected; plaintext memory erasure is not guaranteed.

## Provider references

- [Create API key](https://docs.near.ai/api-reference/workspaces/create-api-key-for-workspace)
- [Usage reporting and per-request costs](https://docs.near.ai/cloud/guides/usage-reporting)
- [Response signatures](https://docs.near.ai/cloud/verification/cloud-api/response-signatures)

Response signatures cover inference bodies, not the key's billing debit. The
observer is a separate accountability service; recipient inference remains direct.
