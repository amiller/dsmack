# Local container and dstack evidence collection

This is a command-driven experiment, not a deployed redemption service. The image
defaults to runner help. No provider credentials, state database or source outside
this experiment directory enter the Docker build context. Do not push the image:
this source candidate is not cleared for publication.

Build and run locally from this directory:

```sh
docker build -t dsmack-coupon-observer:local .
docker run --rm --read-only dsmack-coupon-observer:local --help
docker run --rm --read-only --entrypoint python dsmack-coupon-observer:local \
  -m unittest experiments.coupon_redemption.test_dstack_identity -v
```

The compose file is intended for a host that already has the dstack guest-agent
socket and the locally loaded image. It neither provisions a CVM nor distributes
the image. `create_host_path: false` prevents silently substituting a directory
for a missing socket. There are no published ports. The read-only root filesystem
and dropped Linux capabilities reduce incidental privileges; they are not TEE
evidence. A private persistent state mount and authenticated service transport
are still needed for an eventual redemption service.

For evidence collection inside a real dstack guest, obtain a fresh, unpredictable
32-byte challenge from the relying verifier, then run:

```sh
docker compose run --rm --entrypoint python observer \
  -m experiments.coupon_redemption.dstack_identity \
  --challenge-hex "$VERIFIER_CHALLENGE_HEX"
```

The command returns an Ed25519 public key, raw TDX quote, event log, VM config,
challenge, and expected report data. Every bundle is explicitly
`unverified-dstack-quote`. The key seed is never printed. SDK failures are redacted.
The normal factory accepts only an existing absolute Unix-socket path and does
not fall back to a simulator or remote HTTP endpoint from environment variables.
A malicious process controlling the socket can still fabricate outputs; choosing
the socket does not establish hardware trust.

The report-data binding is exactly:

```text
SHA512(b"dsmack-coupon-observer-identity-v1\0" || ed25519_public_key[32] || challenge[32])
```

Use `DstackIdentity.signing_key` with the observer's evidence signer when wiring
the components. The quote binds a signing key and challenge, not a specific
usage observation by itself; verify the separately signed observation, its key,
challenge, deposit/coupon scope and freshness. This module deliberately provides
no permissive remote verifier: `verify_remote_identity` always rejects. Neither a
decoded quote nor an echoed expected report-data field counts as verification.

The relying verifier must validate hardware signatures/collateral and TCB policy,
extract report data from the authenticated quote, reproduce the binding, check
accepted image/compose measurements and event log, and assess KMS key custody and
upgrade/rollback policy. App-scoped deterministic key derivation alone does not
prove only one code version can access the key. A fresh quote is not proof that
old SQLite state has not been restored. Native provider signatures are not
required by the accepted observer design; authenticated provider accounting and
the measured observer remain trusted inputs.

This adapter targets the TDX `GetQuote` path. It does not qualify AMD or GCP vTPM
evidence, nor use the more general versioned `Attest` API. The pinned Python SDK
is `dstack-sdk==0.5.4`; `get_key(..., algorithm="ed25519")` requires guest-agent
support from dstack OS 0.5.7 or later. It uses a domain-specific derivation path
because selecting the key algorithm does not itself separate derivations.

References: [official Python SDK](https://github.com/Dstack-TEE/dstack/blob/master/sdk/python/README.md),
[published SDK 0.5.4 metadata](https://pypi.org/pypi/dstack-sdk/0.5.4/json),
[guest-agent API](https://github.com/Dstack-TEE/dstack/blob/master/sdk/curl/api.md).

Before a real run, supply an existing approved dstack guest with a compatible
socket, a privately transferred reviewed image, fresh verifier challenge and
accepted measurements/KMS policy. Provider preflight/usage additionally needs
the account session or organization reporting token and exact organization,
workspace, key and date scope. Set secrets through the chosen runtime's secret
mechanism; do not place them in the image, compose source, command arguments,
test fixtures, or evidence output. No external deployment is performed here.

The base image uses a mutable Python tag and transitive Python dependencies are
not fully hash-locked. Production measurement approval requires a reviewed,
reproducible/pinned artifact; this local Docker recipe is not that qualification.
