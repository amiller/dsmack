# Public testnet coupon service profile and rollout

This is a reviewable deployment profile, not a deployed-testnet claim. It uses
public source, issues and reviewed releases. Environment topology remains private
development, private staging, public testnet, and public production **not yet
deployed**. Public testnet means an explicitly advertised, stable service for
external recipients; it never makes operator configuration or debug access public.

The existing trial demonstrated a public WSS/Noise connection, genuine issuer
admission, direct provider delivery and a bounded inference. Its runtime admission
still says `private-debug-staging`, with operator-readable credentials and no
rollback/private-issuance qualification. An open gateway URL or renamed dashboard
is insufficient to promote it. This profile requires the operational gates below.
It does not close the broader [gift milestone](https://github.com/amiller/dsmack/milestone/1).

## Supported first testnet slice

One persistent dstack-backed issuer and one qualified direct NEAR adapter suffice;
a fleet, router, pool treasury and deposit settlement are separate. External users
need the reviewed Abalone client, a coupon and the signed public bundle. They need
no issuer SSH credential, provider account, funded wallet or VPN. A client peer is
not an independently operated service node or proof of network membership.

Keep the current signed debug policy truthful: `debug-staging` is the cryptographic
trust profile, independent of the deployment's advertised testnet environment.
The existing runtime string is not a production qualification. The initial testnet
explicitly retains `operator-secret-access`, `application-exec`, `debugger` and
`host-clock`, synthetic-prompt restrictions and signed budget limits. Display
`private_issuance_qualified=false`, `rollback_qualified=false`, and
`deposit_release_authorized=false`. Any policy expansion requires separately
reviewed controls and client support; editing discovery cannot grant it.

The current coupon guard uses Base mainnet, chain 8453, under
[`base-mainnet-rpc-safe-debug-v1`](../../experiments/coupon_redemption/BASE_TRIAL.md).
“Testnet” describes this dsmack deployment, **not** the guard's funding domain.
The configured RPC supplies `safe`; independently authenticated L1 finality is
not verified. Real gas and provider credit remain bounded separately. No purchase,
funding, new guard or paid request is authorized by this document. Provider gateway
and model TCB exceptions, when signed and explicitly opted into, retain their
warnings; the public status is not provider/model admission.

## Public discovery and immutable release contract

Publish one stable HTTPS discovery URL containing a versioned public manifest and
immutable, checksum-addressed client/bundle links. Record its operator, update
procedure and rollback/fencing rule in the reviewed rollout packet. For v1, one
operator-hosted index is acceptable; coverage, availability and censorship
resistance remain limited. Clients independently verify the bundle's trusted
approval root, signatures, exact issuer identity/compose/key/policy and fresh
attestation over the actual Noise connection. The index and dashboard grant no
membership, execution, credential or spending authority.

The selected endpoint is a public `/dns4/.../tcp/443/wss/p2p/...` route through
existing TLS gateway infrastructure, verified from outside the operator host.
Publish only the reviewed peer identity, endpoint, source/image/compose pins,
public approval/pin and artifact checksums. No operator config, provider/account
identifiers, credential inventory, coupon hashes, recipient identities, raw quotes
with unnecessary joins, prompts, traces, bearer responses or private attach output
belongs in discovery/status. Contributions and independent listings are separate
[discovery work](https://github.com/amiller/dsmack/issues/34); do not invent a
participant count from relay transactions or repeated probe clients.

## Sanitized operational status

[`tools/coupon_testnet_status.py`](../../tools/coupon_testnet_status.py) exports
an allowlisted JSON status from a **public manifest** and the normal client's
coupon-free issuer probe report. It does not contact the provider, inspect the
Store/config/operator channel, verify a quote itself, or authorize a claim. The
result explicitly attributes the observation to the operator. Run the independently
verifying client probe first; arbitrary JSON claiming success is not evidence.

The v1 public manifest has exactly these fields:

| Fields | Meaning |
| --- | --- |
| `version=1`, `network`, `environment=public-testnet` | Stable deployment identity; not provider-chain or membership authority. |
| `trust_profile=operator-readable-debug` | Honest current privileged-control boundary. |
| `peer`, `bundle_url`, `bundle_sha256` | Public WSS/Noise route and immutable HTTPS bundle without URL credentials/query tokens. |
| `source_revision`, `image_digest`, `app_id`, `compose_sha256` | Reviewed source and actually observed deployed pins. |
| `chain_id=8453`, `guard_address`, `confirmation_profile=base-mainnet-rpc-safe-debug-v1` | Declared current guard/trust domain. |
| `approval_expires_at`, `claiming_available_until` | UTC `Z` deadlines; latter is an operator-advertised window, not a promise that a particular coupon is ready. |

Record `observed-at` when the normal probe completes, not when copying its report:

```sh
python3 tools/coupon_testnet_status.py \
  --manifest /absolute/public-testnet-manifest.json \
  --probe /absolute/public-issuer-probe.json \
  --observed-at 2030-01-01T00:00:00Z
```

The example time must be replaced with the real completion time. Status expires
after 300 seconds; a future time beyond 30 seconds is refused. Consumer views must
also recompute age against their own clock instead of freezing an old green badge.
The output distinguishes `issuer-reachable`, `stale`, `expired` and `refused`.
An open advertised claim window is not issuance availability. Provider/model state
remains `unknown-requires-fresh-recipient-admission`, and independent participant
count remains unknown. Missing feed/input/export failure must show **unknown**,
not the last healthy state. Export refuses unknown fields, mismatched peer/app/
compose and probes that sent a bearer or performed a provider effect. This is an
allowlist, not a general secret detector; only reviewed public inputs are allowed.

Publish a status endpoint or static JSON with freshness/provenance and client-side
age checks, separately from private alarms. Authentication, capacity, one-claim gas
reserve, expiry and coupon readiness are checked at the actual OFFER/CLAIM boundary.
A read-only status outage cannot bypass that boundary or block peer operation.
See [dashboard #28](https://github.com/amiller/dsmack/issues/28).

## Reviewable promotion packet and execution order

1. Identify the exact existing infrastructure/endpoint to use and its public-testnet
   ownership. Review the complete delta, image/source closure and actual measured
   compose. Preserve private staging as a distinct deployment/authority boundary.
   Reusing the current issuer requires explicit promotion review and preserved
   obligations; creating an isolated issuer requires separate capacity/state
   approval. Neither happens as a side effect of documentation or publishing source.
2. Capture a full protected state/SQLite-WAL backup, live build/container/volume/
   logging pins and durable obligations; require no active claim jobs and acquire
   the existing worker lock before restart/migration. Never reset winners, grants,
   pending/quarantined effects, delivered envelopes or aggregate reservations.
   Historical failed grants remain evidence, not retries. Keep backups private.
3. Admit exact reviewed controls against fresh genuine quote/key/compose evidence.
   Public transport must expose only recipient issuer-info/evidence and coupon
   protocols. Operator frames stay on a private owner-only channel; keep container
   logging disabled, no secret argv/env, and verify no public log retrieval.
4. Run a detached supervised controller with restart ownership and independent
   liveness checks; stdin closing stops the current launcher. Record host reboot,
   controller death, renewal, operator absence and shutdown behavior. Detached
   operation during one turn is not a proven reboot recovery or uptime SLA.
5. Renew NEAR owner authorization privately using the documented fixed-host flow,
   exact session user-agent and durable rotated-refresh capture. No token/body is
   public. Refresh before expiry; defer same-volume signed-config rotation while
   jobs are active. Stop advertising claiming availability if renewal fails or its
   remaining window cannot cover the job deadline and safety margin. Reconcile
   ambiguous provider creates, never blindly repeat them. Reporting credentials
   remain private and read-only; missing reporting does not authorize settlement.
6. Immediately verify network fees, sufficient existing issuer reserve, provider
   backing, approval/config lifetime and fresh claim window. Read-only readiness
   must not create keys or spend. Publish available/unavailable/unknown accurately;
   budget increases, new funds and paid experiments need their own scope review.
7. From an independent client, verify actual public WSS/Noise identity and signed
   pins; do coupon-free OFFER/STATUS checks only for an authorized unclaimed test
   gift. Preserve recipient keys for CLAIM/WAIT. Successful OFFER is not proof that
   paid inference or unattended renewal will succeed. Keep production “not deployed”.
8. After independent packet review, obtain approval of the exact publication/
   deployment actions. Publish the immutable release/bundle, stable discovery and
   fresh sanitized status; record exact URLs/checksums/observed times. Run the
   authorized bounded end-to-end acceptance separately. Do not claim general
   anonymity, private key custody, rollback protection or deposit settlement.

## Public development and credential-free CI

The service package's [paired-source pin](paired-source.json) identifies an
allowlisted Abalone module closure, distinct from the recipient release version.
Do not change that pin merely to match a client tag: compare the selected module
bytes and qualify any real interface change. Export the exact reviewed pair with
[`tools/coupon_package.py`](../../tools/coupon_package.py) `--export-pair`; record
its archive SHA-256 and the public immutable HTTPS URL in the release packet.
Publication of those selected bytes needs review/approval; no private history or
operator credentials belong in the archive or URL.

The [manual package workflow](../../.github/workflows/coupon-package.yml) accepts
that public URL. It validates the allowlisted pair before running
[`tools/coupon_ci.sh`](../../tools/coupon_ci.sh), which tests reproducible export,
normalized readable image modes, secret-context exclusion and actual network-none
packaged behavior. After approved source/archive publication, obtain a real hosted
manual pass against the exact URL and hash. Then separately review enabling PR CI
with the fixed public dependency and digest. No adjacent private checkout,
repository read token or management secret may be required by public CI. Until
these steps pass, local checks are evidence for their named candidates, not hosted
CI or a publicly reproducible release. Pin the dependency/version description to
the actual archive; a workflow file alone is not an installed successful pipeline.

## Operational acceptance still required

The release packet must include successful unattended credential renewal or an
explicitly staffed availability window, controller restart without obligations
loss, status-feed stale/refused/expiry behavior, an independent acquisition and
public peer probe, actual supported claim/recovery behavior and a useful bounded
inference. Fault drills use fixtures or isolated state first; they must not revoke,
reissue or interrupt a live user's delivered credential. Record provider failures
separately from issuer delivery and chain wait. Redemption latency, time to first
token and throughput are separate measurements; see
[optimistic redemption #46](https://github.com/amiller/dsmack/issues/46).
