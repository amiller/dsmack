# Coupon redemption as a dsmack service

The service belongs on a dsmack peer. A sponsor contributes provider-backed
capacity through a protected setup path; a recipient claims a coupon from that
peer and receives an encrypted provider credential. The recipient then uses the
provider directly. A dsmack observer independently reads provider accounting and
produces signed evidence. Clients do not configure a standalone CVM.

The separate [v2 accepted-offer experiment](coupon-v2.md) binds terms to delivery
and observation for pre-bound synthetic recipients. It preserves v1 behavior and
does not qualify the accountless public-preview release path.

The [packaged development node](../../packaging/coupon/README.md) mounts these
services on a pinned Abalone peer registry, preserves its protected Noise identity
and tests claim/restart behavior inside a local image. It uses synthetic providers
and development evidence; it is not a qualified live issuer.
The [v3 atomic accountless experiment](coupon-v3.md) adds a synthetic first-bearer
claim and winner-bound replay while retaining those release qualification gates.

`DsmackCouponService` is the transport-neutral handler for this journey. The
experimental `peer_bridge.mjs` mounts it on an authenticated Abalone peer through
a supervised Python worker. This is exercised locally; no live peer or directory
entry has been registered. The injected
HTTPS transport can use a bounded subprocess for a provider request. The proposed
`/dsmack/coupon/1` identifier is explicitly experimental and unregistered; existing
`/abalone/redeem/1` behavior and wire identifiers are unchanged.

## Adapter and authorization contract

Construct the handler with an existing Store, trusted provider/account adapter,
observer signing key and authorized sponsor/observer subjects. The hosting peer's
protected setup supplies management/reporting credentials to that adapter. They
never appear in coupon frames or recipient configuration. Each handler instance
is bound to one sponsor/account context; there is no caller-selected provider
URL, upstream bearer token or arbitrary accounting ingestion endpoint.

A transport adapter calls `dispatch(frame_bytes, principal)`, where `principal`
is a `Principal(subject, frozenset(roles))` created **only after independent
transport/application authentication and authorization**. Constructing this Python
object itself performs no authentication. Never derive its subject or roles from
request JSON. Roles are sponsor, recipient and observer; the handler additionally
checks the exact subject granted access to the coupon. A stolen coupon token
alone therefore cannot authorize a different authenticated subject.

`provision(sponsor_principal, budget_nano_usd, recipient_subject)` is a protected
control-plane method, not a wire operation. It durably stores the random coupon
digest and its sponsor/recipient/observer grant atomically and returns the coupon token
for secure delivery. The sponsor cannot use the claim operation unless separately
granted the intended recipient identity. This does not restrict the sponsor's
upstream account revoke/edit powers.

Dispatch accepts a single JSON object with exact fields:

| Operation | Required fields beyond `id`, `op`, `coupon` | Authorized subject |
| --- | --- | --- |
| `claim` | `recipient_key`: base64 32-byte X25519 public key | Granted recipient with recipient role |
| `status` | None | Granted sponsor, recipient or observer with matching role |
| `observe` | `start`, `end`: timezone-aware timestamps; `challenge`: 64 lowercase hex characters | Granted observer with observer role |

Successful replies contain `{id,ok:true,result}`. Claim returns provider key ID
and encrypted delivery envelope only. Status returns state, key ID, accounting
block flag and false release authorization; it never returns the secret or
envelope. Observe fetches provider records internally, then returns a signed
observation. It does not accept rows, charged amounts, credentials, roles or
provider configuration from the frame. The relying verifier must originate and
track the observation challenge; this handler is not a contract replay ledger.

Requests/replies are limited to 64 KiB. Duplicate JSON keys, nonfinite numbers,
unknown fields and operations are rejected. All failures return the same generic
`request_failed` envelope without upstream exceptions or secrets. A failed
upstream issuance retains the durable non-retryable state. The peer must impose
stream size limits before buffering, timeouts, admission/rate limits and per-store
serialized execution. It must not log raw coupon frames or secret setup data.

## Authenticated peer mount

The companion Abalone adapter supplies a frozen fourth callback argument after
checking that the actual libp2p connection uses Noise:

```js
{ remotePeer, localPeer, protocol: '/dsmack/coupon/1',
  authenticated: true, transport: 'noise' }
```

The raw service descriptor preserves the original bytes, including duplicate
JSON keys, and applies its 64 KiB limit before buffering a length-prefixed frame.
The host must bound the entire stream using the descriptor's `timeoutMs`, abort
on expiry and sanitize service errors. Existing JSON service callbacks can keep
their prior behavior. The experimental mount requires this companion callback
contract; an older three-argument host is not compatible.

`createCouponPeerService({configPath, python, cwd, timeoutMs, maxQueue})` creates
the worker and returns `service`, `provision`, `pending`, `restart` and `close`.
Mount `services['/dsmack/coupon/1'] = bridge.service`. The default worker root is
derived from this module, not a private workspace path. The selected Python
interpreter must provide the existing `cryptography` dependency. `provision` and
`pending` are protected local supervisor methods, never peer-frame operations;
the local supervisor is itself trusted to supply an authorized sponsor context.
They do not prove that a remote sponsor is present. Mounting remote sponsor setup
requires a separately reviewed control-plane protocol.

The Node worker runs with inherited anonymous stdin/stdout pipes and no bridge
socket or HTTP listener. Only this trusted host may write peer identities to
those pipes. A JSON context fabricated by a client or passed directly to this
module by untrusted application code is not authentication. Roles come solely
from the protected peer-ID map loaded by Python. The callback context describes
the real connection key; no frame field can change it. The same host must keep
its peer private key if its service address should survive a restart.

Requests execute serially over one SQLite connection. Both mounts share bounded
per-peer pacing; see the [v2 admission limits](coupon-v2.md#authorized-status-and-admission-limits)
for defaults and limitations. The supervisor bounds the
queue, worker readiness, upstream operation and stream reads/writes. A worker
timeout stops its entire process group, including provider transport helpers,
waits for parent exit, and requires an explicit restart. It never resubmits the
timed-out request. Successful claim replay returns the stored ciphertext. An
interrupted creation remains `issuing` or `quarantined` across restart.

## Protected operator configuration and recovery

The config must be a regular file owned by the current UID, without hard links,
symlinks or group/world permissions. The state directory must have mode 0700 and
the same owner; config, signing key, lock and existing database files require
mode 0600 or stricter. File modes are local protection, not TEE sealing. The host
account and local supervisor can read the state and setup credentials. Run the
worker under a dedicated account when qualifying a deployment.

An explicit synthetic configuration is:

```json
{
  "version": 1,
  "state_dir": "/absolute/operator-state/coupon",
  "sponsor_subject": "peer:sponsor",
  "observer_subject": "peer:observer",
  "peers": {
    "ADMITTED_SPONSOR_PEER_ID": {"subject": "peer:sponsor", "roles": ["sponsor"]},
    "ADMITTED_RECIPIENT_PEER_ID": {"subject": "peer:recipient", "roles": ["recipient"]},
    "ADMITTED_OBSERVER_PEER_ID": {"subject": "peer:observer", "roles": ["observer"]}
  },
  "provider": {"mode": "synthetic"}
}
```

Replace placeholder peer IDs with actual alphanumeric libp2p identities; the
placeholders above are explanatory and are rejected as runtime peer IDs.
The recipient is pre-bound to the admitted transport key and selects its X25519
delivery key inside that authenticated claim. Losing either private key is not
automatic account recovery. Retaining or migrating transport/delivery keys is a
client policy decision; a new transport key needs protected authorization.

For NEAR, the provider object instead has exactly `mode: "near"`, `workspace_id`,
`organization_id` and an absolute `credentials_file`. That separate protected
JSON file has exactly `session_jwt` and `reporting_token`, both nonempty strings.
No token appears in request frames, command arguments, replies or SQLite. Setup
does not call the provider; an authorized claim can create a real key and an
authorized observer can fetch real accounting, so use explicit live qualification
parameters before operating this configuration. This local milestone used only
synthetic mode. The child receives PATH, LANG and LC_ALL where present, plus
unbuffered output; unrelated host credentials and Python override variables are
not inherited. The bridge is not a process sandbox or an attestation mechanism.

SQLite stores a binding to sponsor/observer subjects, provider/account scope and
the persisted observer public key. Startup rejects silent account or signing-key
replacement. A lifetime file lock rejects competing workers over the same state.
Persist the entire private directory; this prevents ordinary duplicate issuance
on restart, but does not detect restoring an old directory snapshot. Rollback
protection and approved signing-key provenance remain deployment gates.

`pending(sponsorContext)` returns only coupon digests and `issuing`/`quarantined`
states, with `automatic_retry_allowed: false`. It exposes no coupon token,
credential or delivery envelope. Inspection changes no redemption state. An
operator must reconcile provider metadata, one-time-secret loss and a reviewed
revocation/replacement policy; this interface has no reset-to-ready operation.

Peer identity does not establish measured-code identity. Real deployment must
bind the approved issuer/observer code and signing key through the peer's supported
attestation path, and supply durable state with rollback policy. The existing
runner interface provides evidence/key facilities for its profiles; this local
handler does not qualify one. No service directory/registry entry or endpoint
is claimed to exist.

## Local protocol harness

From the repository root:

```sh
python3 -m experiments.coupon_redemption.service
python3 -m unittest experiments.coupon_redemption.test_service -v
python3 -m unittest experiments.coupon_redemption.test_peer_worker -v
node --test experiments/coupon_redemption/test_peer_bridge.mjs
```

The harness creates a temporary store and synthetic provider, provisions a
recipient-scoped coupon, dispatches claim and observe frames, and prints only
summary statuses. It opens no network socket and uses no real account. Tests
cover caller/role failures before upstream effects, scoped status, forbidden
caller-supplied accounting/credentials, frame checks, private delivery, restart
replay and ambiguous issuance. Worker and supervisor tests additionally exercise
protected configuration, account/signer binding, lock ownership, large state,
bounded stream deadlines, process-group termination and nonretryable restart
after an interrupted provider creation. The companion Abalone cross-repository
test uses actual local Noise peers and this module to check private delivery,
wrong-peer refusal, restart replay, direct synthetic-provider use and a locally
signed observation. It is optional and does not make this repository depend on
a private adjacent checkout to run its own tests.

Generated observations remain `local-unattested` even if a dstack-derived key is
injected. Key derivation alone does not verify hardware or measured policy.
Contract release remains disabled pending the accepted issuer/observer evidence
verification, exact policy and replay/finality handling. Native provider-signed
billing receipts are not a prerequisite; provider accounting remains trusted.

[Local spike guarantees](../../experiments/coupon_redemption/README.md), [provider transport diagnostics](provider-transport.md),
and [dstack identity evidence collection](dstack-collection.md) are implementation aids for
service operators, not recipient-facing setup steps.

## Runtime portability

Python preserves the existing adapter/state-machine reference and cryptographic
tests; it provides no privacy or attestation advantage over TypeScript. The
two-runtime bridge adds interpreter/dependency packaging, framing, IPC deadlines,
process-group supervision and restart coordination. It currently uses POSIX
file permissions, advisory locks and process groups; Windows is not qualified.
Before deployment, compare a single Node/TypeScript implementation against this
reference. Migration must preserve raw-frame rejection, authenticated ACL and
coupon/key bindings, durable pre-call intent, replayed ciphertext, correction
blocking, process-interruption behavior, provider-direct observation and rejection
of all unattested settlement evidence. The local peer E2E is a useful cross-runtime
acceptance contract; no runtime rewrite is part of this milestone.

The [policy-bound v4 experiment](coupon-v4.md) adds pre-bearer issuer evidence and
separate issuer identity/issuance-policy commitments. Normal live issuance remains
closed until measured custody, authenticated configuration and external rollback
enforcement are qualified; its synthetic fixture does not approve NEAR secrets.
