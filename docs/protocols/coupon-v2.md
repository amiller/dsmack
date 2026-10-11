# Experimental accepted-offer contract

`/dsmack/coupon/2` is a local pre-bound, session-only binding experiment. It is
reusable protocol work, not acceptance of the accountless public preview. The
public preview requires a reviewed atomic first-bearer claim profile. This slice
uses synthetic provider fixtures and explicit admission of a development peer;
it qualifies no provider behavior, hardware identity, privacy claim or settlement.

The authenticated [peer mount](coupon-service.md) exposes `bridge.serviceV2` alongside
the existing `bridge.service`. Add the protected config field `issuer_peer_id`
with the actual hosting libp2p PeerId. The worker persists that identity and checks
it against callback `localPeer` on every v2 request. The Node host sends protocol
and local identity through the protected pipes; frames cannot select them. A
changed peer identity requires explicit reviewed state migration. Configs without
that field can continue serving v1 but cannot serve v2.

`provisionV2(sponsorContext, budgetDecimal, recipientPeer, claimExpiresAt)` is a
protected local control method. It atomically persists a coupon, its versioned
grant and the canonical offer. The recipient must already be admitted through
the protected peer map. This is not remote sponsor onboarding or first-bearer
claiming. `pendingV2(sponsorContext)` performs the existing read-only reconciliation
inspection after checking the configured issuer context.

## Exact offer schema

The `offer` operation returns `{offer,offer_hash}`. `offer` has exactly:

```json
{
  "version": 2,
  "coupon_digest": "64 lowercase hex characters",
  "issuer": {"peer_id": "configured actual PeerId", "policy": "experimental-local-unattested"},
  "provider": {"id": "synthetic-near", "scope_commitment": "64 lowercase hex characters"},
  "recipient_subject": "opaque pre-bound service subject",
  "delivery_profile": "x25519-aesgcm-session-only",
  "budget_nano_usd": "5000000000",
  "cap_semantics": "nominal-provider-limit",
  "claim_expires_at": "2030-10-10T00:00:00Z",
  "provider_expires_at": null,
  "sponsor_powers": ["revoke", "change_limits"]
}
```

The values above describe the schema; this explanatory example is not a runnable
offer. [offer_v2.py](../../experiments/coupon_redemption/offer_v2.py) is the exact validator. Provider ID is `near` or
the explicitly synthetic `synthetic-near`. The recipient subject uses ASCII
letters/digits plus `:_./-`, at most 200 characters. Peer IDs use ASCII letters
and digits, at most 200 characters. Fixed policy/profile/cap values and sponsor
power ordering are part of this version. Unknown or missing fields are rejected.

Budget is a canonical positive decimal string matching `[1-9][0-9]{0,18}` and at
most `9223372036854775807`. It is never converted to a JavaScript number. Expiry
is a valid UTC timestamp with exactly `YYYY-MM-DDTHH:MM:SSZ`, using ASCII digits
and years 0001–9999. Provider expiry is explicitly unknown/null. The claim expiry
does not promise provider-side credential expiry, a reserve of funds or an exact
admission cap. Sponsor revoke and limit-change powers remain allowed.

Canonical bytes are ASCII JSON with recursively sorted object keys, no whitespace,
the exact schema's fixed array order, and ordinary JSON integer `version:2`.
All strings are restricted to the validated ASCII forms above; no float, Unicode
normalization or alternate decimal spelling participates. `offer_hash` is lowercase
SHA-256 of `dsmack-coupon-offer-v2` followed by one zero byte and these canonical
bytes. The synthetic [cross-runtime vector](../../experiments/coupon_redemption/fixtures/offer-v2.json) includes a
uint63-max budget and expected hash/AAD. Its issuer name is a schema primitive
fixture, not a dialable libp2p identity.

The scope commitment hashes `dsmack-coupon-scope-v2`, a zero byte, a persisted
random 32-byte service salt, then the canonical protected provider/account binding.
It excludes credentials. The salt remains private; offers disclose no raw account
or workspace UUID. Offers for this service share the scope commitment, so this
does not promise unlinkability. Restart preserves salt, issuer, account scope,
canonical offer and accepted hash. Local state copying/rollback remains unqualified.

## Requests and expiry

Every operation has exactly `id`, `op`, `coupon` plus the fields below. IDs and
coupons retain v1 validation and frames remain bounded to 64 KiB.

| Operation | Additional fields | Authorized subject |
| --- | --- | --- |
| `offer` | None | Granted sponsor, recipient or observer |
| `status` | None | Granted sponsor, recipient or observer |
| `claim` | `recipient_key`, `offer_hash` | Granted recipient |
| `observe` | `start`, `end`, `challenge` | Granted observer |

The recipient fetches and explicitly accepts the offer authenticated by the
admitted service. It checks the offer's issuer against the dialed peer and retains
the delivery key for its private session. Claim compares the supplied hash to
the stored offer before any provider effect. Caller-supplied terms, principal,
roles, usage rows or provider credentials are rejected. Initial expiry is checked
against the service clock before the durable `issuing` transition.

Only a `ready` coupon can create a key, and it must be before expiry. Already
delivered same-key claims with the same accepted hash replay the original
ciphertext after expiry. This does not extend provider validity. Changed keys or
hashes never rebind a delivery; interrupted or quarantined creation never retries.
The declared profile keeps delivery keys/secrets in the client session; service
ciphertext is durable. Losing the session key requires a future explicit recovery
policy. It cannot silently recover the one-time upstream secret.

Grants persist `protocol_version`. V2 coupons are rejected by v1, preventing a
claim from bypassing offer acceptance or expiry. V2 rejects v1 coupons; there is
no implicit conversion or changed interpretation of old ciphertext.

## Delivery and observation binding

Claim results retain exactly `{key_id,envelope}`. The outer encrypted envelope
uses crypto-format `version:1`, X25519, HKDF-SHA256 and AES-256-GCM. HKDF info is
still `dsmack-coupon-v1` plus a zero byte plus the AAD; the accepted-offer binding
is a separate versioned AAD, not a changed cipher suite. That AAD is canonical
ASCII JSON with exactly:

```json
{
  "domain": "dsmack-coupon-delivery-v2",
  "version": 2,
  "offer_hash": "accepted hash",
  "coupon_digest": "bound coupon digest",
  "key_id": "issued provider key ID",
  "recipient_key_sha256": "hash of the recipient's raw 32-byte delivery public key"
}
```

The recipient independently reconstructs those bytes; trusting the envelope's
own `aad` field is insufficient. Provider key IDs are nonempty, bounded to 200
UTF-8 bytes and must use the v2 ASCII identifier form. Secrets are nonempty UTF-8
strings bounded to 8192 bytes before committing delivery, leaving encrypted
responses under the frame limit. Oversized/invalid provider results quarantine
the already-attempted creation without storing plaintext or blindly issuing again.

The observer fetches accounting through the configured authenticated provider
adapter. V2 receipts use domain `dsmack-coupon-observation-v2`, `version:2` and the
stored `offer_hash`, alongside the existing coupon/key/recipient/delivery hashes,
challenge, evidence ID and fetched window. Provider ID comes from that offer;
threshold is its canonical decimal amount, and cumulative charge is a canonical
nonnegative decimal string of at most 39 digits. A client checks the expected
offer, challenge, key and delivery/recipient commitments plus signature integrity.
The signing public key still has no approved measured provenance. Every receipt
remains `local-unattested`, and deposit release rejects it.

## Authorized status and admission limits

Status has exactly `state`, `claim_expired`, `accounting_blocked`,
`automatic_retry_allowed:false`, `deposit_release_authorized:false` and optional
`key_id` after delivery. State is `ready`, `delivered` or `reconciliation_required`.
Persisted `issuing` and `quarantined` map to reconciliation; serialized execution
does not promise visibility into an active provider call. The two boolean flags
carry independent expiry/accounting facts. `automatic_retry_allowed:false` means
no automatic new issuance: it does not prohibit an explicit same-key ciphertext
replay. Denied/unknown coupons have the same generic failure envelope and reveal
no another recipient's state, secret or ciphertext.

Both mounts share per-peer token buckets in the trusted Node process. Defaults
are capacity 60, refill one request per second, at most 1024 retained peer entries;
`rateCapacity`, `rateRefillPerSecond` and `maxRatePeers` configure bounded values.
The guard runs before reading frames, shares capacity across v1/v2, and ages out
idle buckets when the map is full. Buckets survive worker restart but not host
restart. Admission/queue/timeouts remain separate. Unknown authenticated keys
also consume entries: this is per-key pacing, not Sybil resistance or qualified
protection against denial of service. A full map can temporarily deny a new
legitimate peer until entries age out.

## Focused verification

```sh
python3 -m unittest experiments.coupon_redemption.test_service_v2 -v
node --test experiments/coupon_redemption/test_peer_bridge.mjs
```

Tests exercise semantic offer mutations before provider effects, exact schema and
ASCII/decimal limits, wrong issuer, ciphertext binding, expiry and delivered replay,
durable offers/salt, cross-version bypass rejection, scoped status and corrections,
oversized provider results, nonretryable reconciliation and shared rate bounds.
The companion Abalone actual-Noise E2E checks the client contract using this
worker, synthetic direct-provider use and signed observation. Live provider,
accountless release, attestation, VPN, retention and settlement qualification are
separate work.
