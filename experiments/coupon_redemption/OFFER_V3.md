# Local atomic accountless claim

`/dsmack/coupon/3` exercises the first-bearer entry needed by an accountless gift.
It uses actual local authenticated peers and synthetic provider fixtures. It is
progress toward that release path, not qualification of public acquisition,
funding, provider secrecy, VPN privacy, attestation or deposit settlement.

A sponsor provisions a gift without naming a recipient. Whoever first presents
the coupon over Noise with valid accepted terms and a delivery key wins an atomic
claim. The service derives the claimant from the real remote connection; request
JSON cannot select a peer, subject or role. No prior account, recipient ACL entry
or pairing is required. Provider inference remains separate and direct.

## Mount and stable offer

Use the same protected operator config and pinned `issuer_peer_id` described for
[v2](OFFER_V2.md). Mount `bridge.serviceV3` at `/dsmack/coupon/3` alongside the
existing descriptors as needed. `provisionV3(sponsorContext, budgetDecimal,
claimExpiresAt)` creates a coupon, v3 grant and offer in one local transaction.
`pendingV3(sponsorContext)` gives the protected read-only ambiguous-claim inventory.
Neither method is a remote sponsor setup endpoint.

The exact offer schema retains every v2 field and constraint except:

- `version` is integer `3`.
- `recipient_subject` is absent.
- `claim_policy` is exactly `first-authenticated-bearer`.

The offer never acquires a mutable winner field. SHA-256 commits the canonical
ASCII JSON after `dsmack-coupon-offer-v3` and one zero byte. Budget remains a
positive uint63 decimal string, policy remains `experimental-local-unattested`,
scope remains the persisted protected account commitment, claim expiry is
distinct from unknown provider expiry, and sponsor revoke/edit powers remain.
[offer_v3.py](offer_v3.py) validates this exact schema; the synthetic
[shared vector](fixtures/offer-v3.json) pins hash, peer commitment and AAD bytes.
Its short peer/issuer labels are primitive fixtures, not dialable peer addresses.

The offer/hash operation, claim, status and observe frames have the same exact
fields as v2. A claim must include `offer_hash` and `recipient_key`; it cannot
include a principal, role, peer, provider configuration or accounting bundle.
All three versions reject coupons belonging to another version. V1/v2 grants,
clients and already-stored encrypted deliveries retain their interpretations.

## Atomic winner and replay

Before any provider key creation, `Store.redeem` validates the 32-byte X25519
delivery key and starts `BEGIN IMMEDIATE`. A trusted service guard inside that
transaction reloads and verifies coupon protocol, persisted offer/hash, account
and issuer binding, positive budget, initial expiry and unclaimed authority.
It inserts the actual winning PeerId, delivery public key and accepted hash,
updates the coupon's recipient grant to a service-derived subject, and commits
those facts together with `issuing` and the bound delivery key. It calls the
provider only after that commit. Guard failure rolls back all winner/grant/intent
changes; it cannot leave an apparent winner with a retryable coupon.

Independent database connections competing for the same coupon serialize this
transition. One winner may create a key. A competing peer cannot create, rebind
or obtain the winner's ciphertext, even if it knows the coupon and copies the
winner's delivery public key. Same-peer, same-key, same-hash delivered retries
return the original envelope after claim expiry and after restart. The recipient
must retain both its Noise private key and X25519 private key for that replay;
a newly generated transport identity is a different claimant.

Initial expiry blocks before durable intent and provider effects. A timeout or
ambiguous creation remains reserved to its winner in `issuing`/`quarantined` and
requires operator reconciliation. A crash after provider success can lose the
one-time secret but cannot reset the winner or silently issue another key. There
is no reset-to-ready or transparent key-loss recovery path.

## Access and receipt binding

While `ready`, any authenticated token bearer may read the authoritative offer
and minimal status. Once reserved, only the bound winner and protected configured
sponsor/observer may read offer/status. Other peers receive the same generic
failure as an unknown coupon. Status includes state, expiry/accounting flags,
false automatic new-issuance/release authorization and optional delivered key ID;
it exposes no actual winner PeerId, credential or envelope. Claim ciphertext is
returned only to the winner presenting the bound delivery key and accepted hash.

Unknown peers receive no sponsor or observer role. Provider observation remains
restricted to the configured observer, which fetches accounting itself. The
accountless bearer path does not grant provisioning, reconciliation inspection,
caller accounting ingestion or settlement authority.

Encrypted delivery retains crypto-format `version:1` and the existing cipher/HKDF
construction. Its canonical AAD instead has exactly:

```json
{
  "domain": "dsmack-coupon-delivery-v3",
  "version": 3,
  "offer_hash": "stable accepted offer hash",
  "coupon_digest": "coupon digest",
  "key_id": "provider key identity",
  "recipient_key_sha256": "hash of raw 32-byte delivery public key",
  "recipient_peer_sha256": "domain-separated authenticated claimant commitment"
}
```

The peer commitment is SHA-256 of `dsmack-coupon-recipient-peer-v3`, one zero byte,
then the actual canonical ASCII PeerId. The client reconstructs these bytes from
its retained transport identity and delivery key; it does not trust the envelope's
own AAD. V3 observations use domain `dsmack-coupon-observation-v3`, integer
`version:3`, the same offer hash and peer commitment, and the existing key,
recipient-public-key and encrypted-delivery hashes. Amounts retain v2 decimal
domains. These are locally signed assertions labeled `local-unattested`; all
settlement entry points continue to reject them.

## Limits and focused checks

Possession authorizes the first claim. Copying, forwarding or theft before binding
can change who wins. A sponsor who retains a coupon can self-claim using an anonymous
peer; the service cannot prove that first bearer is a different natural person.
The custody boundary is that sponsor control replies do not disclose a separately
bound winner's credential. It does not promise absence of self-dealing, organic
use or recipient sharing. Whether the provider account owner can later retrieve
a supposedly one-time secret still needs real API qualification. No locally
signed receipt removes those provider or economic assumptions.

Client keys/secrets are session-only in this experiment; service ciphertext,
winner metadata, grant and intent are durable. Retention UI, secure deletion,
account migration and rollback protection are unqualified. The shared per-peer
token bucket/queue/stream/worker bounds apply to v3 too; connection-key pacing is
not Sybil resistance or a funded-abuse policy. No gas or on-chain step is invented
for this local off-chain claim.

```sh
python3 -m unittest experiments.coupon_redemption.test_service_v3 -v
node --test experiments/coupon_redemption/test_peer_bridge.mjs
```

Tests use two independent Store connections and competing threads, prove intent
is committed before a blocked provider call, reject loser retrieval, check atomic
rollback after winner writes, preserve reservation after crash following provider
success, and exercise expiry/hash/key/protocol failures before creation. The
protected worker tests cover unknown-peer claims, operator-role refusal and restart.
The companion Abalone E2E uses two actual Noise clients with no recipient ACL,
then validates the winning private delivery, replay, synthetic direct use and
observer integrity. Full existing v1/v2 checks remain required.
