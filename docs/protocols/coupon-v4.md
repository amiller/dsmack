# Policy-bound first-bearer experiment

`/dsmack/coupon/4` extends the [accountless v3 contract](coupon-v3.md) with immutable
issuer identity and issuance-policy commitments. It preserves the atomic first
claim, winning Noise peer and delivery key, lost-acknowledgement replay, expiry
and non-retryable ambiguous creation rules. Protocols 1–3 remain separate; their
coupons cannot be redeemed through protocol 4 or vice versa.

The exact offer has v3 fields with version `4` and this replacement issuer:

```json
{"peer_id":"ACTUAL_NOISE_PEER","policy":"dstack-tdx-coupon-v1","identity_policy_sha256":"64_lower_hex","issuance_policy_sha256":"64_lower_hex","issuer_public_key_sha256":"64_lower_hex"}
```

The signing-key hash commits SHA256 of the actual service signer's raw 32 bytes.
The immutable issuer object is durably pinned to the state database; changing its
peer, key or policy cannot reinterpret existing offers. Exact ASCII validation,
positive decimal uint63 amounts and canonical dates follow v2. Offer hashing is
SHA256 of `dsmack-coupon-offer-v4\0` followed by recursively sorted compact ASCII
JSON. Winner peer hashing uses `dsmack-coupon-recipient-peer-v4\0` followed by the
actual ASCII Noise PeerId. Delivery AAD and signed observations use their v4
domains and version, otherwise the v3 commitments. The encrypted wrapper remains
crypto version 1 and its HKDF info remains `dsmack-coupon-v1\0` plus exact AAD.
The [shared vector](../../experiments/coupon_redemption/fixtures/offer-v4.json) is synthetic and grants no admission.

## Public evidence before the bearer

`/dsmack/coupon/issuer/2` accepts an exact `{id,op:"info"}` request or
`{id,op:"evidence",binding}`. It accepts no coupon, account, role or claimed peer.
The info result is exactly `{version:2,issuer_public_key_hex,
identity_policy_sha256,issuance_policy_sha256}`. Discovery is untrusted until a
client verifies fresh evidence against independently pinned policies.

The evidence binding is the exact [issuer identity v2](../../runner/verify/DSTACK_ISSUER.md)
binding. The service checks actual callback `localPeer`, its actual receipt
signer and the protected identity policy before collecting a quote. The evidence
collector receives that same signing key rather than deriving a replacement.
Successful responses are `{id,ok:true,result}`; all denials are generic
`{id,ok:false,error:"request_failed"}`. Coupon frames remain 64KiB; identity frames
are capped at 2MiB, with the same bounded admission, deadlines, worker process
group termination and replay restrictions. Worker startup and per-operation
deadlines can be configured separately (each 50ms–120s, equal by default), so
short stream/lifecycle tests do not mistake interpreter startup under load for an
in-flight provider timeout. Exceptional escaped evidence larger
than the outer limit is refused. The internal anonymous-pipe limit is 3MiB for
identity only; ordinary coupon requests and responses retain 100KB limits.

Protected config may add `issuer_evidence` with exactly
`identity_policy_sha256`, `issuance_policy_sha256`, `socket_path`, `compose_file`.
The compose file is absolute, private and at most 100KB under the existing
protected-file reader. Normal collection requires dstack-sdk 0.5.4 and guest
version at least 0.5.7. These pins identify discovery and offer semantics; they
cannot approve issuance. The current development package does not include the
SDK closure or a qualified live custody factory.

## Independent issuance authority

A trusted service hook runs after durable winner/key/issuing intent and before
provider creation. The hook receives the coupon digest, actual winning peer,
delivery key, accepted offer hash and immutable issuer object. The default hook
refuses creation. Protected config, successful quotes, policy hashes or caller
booleans cannot construct this authority. The live NEAR profile is refused before
credentials are read until a separately qualified factory exists. This is the
integration point for external irreversible consume-before-create enforcement;
authenticated chain finality, measured configuration provenance, protected keys,
no live-memory cloning and provider-owner retrieval remain separate requirements.
A restart cannot infer creation permission from durable state or a stored receipt.

`test_issuer_fixture.py` is a named, unexported synthetic worker factory. It checks
the exact synthetic policy/compose and synthetic provider before authorizing a
fixture create. Its quote bytes contain JSON and are rejected by the normal DCAP
verifier. Only explicitly named synthetic verifier factories can interpret them.
Synthetic observations remain `local-unattested`; every observation still fails
deposit-release authorization. This milestone does not qualify live issuance,
provider accounting freshness or settlement.
