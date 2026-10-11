# dstack issuer identity verifier

This implementation authenticates a dstack TDX issuer identity against an explicit
locally approved policy. It does not approve private coupon issuance, provider
account ownership, KMS secrecy, rollback resistance or settlement. No positive
real quote or live node qualification is claimed by its offline tests. The old
[observer collector](../../experiments/coupon_redemption/dstack_identity.py)
remains unchanged and its remote verifier still refuses.

## Interface and challenge

After `npm ci` in this directory, import `createDstackIssuerVerifier` from
[dstack_issuer.mjs](dstack_issuer.mjs). Supply exactly `{policy,
expectedPolicySha256}`; the expected hash must be obtained from independently
approved configuration. The normal factory cannot inject a quote verifier.

`challenge({remotePeer, issuerPublicKeyHex})` returns the exact object:

```text
{version:2, peer_id, public_key_hex, challenge_hex, policy_sha256}
```

The connection adapter supplies the actual authenticated Noise issuer peer ID.
Do not use a request's claimed peer field. The discovered issuer key may be
untrusted initially; both the quote and possession signature must bind that exact
key and actual peer. The verifier generates the 32-byte challenge, retains its
expected binding and time, and consumes it before asynchronous verification.
Challenge expiry, clock regression, replay and concurrent reuse refuse admission.
Pending challenges are bounded to 256 and active verification to four processes.
`close()` refuses new work and aborts active DCAP workers.

Report data is all 64 bytes of:

```text
SHA512("dsmack-coupon-issuer-identity-v2\0" || canonical_binding_json)
```

Canonical JSON sorts the exact ASCII keys, has no whitespace, and carries only
the fixed integer version and ASCII strings. Public key, challenge and policy
digest are lowercase 32-byte hex. The possession signature is Ed25519 over
`"dsmack-coupon-issuer-possession-v2\0" || report_data` under that public key.

`verify(bundle, {remotePeer})` accepts exactly `{domain,binding,quote_hex,event_log,
app_compose,possession_signature_hex}`, where domain is
`dsmack-coupon-issuer-identity-v2`. The quote is bounded to 128 KiB, event log to
1 MiB/2048 entries, and exact UTF-8 compose bytes to 128 KiB. The API snapshots
input and approved policy before awaiting external work. A successful normal
result has `scope:"issuer-identity-only"`,
`evidenceStatus:"verified-intel-tdx-identity"`, matched peer/key/policy/compose,
verification time and expiry, **`privateIssuanceQualified:false` and
`rollbackQualified:false`**. Keep it bound to the same connection and stop using
it at expiry; it is not a reusable production approval token.

## Approval policy

The exact policy shape is:

```text
{version:2, challenge_ttl_ms, approved_measurements:[
  {compose_sha256,mr_td,rtmr0,rtmr1,rtmr2,
   runtime_events:{"app-id":hex,"key-provider":hex,"os-image-hash":hex}}
]}
```

The challenge lifetime is 1000–300000 ms. There must be 1–64 exact measurement
sets, with no wildcard/default acceptance. Compose hashes are 32-byte hex, boot
MRTD/RTMR pins are 48-byte hex. Required runtime values are exact nonempty hex
payloads, not arbitrary friendly names. The policy hash is
`SHA256("dsmack-coupon-issuer-policy-v2\0" || sorted_policy_json)`.
The same compose in a different app identity or key-provider scope is refused.
App/KMS pins identify the approved measured scope; they do not prove that an
account owner cannot retrieve a credential or that cloned/restored state cannot
issue twice. Those require separate custody/recovery authorization.

The first quote profile is deliberately narrow: Intel DCAP quote v4, TD10,
`UpToDate` TCB, debug disabled, reserved attribute bits clear and SEPT_VE_DISABLE
set. The genuine worker uses locked `@phala/dcap-qvl` 0.6.6 and Intel PCS
collateral. It verifies vendor-root signatures, certificate/CRL/TCB/QE validity
against actual current time. Caller-provided `report_data`, status or a parsed
quote alone cannot satisfy it. The pinned library's collateral requests have no
abort hook; a minimal-environment child process is killed as a process group at
the 15-second deadline and the parent waits for close before completing refusal.
Errors and stderr are never forwarded to the caller; output is bounded to 4 KiB.

The issuer verifier recomputes every runtime-event digest before replaying RTMR3,
checks exactly one pre-ready compose/app/KMS/OS event and one `system-ready`,
and checks the resulting RTMR3 against the authenticated quote. V1 digests use
the little-endian event type, separators, event name and decoded raw payload;
V2 digests use the canonical event JSON and require the exact supplied preimage.
Boot lanes are pinned using authenticated measurements; unverified boot event
display labels cannot approve a new boot image. Sources:
[pinned dstack runtime preimages](https://github.com/Dstack-TEE/dstack/blob/182fa12bd763a1de4e5f01a16f5d35baf93e0bae/dstack/cc-eventlog/src/runtime_events.rs),
[pinned TDX event validation](https://github.com/Dstack-TEE/dstack/blob/182fa12bd763a1de4e5f01a16f5d35baf93e0bae/dstack/cc-eventlog/src/tdx.rs).

Approve actual measured worker/issuer code, immutable image digests, all mutable
configuration authority, guest boot measurements, KMS release policy and rollback
handling independently before allowing production issuance. Pinning compose text
with mutable image tags does not prove the reviewed application bytes ran. Do
not turn synthetic fixture measurements into an approved live allowlist.

## Collector and runnable verification

The new [issuer collector](../../experiments/coupon_redemption/dstack_issuer_identity.py)
preserves the legacy observer domain. It defaults to the derived key path
`dsmack/coupon-issuer/v2/ed25519`. Integration may supply the actual service
Ed25519 signer; it must not silently substitute another observer key. The live
factory requires an explicit absolute Unix socket, `dstack-sdk==0.5.4` and guest
Version at least 0.5.7. Neither environment-selected simulators nor an HTTP key
service are normal paths. Collection returns unverified evidence only.

SDK 0.5.4 `get_quote(bytes)` passes the raw bytes as hex without hashing; its
`get_key` forwards path/purpose/`algorithm:"ed25519"`, and `decode_key` yields the
32-byte seed. The inspected wheel SHA256 is
`3c64d021408cc95def04332caab4593efb9d91fe87553d1f9d31c7c6e0fee07b`.
The declared SDK requirements are in
[requirements-dstack.txt](../../experiments/coupon_redemption/requirements-dstack.txt);
deployment packaging must lock the transitive closure separately.

Get the issuer public key from the collector, then run this verifier process
with independently approved policy and the authenticated peer/key:

```sh
node dstack_issuer_cli.mjs --policy approved-policy.json \
  --expected-policy-sha256 <approved-hash> --peer <actual-peer-id> \
  --issuer-public-key <public-key-hex>
```

It prints a binding challenge, then reads one bounded evidence JSON from stdin
through EOF. Within that same process/lifetime, collect the challenge using:

```sh
python3 -m experiments.coupon_redemption.dstack_issuer_identity collect \
  --binding-file challenge-binding.json --compose-file app-compose.json \
  --socket /var/run/dstack.sock
```

The binding file contains the printed `binding` object, not the wrapper. The
collector runs from the code root with the declared Python dependencies; retain
neither private seed nor live operator state in fixtures. The verifier CLI's peer
argument is an operator input, so the CLI alone does not prove network connection
authentication. The peer adapter must supply that context in the integrated path.

## Tests and remaining evidence

```sh
node --test dstack_issuer.test.mjs
python3 -m unittest experiments.coupon_redemption.test_dstack_issuer_identity -v
```

Run Python from the code root; use the declared SDK environment for its actual
SDK RPC-shape test. Named `createDstackIssuerVerifierForTesting` accepts a
synthetic low-level adapter and always returns `synthetic-only-not-hardware`.
Tests cover binding/possession substitutions, challenge replay/expiry/closing,
policy mutation, report type/version/TCB/debug/boot mismatch, event payload/name
tampering, v1/v2 preimages, missing/duplicate/post-ready events, app/KMS changes
and resource bounds. Normal-path tests reject malformed quotes and enforce
worker timeout/reaping; they do not qualify a positive real quote.

The selected live dstack issuer has not been inventoried or qualified here. A
live drill must independently record exact node identity, SDK/guest versions,
genuine quote/collateral, measured bundle/policy pins and actual authenticated
channel. Private-issuance, no-owner-secret-knowledge, anti-rollback, provider
accounting, VPN, installed-client retention and chain finality remain separate
release evidence. This module is runnable cryptographic identity verification,
not an always-refuse placeholder and not approval to deploy.
