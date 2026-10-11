# Dsmack protocol profile, revision 1

This is a source-grounded profile of the native RC3 participation protocol and
the separate coupon service, dated 11 October 2026. **Document revision 1 is not
wire protocol version 1.** Native RC3 selects wire version 2. This profile does
not invent a common replication protocol between these components.

## Native participation profile

The release's [compiled network](../node/mac/NetworkConfig.swift) pins Base
Sepolia (chain 84532), registry
`0xd4B33C83576a6049d29c6B849ec73491e52781a0`, category
`0xbbbb9ea44ff8fbd35e60f06bdf52445c102d8d1ffa10f5df51582dbd45cda9b6`,
protocol version 2, relay
`https://pod.dstack.soc1024.com/apple-attest-p2p-relay/nft` and seed mailbox
`release-nft-seed`. It also pins the badge and personal-account factory contracts.
The [RC3 artifact record](https://github.com/amiller/dsmack/blob/761cd18dc87f26b5fa72ccc8639ab7a0fbd74982/release/v0.1.0-rc.3.json) identifies the signed build
and checksum. These are release pins, not newly checked health observations.

A native member is admitted using category/App Attest identity. A relay mailbox
name is a routing label, not an authenticated member identity. Personal receipt
account keys are separate from the network's shared signing key. The
[implementation](../node/shared/Node.swift) keeps the shared key in process memory
and creates a fresh P-256 receiving session key. Persistent enrollment/personal
identity survives supported restart; restart reacquires the shared capability.

### Messages and validation

The [relay](../node/relay-hosted/README.md) transports JSON over HTTPS and sponsors
allowlisted on-chain actions. It provides `/info`, `/status`, enrollment/execution
and `/send/<mailbox>` / `/recv/<mailbox>` routes. Mailboxes are untrusted,
unauthenticated transport; TLS does not make their `from` field an identity.
The production node uses these message types:

| Message | Fields besides `type` and routing `from` | Meaning |
| --- | --- | --- |
| `HELLO` | `member`, `joinTx`, `sessionPublic`, `nonce` | Request a scoped key after an on-chain check-in. The sender derives the authenticated member from the checked transaction, not the claimed `member` field. |
| `PARCEL` | `parcel`, `receiptTx` | Encrypted key and on-chain release commitment. |
| `PROOF` | `signature` | Shared-key signature over the pending challenge. This shows key possession, not a unique device or exclusive custody. |
| `ERROR` | `reason` | Exchange failed; grants no authority. |

`STOP` is a test-only control, rejected unless explicitly enabled by a test
caller. It is not a public shutdown command.

[Request encoding](../node/shared/Protocol.swift) binds action, category, owner,
member signer, receiving-session hash, nonce, expiry, scope, public key and envelope
digest to chain ID and registry. Version 2 adds the key epoch under
`TEE_INTEROP_DEMO_V2`; version 1 uses `TEE_INTEROP_DEMO_V1` and has no key epochs.
Join is action 0, bootstrap 2 and key receipt 3. Existing identifiers must not be
renamed when editing product prose.

A parcel is exactly 254 bytes: sender session public key (65), recipient session
public key (65), recipient member (32), scope (32), and AES-GCM combined sealed
payload (60). P-256 ECDH plus HKDF-SHA256 derives the 32-byte transport key.
Associated data is `TEE_INTEROP_PARCEL_V1`, chain ID, registry, scope, recipient
member and recipient public key; its SHA-256 is the HKDF salt, and the same domain
string is HKDF shared info. The sealed plaintext is the 32-byte shared signing key.
The implementation checks recipient/session binding, current eligibility, exact
parcel commitment and imported public-key commitment before retaining it.

[Chain checks](../node/shared/Chain.swift) require a successful receipt from the
configured registry in the RPC-reported canonical block, exactly one matching
check-in, a fresh check-in timestamp (less than 60 seconds old, at most five
seconds in the future), correct release digest/context and active scope admission.
Request deadlines derive from a recent chain timestamp. The contract enforces
its own assertion/nonce/epoch policy. RPC-reported state is trusted: this is not
a light client or independent finality verification.

The epoch and committed public key are shared state. Peer mailboxes, arbitrary
service advertisements, coupon ledgers and treasury balances are not replicated
by this exchange. Losing the configured seed or relay can stop new acquisition;
there is no documented automatic alternative-peer directory. A missing seed must
not cause a participant to replace an existing committed key.

## Coupon service profile

Coupon peers use libp2p Noise and explicit dialable addresses. The selected
[paired-source manifest](../packaging/coupon/paired-source.json) pins the Abalone
transport module closure independently from the recipient package version.
The [bridge](../experiments/coupon_redemption/peer_bridge.mjs) declares
`/dsmack/coupon/1`, `/dsmack/coupon/2`, `/dsmack/coupon/3`,
`/dsmack/coupon/4` and `/dsmack/coupon/issuer/2`. Available handlers depend on the
selected node/profile; the presence of a constant is not deployment support.

Use the [service protocol](../experiments/coupon_redemption/SERVICE.md),
[v2 offers](../experiments/coupon_redemption/OFFER_V2.md),
[v3 offers](../experiments/coupon_redemption/OFFER_V3.md) and
[v4 offers](../experiments/coupon_redemption/OFFER_V4.md) for exact frames,
operations, recipient binding and retry semantics. Fresh issuer admission binds
both Noise peers, nonce, code, workload compose, issuer key and signed policies.
A Noise connection alone does not admit the workload or provider.

One issuer owns durable coupon/accounting state. Ambiguous external effects stay
pending/quarantined; copying an old database or retrying provider creation cannot
be used as recovery. No native membership receipt authorizes issuer secrets,
sponsor spending or a replicated coupon ledger. The selected coupon guard uses
Base mainnet (8453), unlike native participation's Base Sepolia. See the
[deployment profile](../packaging/coupon/public-testnet.md) for its RPC-safe
confirmation assumptions and bounded real-funds policy.

## Secure hardware, authority and compatibility

The native design uses fresh receiving keys and fresh App Attest code admission
before scoped secret release. This is the useful connection to secure-hardware
research: persistent hardware identity alone is not permission for any executable
to receive a key. Nevertheless, recipients receive the full shared secret; this
is not threshold custody, and multiple participants do not imply resistance to
one compromised full-secret holder.

The selected Mac coupon profile is identity-only with operator/KMS-readable
secrets. It does not establish operator-resistant custody or rollback protection.
The native relay can delay/drop traffic; its sponsor can stop paying gas. The
pinned RPC is a chain-state trust boundary, and contract admission/upgrade
administration remains a privileged boundary. Direct provider inference has its
own admission/encryption and retained provider-account powers.

Release changes must name the exact wire versions, code/compose and chain-policy
pins, migration and backward-compatibility decisions. Preserve personal identity,
coupon obligations and immutable prior release artifacts. Never silently fall
back to an older/weaker profile when admission fails. Follow the
[managed release process](testnet-release-process.md) before directing new users
to a changed network. [Milestone acceptance](operator-testnet-milestones.md)
requires real device evidence beyond schema, crypto or same-host tests.
