# Dsmack operator testnet: milestones 1–3

This acceptance track, dated 11 October 2026, makes the next product release
concrete. It supplements the [broader roadmap](roadmap.md); the numbers below
identify this track, not historical GitHub milestone numbers. A deadline can
bound a sprint, but cannot turn an unverified device journey into a pass.

| Milestone | Product outcome | Evidence required to pass |
| --- | --- | --- |
| 1. Usable coupon preview | A friend installs the tagged Abalone client, redeems one authorized coupon and completes useful inference. | Exact public package/checksum; independent installed walkthrough; verified issuer/provider policy; one bounded successful claim and response; visible remaining allowance and failure state; restart/recovery preserving claims and ambiguous obligations. |
| 2. Friends join and synchronize | Two independently operated physical Macs join from one pinned release, authenticate each other and exchange the scoped testnet capability. | Distinct enrollment identities and operators; actual first-open, bootstrap, fresh admission and matching scope/epoch/key commitment; quit/rejoin with preserved personal identity; real relay/seed outage and recovery observations; rejected invalid admission and stale/replayed exchange. |
| 3. Observable operator testnet | A newcomer can install the node and understand who was observed and which services are available. | Reviewed tagged node package, joining guide and versioned protocol profile; published read-only status with provenance and freshness; actual independent-device journey from milestone 2; stale/missing/refused status checks; explicit service opt-in and advertised scope where implemented. |

The coupon client is a peer, but installing it does not make the recipient a
service operator. Native membership does not grant coupon issuance, sponsor
credentials or treasury authority. Milestone 2 qualifies native capability
exchange; it does not qualify replicated coupon accounting. Milestone 3 cannot
pass solely because a dashboard renders or two processes run on the same Mac.

## What “synchronize” means

| State | Current mechanism | Acceptance boundary |
| --- | --- | --- |
| Admission and policy | Native peers read the pinned registry/category through a trusted RPC and submit fresh App Attest assertions. | Record identical chain, registry, category and supported protocol version, plus fresh successful checks on both devices. This is not a light-client consensus implementation. |
| Scoped testnet capability | Encrypted parcel transfers a shared signing key; peers verify its on-chain commitment and epoch. | Record matching scope, epoch and public commitment; never record the private key. Restart must reacquire under fresh admission. |
| Service advertisements | Coupon clients use explicit addresses; native peers use configured relay mailboxes. | Authenticated expiring network-wide discovery remains implementation work. A curated observation list must disclose its coverage and cannot grant authority. |
| Coupon obligations | One issuer owns durable claim/accounting state. | No cross-issuer replication is claimed. Preserve issuer affinity and ambiguous effects; never clone the ledger to create a second issuer. |
| Zcash wallet/chain state | Separate integration work. | Matching chain height or restoring a wallet does not establish any of the preceding properties or complete payment-to-coupon acceptance. |

## Current evidence and release gates

The [RC3 record](https://github.com/amiller/dsmack/blob/761cd18dc87f26b5fa72ccc8639ab7a0fbd74982/release/v0.1.0-rc.3.json) reports successful exact-package
restart and exchange between two processes on one operator Mac. Independent
first-open and second-team builder acceptance remain unrecorded. The
[Abalone preview.2 release](https://github.com/amiller/abalone/releases/tag/v0.1.0-preview.2)
explicitly pauses coupon redemption pending usable provider authorization/path.
Consequently none of these three milestones is established by those records.
A new qualification report must replace this baseline with dated observations.

For each run, retain source/artifact hashes, device and operator independence,
public configuration, observation times, steps/results, recovery behavior and
reviewer decision. Keep private identifiers, coupon bearers, credentials and raw
operator state out of public evidence. Report **passed**, **failed** (an exercised
condition did not hold), or **blocked** (the required run could not be performed),
with the precise reason. A simulated result may support development only.

The [joining guide](join-testnet.md) distinguishes available products; the
[protocol profile](protocol-profile-v1.md) specifies their authority boundaries.
The [release gates](public-testnet-release.md) and
[coupon operations](../packaging/coupon/public-testnet-operations.md) remain
applicable. There is no committed production/mainnet date here. Native participation
uses Base Sepolia; the coupon preview guard uses Base mainnet with bounded real
funds. “Public testnet” names a product release stage, not a promise of test currency.

After these milestones: qualify replicated coupon service accounting under
concurrency/partitions, complete ZEC payment → coupon → inference, and qualify
production custody, upgrade authority and incident recovery separately.
