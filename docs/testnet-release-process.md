# Managed Dsmack public testnet releases

A public **join link may be published before an independent second Mac has
completed acceptance**. Its release notes must say what is available and what
remains unverified. The stable entry point is [Join the Dsmack testnet](join-testnet.md);
a release is not promoted to independent-operator qualification by publishing it.
This process covers native participation and the separate coupon issuer profile.

## Stages and ownership

| Stage | Required result | Allowed claim |
| --- | --- | --- |
| Reviewed candidate | Selected public source, independent review, checks and exact artifact manifest; no private history/state in payload. | Candidate ready for operator validation. |
| Managed public testnet | Release owner validates admission of the exact artifact; operator records bootstrap/relay/chain availability, upgrade/recovery procedure and support window; reviewed join page points at the immutable tag. | Available to try; list any unverified first-open or independent-device gates. |
| Friend acceptance | An independent operator completes actual install, admission, exchange, restart and failure/recovery steps; coupon acceptance is separately exercised. | Only the corresponding evidenced milestones pass. |
| Production | Separately reviewed custody, authority, accounting, funding, operational and recovery gates. | No production date or readiness is implied by the testnet stages. |

The repository/release maintainer owns source and artifact publication. The
operator of the pinned relay/seed and coupon issuer owns those services' uptime,
state, sponsor funds and incident response. A reviewer validates the exact change
and evidence before integration/promotion. For each release packet, name the
actual owner, reviewer, service operator, support/contact route and availability
window; a generic role table is not an on-call roster. Repository issue reports
must contain reviewed diagnostics only, never bearers or operator state.

## Native release packet and ordering

The currently available native package is the legacy AttestNode
[v0.1.0-rc.3](https://github.com/amiller/apple-attest-p2p/releases/tag/v0.1.0-rc.3).
It retains its original release location/name. The
[verification manifest](https://github.com/amiller/dsmack/blob/761cd18dc87f26b5fa72ccc8639ab7a0fbd74982/release/v0.1.0-rc.3.json),
[compiled network pins](../node/mac/NetworkConfig.swift) and
[protocol profile](protocol-profile-v1.md) describe that baseline. Source
publication in this repository does not retag or replace that signed artifact.

RC3's original source/tag is public in
[`amiller/apple-attest-p2p`](https://github.com/amiller/apple-attest-p2p/tree/v0.1.0-rc.3),
at `6a3cca34f53a3cf8fe241aca4a8d8b3e0c76ef81`. Historical instructions to fork
and check out RC3 refer to that repository, not the fresh Dsmack history. Use
that exact source to reproduce RC3. A new Dsmack candidate uses its own reviewed
source and toolchain/build instructions and needs fresh admission qualification;
changing even a compiled documentation URL changes the measured executable.

## Current native joining incident

Observed 11 October 2026 at 21:56 UTC: the RC3 NFT-network seed was
retrying because it could not recover the committed shared key. The other
inspected seed belongs to a different registry/network, while two additional
development processes use a local Anvil chain. These observations do not establish
a same-network public pair or prove that no other key holder exists. No current exchange was observed. This blocks
advertising the native joining path as available despite successful package,
relay and chain checks. The operator must complete separately reviewed seed
recovery and demonstrate actual exchange before changing that public status.
No epoch reset, identity replacement or other live mutation is authorized by
this document; historical exchange evidence does not close this incident.

## New candidate checklist

For a new candidate:

1. Review source, fixture/package inventory, version compatibility and release
   notes. Pin source revision, supported OS/hardware/security settings, build
   toolchain, app version, signing identity, executable/ZIP hashes and notarization
   evidence. Keep earlier tagged artifacts immutable.
2. Pin protocol version, chain, registry, category, badge/account contracts,
   relay endpoint and seed mailbox in the packet. Review any changed admission
   or administrative authority and record who can execute it. Endpoint strings
   and a release tag do not prove service health.
3. Build/sign/notarize through the [release instructions](https://github.com/amiller/dsmack/blob/761cd18dc87f26b5fa72ccc8639ab7a0fbd74982/release/README.md)
   on the supported remote Mac. Verify the exact extracted download. The
   [builder guide](https://github.com/amiller/dsmack/blob/761cd18dc87f26b5fa72ccc8639ab7a0fbd74982/release/builder-guide.md) documents build registration;
   registration is not proof of genuine live App Attest admission.
4. Before changing admission, preserve operator/personal state and document
   compatibility with the current seed and old clients. Validate the exact new
   artifact's fresh admission in the intended profile, then coordinate any
   required seed/relay/contract changes. Do not strand existing participants by
   admitting clients whose seed cannot serve them. Chain administrator mutations
   and spending must remain within separately established authorization.
5. Record a timestamped coupon-free/read-only service observation and exact-app
   exchange/restart evidence where available. Preserve enrollment and Keychain
   identity; do not delete them or clone identities. Replacing the committed key
   requires separately reviewed, owner-authorized epoch recovery. Distinguish a completed run from an expected procedure.
6. Publish the reviewed release and update the stable join page to the exact
   immutable tag/checksum. State known blockers, sponsor/seed dependencies and
   the scope of observed acceptance. Independent-Mac acceptance can remain open.
7. Invite friends using that link. Retain their actual independent-device evidence
   before marking [milestones 2 or 3](operator-testnet-milestones.md) passed.

RC3 requires preserving app state and Keychain through upgrade and restart.
Its recorded network cutover requires RC2 users to update; do not assume any old
binary is a rollback option. A rollback must itself remain admitted and compatible
with the current epoch/state. If it does not, stop advertising availability and
prepare a reviewed corrective release. Do not reset the registry, epoch or
personal accounts as an undocumented recovery shortcut.

## Next-release experience to qualify

The intended friend path is one stable join link → a signed download → open →
automatic join → a clear connection and scoped-key synchronization result.
Receipt/artwork progress and coupon service readiness must be shown separately.
Failure should name the failing step and offer one useful diagnostic report.
No source checkout, developer config, terminal or signing account should be
required for the ordinary friend path; command-line checks remain optional.

A future in-app updater should show an available admitted release, verify the
release/package before replacement, restart and preserve identity and receipts.
The release owner must qualify admission and compatibility **before** offering
that update. Failed download, verification or restart must leave a recoverable
installation and understandable state. This is a product acceptance requirement;
it is not functionality supplied by RC3 or by this documentation change.

## Two real processes on one Mac: local qualification gate

Before asking a friend to debug joining, rehearse actual native exchange and
restart with two processes on one supported physical Mac, using two reviewed,
distinct valid enrolled members. Reuse valid existing enrollments where available;
an expired enrollment needs renewal within the operator’s authorized scope. Record
the new member after renewal instead of claiming the old enrollment was preserved. This tests the real protocol and same-host
reliability; it does not establish independent devices, operators or compromise
domains. Independent friend acceptance remains pending until its later run, after
the public join link is available.

The [native state implementation](../node/shared/Node.swift) scopes persistent
enrollment by chain, registry, category and configured `name`. It takes a
nonblocking exclusive lock on that identity's state; starting the same identity
twice must refuse with `identity already running`. Distinct names select distinct
state domains, but do not alone prove distinct enrolled keys. Preserve both
existing state files and Keychain identities; do not copy enrollment state or
reset a name as a recovery shortcut.

The [GUI developer path](../node/mac/GUI.swift) accepts `--config` with one
reviewed configuration file, uses its explicit name, and forces persistent
identity. Normal GUI launch reuses its saved participant name, so opening the
same installation twice is not a second-member experiment. The compiled release
continues to reject overrides of pinned network/admission settings. These are
operator rehearsal details, not steps for a friend to join.

The operator records the exact signed executable, two distinct valid member
identities/mailboxes, configuration provenance, chain/category/protocol and
current key epoch. Route the second peer to the first's reviewed mailbox. Require
actual fresh check-in, encrypted parcel exchange, matching public commitment/epoch,
and a key-possession result; two running processes or a relay HTTP 200 do not pass.
Quit and restart each process in turn under the supported bootstrap conditions,
then verify fresh exchange/rejoin and preservation of each personal account and
receipt. Check for unexpected new `BadgeClaimed` events and token-counter growth:
an unchanged `participantOf` mapping alone does not rule out a duplicate NFT.
Keep at least one verified current-epoch key holder running throughout
the rehearsal. Before restarting the seed, require a separately reviewed recovery
peer configuration pointing to the other verified holder: an empty seed `peer`
does not rediscover it. If both processes exit, their RAM-held keys are lost;
without another live holder, recovery requires an explicit owner-approved plan,
not an automatic epoch reset. Record refusals and bootstrap/relay dependencies. Do not log the shared
secret or treat same-host success as replicated coupon accounting.

Retain a dated pass/fail record with the exact steps and observations. This
rehearsal does not authorize new enrollment, network administration, receipt
creation or spending beyond the operator's existing scope. A future updater must
also pass a verified update/restart and failed-update recovery on this local
setup before its simpler friend journey is advertised. Current RC3 updates remain
manual as described in the [joining guide](join-testnet.md).

## Current-source local protocol qualification

The [11 October V2 rehearsal](../packaging/participation/same-mac-v2-qualification-20261011.json)
passed real Apple Development attestation, two same-Mac peer exchanges, and a
participant restart preserving its enrolled member. It used the current native
CLI core on an isolated Anvil chain with fixture funds. Independent review checked
source/signature evidence, decoded receipt linkage, key-possession results and
cleanup. Raw receipts and block headers were not retained after the fixture retired.
This qualifies that local protocol component only: public RC3 seed recovery, GUI
first-open, personal-account/NFT continuity and independent-friend acceptance remain
open. It does not close the current public joining incident or milestone 2.

## Service observation and outages

Native relay observation is read-only:

```sh
curl --fail --silent --show-error https://pod.dstack.soc1024.com/apple-attest-p2p-relay/nft/info
curl --fail --silent --show-error https://pod.dstack.soc1024.com/apple-attest-p2p-relay/nft/status
```

`/info` reports configured chain/registry/protocol and sponsor identity. `/status`
reports sponsor write pause and journal pending/completed transactions. These do
not establish current seed health, a successful App Attest handshake, online
membership, or coupon readiness. The [read-only release checker](../packaging/participation/README.md) bundles
these observations with exact-package checksum and chain configuration checks.
Record observation time and failure response;
do not convert a successful HTTP response into a peer count. Check the exact app
journey for fresh native admission and key acquisition.

If relay/RPC/seed access fails, show unavailable/unknown and retain identity and
operator state. Relay operators preserve the durable transaction journal and
pending entries; the [relay operations guide](../node/relay-hosted/README.md)
describes sponsor-write pausing and nonce coordination. Recovery must reconcile
pending transactions before new writes. A dashboard outage must not grant or
revoke peer authority, and cached green status must expire.

## Coupon issuer releases are separate

The [Mac coupon profile](../packaging/coupon/public-testnet.md) and
[operations runbook](../packaging/coupon/public-testnet-operations.md) govern
workload/source/compose pins, fresh issuer admission, private control channel,
credential renewal, funding and durable obligation recovery. Native RC3 joining
does not install this service or opt a participant into it.

Abalone [preview.4](https://github.com/amiller/abalone/releases/tag/v0.1.0-preview.4)
publishes the new Linux client archive `abalone-993de6e.tar.gz`, its installer and
signed wallet-epoch inputs pinned to that immutable release. Check
`release-provenance.json`, `SHA256SUMS` and `FRIEND-SHA256SUMS` for the exact bytes
and limitations; do not substitute an earlier preview archive.
The client preserves sanitized admission diagnostics and retries one transient
DNS failure on a verification GET within the original deadline. Inference POSTs
are never automatically replayed.

Redemption remains **paused** until the full five-cent Mac coupon document canary
passes and the owner handoff is ready. A separate already-created one-cent key
produced the correct synthetic document answer through genuine encrypted NEAR
inference; it did not exercise a fresh coupon claim or establish owner acceptance.
This is a synthetic text-only preview on a trusted Linux Node 24 host, with an
identity-only Mac issuer, operator/KMS-readable custody and an explicitly admitted
verified OutOfDate NEAR debug profile. It does not qualify PDF use, OS/tool
isolation or stronger private guarantees.
Publish that state even if the public transport and issuer admission succeed.
Before reopening, exercise the authorized bounded coupon-to-inference journey
and preserve its accounting/recovery evidence. Neither a relay health check nor
an issuer probe qualifies provider authorization or a usable paid response.

An operator release packet must pin chain 8453 and the exact coupon guard,
confirmation profile and budget separately from native chain 84532. Keep claims,
ambiguous provider effects and delivered credentials through upgrade; never
recover by restoring an older ledger as authoritative or blindly reissuing.
