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
   identity; do not delete them, clone identities or replace the committed key to
   recover. Distinguish a completed run from an expected procedure.
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

Abalone [preview.2](https://github.com/amiller/abalone/releases/tag/v0.1.0-preview.2)
currently states redemption is paused pending usable provider authorization/path.
Publish that state even if the public transport and issuer admission succeed.
Before reopening, exercise the authorized bounded coupon-to-inference journey
and preserve its accounting/recovery evidence. Neither a relay health check nor
an issuer probe qualifies provider authorization or a usable paid response.

An operator release packet must pin chain 8453 and the exact coupon guard,
confirmation profile and budget separately from native chain 84532. Keep claims,
ambiguous provider effects and delivered credentials through upgrade; never
recover by restoring an older ledger as authoritative or blindly reissuing.
