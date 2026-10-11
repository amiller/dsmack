# Architecture

Dsmack's native participation network and workload runner provide infrastructure
for services. Coupon issuance is the first packaged service; Abalone is its client.
Joining as a native peer does not automatically run an issuer or replicate its
accounting database. The selected preview operates one persistent issuer. A
mandatory-service mechanism or developer-curated service subscription is not
implemented by native joining.

A friend uses Abalone to accept a coupon, bind the claim to recipient-generated
keys, and receive encrypted provider access. The issuer records an issuance
attempt with the selected guard before creating a capped credential. The client
then sends encrypted inference requests directly to the provider.

| Component | Source | Role |
| --- | --- | --- |
| Client | [Abalone](https://github.com/amiller/abalone) | Coupon verification, decryption and inference |
| Coupon service | [experiments/coupon_redemption](../experiments/coupon_redemption/README.md) | Claims, issuance, durable replay and accounting |
| Peer bridge | [node/coupon-node.mjs](../node/coupon-node.mjs) | Authenticated peer service and protected operator pipes |
| Mac worker | [mac_live_worker.py](../experiments/coupon_redemption/mac_live_worker.py) | Current identity-only issuer profile |
| Workload runner | [runner](../runner/README.md) | App Attest binding, compose VM, controlled egress and receipts |
| Admission verifiers | [verifier/core.py](../verifier/core.py), [runner/verify](../runner/verify/macrunner.mjs) | Apple and provider evidence verification |
| Native participants | [node/shared](../node/shared/Node.swift), [Mac build](native-build.md) | Attestation, account keys and participation |
| Contracts | [contracts/src](../contracts/src/CDRegistry.sol) | Build/admission registries, accounts and issuance guards |
| Packaging and operations | [packaging/coupon](../packaging/coupon/README.md) | Source export, pinned images, supervision and status |

The selected preview is a Mac issuer with an ordinary local ARM container,
Base mainnet's debug single-RPC guard and a Linux recipient. A network release
stage and the blockchain network are separate settings. The amd64 dstack and
Ethereum finality implementations remain available as distinct profiles.

A PeerId, app/code identity, contract address and participant NFT identify
different things. None alone proves independent operators or confidential
execution. The host proxy and stand-in KMS retain access to issuer secrets;
named volumes are operator-readable and can be rolled back. Direct inference
E2EE is a separate boundary from issuance custody.

## Workload packaging and authority

The coupon image contains JavaScript peer transport and Python service logic,
including issuance, accounting and replay handling. Python also supports
verification, testing and release tooling; it is not merely an example workload.
The native Mac participant is Swift and its signed app does not require the friend
to install Python.

The [ARM Dockerfile](../packaging/coupon/Dockerfile.mac-base) builds the service
image. A restricted app-compose manifest selects the image and configuration;
admission binds its exact hash alongside the runner and issuer identity.
The operator can replace the workload, but clients must still verify the selected
signed admission policy. Source publication alone does not authorize a new build.

The [issuance guard](../contracts/src/application/CouponIssuanceGuardExperiment.sol)
records consumption attempts under an immutable issuer and policy hash. Its
deployment address is separate from a peer's account or membership identity.
Local persistent accounting/recovery state and the on-chain journal serve
different purposes; native shared-key exchange does not replicate either one.

## Relationship to dstack

The runner adopts the exact-byte compose-hash convention and a stable application
key API analogous to dstack's `get_key`. Provider verification can inspect dstack
TDX evidence and on-chain admitted compose hashes. See the
[runner protocol](protocols/runner.md) and [peer interface](protocols/runner-peer.md).
These interfaces do not transfer confidential-VM guarantees to the operator-readable
Mac profile. The dstack/TDX deployment remains a distinct profile, not a property
of every Dsmack peer or service.

See [protocols](protocols/README.md), [release acceptance](release.md) and
[the charter](charter.md) before making privacy or decentralization claims.
