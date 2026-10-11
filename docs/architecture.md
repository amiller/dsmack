# Architecture

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

See [protocols](protocols/README.md), [release acceptance](release.md) and
[the charter](charter.md) before making privacy or decentralization claims.
