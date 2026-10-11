# Protocols

These references describe implemented interfaces and their explicit experimental
limits. A wire contract or historical vector does not qualify a live deployment.

| Reference | Scope |
| --- | --- |
| [App Attest lab](app-attest.md) | Challenge, enrollment, assertion and parser rules |
| [Runner](runner.md) | Compose, attestation, proxy, keys, receipts, volumes and tasks |
| [Runner peer](runner-peer.md) | Guest socket API and task exchange |
| [Coupon service](coupon-service.md) | Peer adapter, authorization, persistence and recovery |
| [Coupon v2](coupon-v2.md) | Accepted offers and delivery binding |
| [Coupon v3](coupon-v3.md) | Atomic accountless first claims |
| [Coupon v4](coupon-v4.md) | Issuer/policy-bound offers and issuance authority |
| [Base guard](base-guard.md) | Single-RPC debug issuance profile |
| [Provider transport](provider-transport.md) | NEAR credential creation and diagnostics |
| [dstack collection](dstack-collection.md) | Observer evidence collection |
| [dstack issuer verifier](../../runner/verify/DSTACK_ISSUER.md) | Cryptographic identity and challenge policy |
| [Ethereum finality](../../runner/chain/ethereum-finality/README.md) | Separate pinned finalized-consumption experiment |
| [Contract guard](../../contracts/COUPON_ISSUANCE_GUARD.md) | On-chain consumption guard |

Use the [architecture](../architecture.md) to locate implementations and
[release acceptance](../release.md) to distinguish the selected Mac profile
from other available experiments.
