# Release and acceptance

The public source and MIT license are available for development. The selected
Mac-issuer/Linux-recipient preview remains in preparation. A source checkout,
a successfully built image and a live accepted release are separate milestones.

## Selected profile

- Native Apple runner on an Apple Silicon Mac, with the
  [ARM Base-only coupon package](../packaging/coupon/mac-base.md).
- Apple App Attest identity and fresh issuer/workload/peer binding. The Mac
  host/operator and stand-in KMS can read issuer secrets; private custody and
  rollback protection are unqualified.
- Base mainnet's [single-RPC debug guard](protocols/base-guard.md), with bounded
  sponsor funding. This is not authenticated L1 finality.
- Direct encrypted NEAR inference from Abalone. The sponsor retains credential
  revocation powers. Incognito needs no VPN and does not promise IP anonymity.

## Acceptance gates

| Gate | Required outcome |
| --- | --- |
| Build and admission | Pinned source/image/toolchain, genuine fresh Mac evidence, exact compose and issuer/peer policy binding |
| Acquisition | Public artifact hashes and a clean Linux install with usable instructions |
| Discovery and status | Reachable public service, timestamped readiness/admission observations and honest unknown coverage |
| Operations | Bounded funding, management-token renewal and recovery preserving issued/ambiguous claims |
| Friend journey | Install, accept a funded coupon, decrypt access and complete useful private inference without maintainer repairs |
| Failure behavior | Expiry, refusal, restart and ambiguous paid effects handled under the selected policy |

Keep the exact revision, signed policy, evidence digests, observation times and
review decisions with each release artifact. Current fixtures replay historical
cryptographic inputs; they do not satisfy fresh hardware or friend acceptance.
Raw captures, operator controls and private user traces belong outside the source tree.

See the [profile and rollout](../packaging/coupon/public-testnet.md),
[operator guide](../packaging/coupon/public-testnet-operations.md),
[release packet issue](https://github.com/amiller/dsmack/issues/2),
[feedback tracker](https://github.com/amiller/dsmack/issues/1) and
[Abalone release gate](https://github.com/amiller/abalone/issues/4).
