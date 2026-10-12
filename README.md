# Dsmack

Dsmack is a peer-to-peer network of attested Mac nodes. Its first service
redeems coupons for private inference; [Abalone](https://github.com/amiller/abalone)
is the client.

## Join the network

You need an Apple silicon Mac on macOS 27 with Full Security.

1. Download `Dsmack Node` from the latest `node-vX.Y.Z` [release](https://github.com/amiller/dsmack/releases).
2. Open it.
3. Find your node on the [dashboard](https://amiller.github.io/dsmack/nodes/).

Any Apple Developer team may build and sign the app from source; the network
admits the code measurement, not the signer ([build it yourself](#build-it-yourself)).
[Troubleshooting](docs/join.md) and [node details](docs/node-details.md).

## Redeem a coupon

If someone sent you a gift link, follow
[Redeem a coupon](https://github.com/amiller/abalone#redeem-a-coupon) in Abalone.
Your agent installs the client and redeems the coupon; you then use the credit
from a fresh terminal. Joining the network is not required to redeem.

## Build it yourself

[Mac builds](docs/native-build.md) pins the toolchain and checks that two builds
of the same source match. [Independent builders](docs/native-builder.md)
describes signing under a different Apple Developer team and registering that
build with the relay.

## Source and documentation

- [Architecture](docs/architecture.md) and [protocols](docs/protocols/README.md).
- [Contributing](CONTRIBUTING.md) and the [synthetic coupon package](packaging/coupon/README.md).
- [Roadmap](docs/roadmap.md), [mainnet plans](docs/mainnet.md) and [public issues](https://github.com/amiller/dsmack/issues).

## Trust and privacy

The coupon issuer delivers a capped sponsor-managed credential encrypted to
recipient keys. The recipient connects directly to NEAR for inference; the
issuer does not proxy that session's prompts. The sponsor retains revocation
powers, and the cap is a spending limit rather than a separate cash balance.

The current Mac profile verifies Apple App Attest code identity, the exact
workload compose, and a fresh binding to issuer keys, policies and Noise peers.
It is identity-only: the host/operator and stand-in KMS can read issuer secrets.
Private custody and rollback protection remain unqualified. Abalone separately
verifies and encrypts the inference connection and reports accepted provider
security-update exceptions. Incognito does not promise IP anonymity.

See the [charter](docs/charter.md), [release boundaries](docs/release.md) and
[security reporting](SECURITY.md). Source is available under the [MIT license](LICENSE);
vendored dependencies retain their own notices. Historical experiments remain
available in Git history; the current tree contains maintained source, guides and
required fixtures.
