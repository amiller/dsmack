# Dsmack

Dsmack is a peer-to-peer service network for private inference. It redeems
coupons for provider access and is developing routing through contributed API
authorization. [Abalone](https://github.com/amiller/abalone) is the client.

The public testnet is in preparation. Its selected issuer runs on an Apple
Silicon Mac through the native runner and an ARM container. Earlier staging
trials delivered capped provider credentials and useful encrypted NEAR inference;
fresh Mac issuer admission and the installed friend journey remain pending.

## Use and contribute

- **Try a gift:** follow [Abalone's getting-started guide](https://github.com/amiller/abalone/blob/main/docs/getting-started.md).
  Dsmack's paired Mac-issuer release still requires [acceptance](docs/release.md).
- **Understand the source:** [architecture](docs/architecture.md) and [protocols](docs/protocols/README.md).
- **Develop:** [contributing](CONTRIBUTING.md), [Mac builds](docs/native-build.md),
  and the [synthetic coupon package](packaging/coupon/README.md).
- **Run an issuer:** [Mac ARM package](packaging/coupon/mac-base.md) and
  [operations](packaging/coupon/public-testnet-operations.md).
- **Track work:** [roadmap](docs/roadmap.md) and [public issues](https://github.com/amiller/dsmack/issues).

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
vendored dependencies retain their own notices. Generated evidence and operator
state belong in ignored `local-data/`. Historical experiments remain available
in Git history; the current tree contains maintained source, guides and required fixtures.
