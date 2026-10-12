# Dsmack

Dsmack is a peer-to-peer network of Macs, each running an app that proves with
Apple App Attest exactly which code it is. Its first service turns gift coupons
into private AI inference for [Abalone](https://github.com/amiller/abalone).

## Join the network

You need an Apple silicon Mac on macOS 27 with Full Security. You do not need
Xcode, an Apple Developer account, a wallet or gas.

1. Download `Dsmack Node` from the [latest release](https://github.com/amiller/dsmack/releases)
   and extract the ZIP.
2. Open it and accept the normal macOS prompt. It says **You’re in.** once it
   holds the network's shared key.
3. Choose **Share in public node directory…** and find your node on the
   [dashboard](https://amiller.github.io/dsmack/nodes/).

If a step stalls, see [troubleshooting](docs/join.md#troubleshooting).

If someone sent you a gift coupon, you do not need to join. Follow
[Redeem a coupon](https://github.com/amiller/abalone#redeem-a-coupon) in Abalone.

## What the network is and is not

When a node joins, it sends fresh App Attest evidence for its executable. The
network checks that evidence against a registry of admitted builds and only then
hands over the shared key. It admits the code, not the signer: anyone with an
Apple Developer account can build the app from source, sign it under their own
team and register it, and that copy is accepted if its executable matches an
admitted build.

What the people running it can still do:

- The registry's administrator decides which builds are admitted, and can change
  that decision.
- The relay can delay or drop messages, and its sponsor can stop paying for the
  on-chain transactions.
- Every admitted node holds the full shared key, so one compromised node exposes it.
- The coupon service runs on one operator's Mac. That operator can read the
  issuer's secrets and roll back its state, and the coupon sponsor can revoke the
  credentials it issues. Your prompts go encrypted from Abalone straight to the
  model provider and do not pass through the issuer.

Dsmack does not hide your IP address. Joining does not make your Mac run the
coupon service. The participation receipt each node gets on Base Sepolia has no
monetary value and does not prove a unique person or Mac. [Mainnet has not launched](docs/mainnet.md).

## Where to go next

- [Node dashboard](https://amiller.github.io/dsmack/nodes/)
- [Troubleshooting](docs/join.md) and [node details](docs/node-details.md):
  updates, diagnostics and checking a release before you open it
- Build it yourself: [Mac builds](docs/native-build.md) pins the toolchain and
  checks that two builds match; [independent builders](docs/native-builder.md)
  covers signing under your own team
- [Architecture](docs/architecture.md), [protocols](docs/protocols/README.md)
  and the [full documentation index](docs/README.md)
- [Contributing](CONTRIBUTING.md), [issues](https://github.com/amiller/dsmack/issues)
  and [security reporting](SECURITY.md)

Source is under the [MIT license](LICENSE); vendored dependencies keep their own notices.
