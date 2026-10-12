# Node details

[Join the network](../README.md#join-the-network) has the three steps and
[the join guide](join.md) has troubleshooting. This page covers the rest:
requirements in detail, updates, the optional release checker and what earlier
releases were verified to do. Read [joining, updating and leaving](node-lifecycle.md)
for account continuity. [Mainnet is not launched](mainnet.md).

## Three separate things

| I want to… | Where |
| --- | --- |
| Run a node in the peer network | `Dsmack Node` from the latest `node-vX.Y.Z` [release](https://github.com/amiller/dsmack/releases) |
| Redeem a coupon for inference | [Abalone: Redeem a coupon](https://github.com/amiller/abalone#redeem-a-coupon) |
| Operate a coupon issuer | [Mac issuer deployment profile](../packaging/coupon/public-testnet.md). Joining as a node does not run an issuer. |

## Requirements and install

You need Apple silicon, macOS 27, Full Security and SIP enabled. The
publisher-signed app does not need Xcode, an Apple Developer membership, a
funded wallet or gas. A VM or hosted macOS runner is not qualified by passing
ordinary build tests.

To check the download, compare the ZIP with `SHA256SUMS` from the same release:
in Terminal, type `shasum -a 256` and a space, drag the ZIP into the window and
press Return. If an older app is installed, choose **Quit peer** in its Testnet
menu first, then replace it. Keep Application Support and Keychain data; copying
another person's identity is not joining.

**You’re in.** means the node holds the current shared key. The separate
**Participant / #… confirmed** line reports the receipt, which may arrive later.
Neither means the node runs the coupon service.

## Diagnostics

If a step fails, save **Share diagnostic report**, read it and then share it.
It can contain public account identifiers. Preserve identity and state; deleting
them is not a retry procedure. Report the release, OS, failing step and time,
without credentials, on the [issue tracker](https://github.com/amiller/dsmack/issues).
There is no uptime or response-time commitment. A relay or seed outage can
prevent joining; the app does not yet discover alternative peers on its own.

## Updates

Releases from `native-v0.1.0-rc.4` on have **Check for updates…**, which reads a
signed recommendation from a GitHub release, verifies the download and installs
it beside the old app ([verified native updates](native-updates.md)). Older
releases, including RC3, have no updater: download the next release, check its
checksum, choose **Quit peer**, replace the app and reopen it. Keep Application
Support and Keychain data. App Attest enrollment may expire and renew as a new
member. Account and receipt continuity depend on keeping the original personal
signing identity and linked-account metadata; check them after reopening. A new
source commit or ZIP does not by itself mean the network admits that build.

If a replacement cannot join, save the diagnostic report and keep your identity
and both release files. Reopen an earlier app only if the release notes say it is
still admitted; do not reset your account.

## Building and signing it yourself

The [independent builder flow](native-builder.md) and [Mac builds](native-build.md)
describe building the app from source under your own Apple Developer team. The
RC3 builder guide is at
[`761cd18`](https://github.com/amiller/dsmack/blob/761cd18dc87f26b5fa72ccc8639ab7a0fbd74982/release/builder-guide.md).
To reproduce RC3, use the original
[`amiller/apple-attest-p2p` RC3 source](https://github.com/amiller/apple-attest-p2p/tree/v0.1.0-rc.3)
at commit `6a3cca34f53a3cf8fe241aca4a8d8b3e0c76ef81`; this repository does not
contain the RC3 tag.

## What RC3 proved

The [RC3 verification record](https://github.com/amiller/dsmack/blob/761cd18dc87f26b5fa72ccc8639ab7a0fbd74982/release/v0.1.0-rc.3.json)
records exchange and restart on the operator's Mac, with two processes on that
device. A clean first open by someone else and a second Mac run by another
operator are not recorded there. The receipt is a research artifact with no
monetary value and does not prove a unique person or physical Mac.

The [protocol profile](protocol-profile-v1.md) explains the native and coupon
transports, which state is shared and what operators can still do.

## Check published inputs before opening the app

This optional check needs the Dsmack source and Python 3. Ordinary joining does
not. From the repository root, run the read-only release checker:

```sh
python3 tools/check_participation_release.py --output /tmp/participation-check.json
```

It checks the published ZIP checksum and reads relay and chain configuration.
A pass does **not** launch the app, perform admission or prove syncing.
See the [checker instructions](../packaging/participation/README.md) and the
[dated public observation](../packaging/participation/qualification-20261011.json).
The [Mac package verification](../packaging/participation/mac-package-verification-20261011.json)
records signature and stapled-ticket checks, not a first open on another Mac.
