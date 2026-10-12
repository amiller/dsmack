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

The app's menu has **Check for updates…** and a line showing the last result.
On first launch it asks once whether to check daily and records the answer.
A check downloads `updates.json` from the latest release:

```json
{"version": "0.2.1", "tag": "node-v0.2.1", "url": "https://github.com/amiller/dsmack/releases/download/node-v0.2.1/Dsmack-Node-0.2.1.zip",
 "sha256": "<zip SHA-256>", "M": "0x<code measurement>", "notes": "…"}
```

The feed only says where to look. The `MeasurementRegistry` on the app's
compiled-in network decides what installs. For a newer version the app reads
`isAdmitted(M, block)` and shows "admitted" or "not admitted". On **Download
and verify** it installs only if every step passes:

1. The ZIP's SHA-256 equals the feed's, and the ZIP is a plain `Node.app` (no
   symlinks, extra fields or paths outside it).
2. macOS accepts the app's code signature, from any Apple team.
3. The executable's CodeDirectory hashes to the CDHash macOS validated.
4. The app's measurement M ([how M is computed](build.md)) equals the feed's M,
   and its version equals the feed's.
5. The configured RPC reports the configured chain, and `isAdmitted(M, block)`
   and `isAdmitted(M, block + 43200)` are both true: admitted now and for at
   least a day of Base blocks.

Any failure refuses with its reason and leaves the running app unchanged. An
unreachable registry is a refusal. Nothing falls back to comparing Apple teams.
The confirmation shows the version, Team ID, M and whether the identity carries
over: same team and bundle id keep the Keychain group and App Attest key. A
build from another team gets a new member and cannot read this app's personal
key. **Install and restart** appends `{time, fromCdhash, toCdhash, M, team, feed}`
to `~/Library/Application Support/AttestNode/updates.json`. The new app goes in
`~/Applications/Dsmack Releases/node-vX.Y.Z-<sha>/`. A helper waits for the
old app to quit, verifies again with a fresh registry read, then opens the new
app. The old app is kept. Builds without a configured measurement registry
refuse every update.

Releases up to `native-v0.1.0-rc.4` have the older updater or none: download
the next release, check `SHA256SUMS`, choose **Quit peer**, replace the app and
reopen it. Keep Application Support and Keychain data.

### Publishing a release (operator)

1. Build, sign and notarize `Dsmack Node` (bundle id `dev.dsmack.provider`).
   Tag the source `node-vX.Y.Z` with `CFBundleShortVersionString` `X.Y.Z`.
2. Package and write the feed:
   ```sh
   python3 tools/native_update_archive.py --app Node.app --output Dsmack-Node-X.Y.Z.zip
   python3 scripts/release/publish_update.py --archive Dsmack-Node-X.Y.Z.zip \
     --tag node-vX.Y.Z --notes "…" --output updates.json
   ```
   `publish_update.py` computes M with `scripts/release/measure.py` from the
   executable inside the ZIP. Attach the ZIP, `updates.json` and `SHA256SUMS`
   to the GitHub release `node-vX.Y.Z` and mark it **Latest**: nodes read
   `releases/latest/download/updates.json`. Publish other releases with
   `--latest=false`.
3. Open a window for the new M: `admit(M_new, from, until)` on the
   `MeasurementRegistry`, with `from` at or before the current block and
   `until` well past the overlap. Nodes refuse it until `from` and if fewer
   than 43,200 blocks remain.
4. Update the seeds first. Confirm each seed on the new build registers,
   joins and records a `KeyReceipt` before announcing the release.
5. Close the old window: `admit(M_old, from_old, now + overlap)`. During the
   overlap old seeds hand the key to new builds; no epoch bump is needed.
   To withdraw a vulnerable build at once, `revoke(M_old)` and start a new key epoch.

### A node that doesn't update

It keeps working until its measurement's `until` block. After that its
assertions revert with "build not admitted", it is inactive within 60 seconds,
and it can neither receive nor hand on the key. Its menu shows the newer
version as admitted until the user installs it. Its copy of the key in memory
stops mattering only after the next key epoch.

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

## SDK app registry (Base Sepolia)

`AppRegistry` is deployed at `0xa4d26deDf4d086216a0E2cFbc7bdA49918f5C5c3` on chain 84532,
owner `0xe45C80da8A992447E9Da6d2d82Fe4b6Fa2d48C61`. The coupon app
`keccak256("dsmack-coupon-v1")` = `0x25e69b5ec66f7453e69abfcf0e4ec54e35643db48be80fa9f96c464010d8429f`
is created with scope 0 and no admitted compose hash. A node serving `sdkPort` names it in config
as `appRegistry` (required with `sdkPort`; without it the node refuses to start the SDK). Each key
op reads `apps(app_id)` and `composes(app_id, compose_hash)` at the current block; the G-signed
statement names that block, so a verifier re-reads the window there.
