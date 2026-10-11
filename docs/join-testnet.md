# Join the Dsmack testnet

This is the entry point for joining as a peer. The public testnet is the planned
friend-facing network; [mainnet is not launched](mainnet.md). Read
[joining, updating and leaving](node-lifecycle.md) for account continuity and
release lifecycle expectations.

**Native joining is temporarily unavailable as of 21:56 UTC, 11 October 2026.**
The configured seed needs recovery. Wait for the release coordinator to confirm
joining works before opening the app. See the
[current incident](testnet-release-process.md#current-native-joining-incident).

There are two different packages. Status below was checked against their release
notes on 11 October 2026; it is not a live endpoint-health claim.

| I want to… | Package and current scope |
| --- | --- |
| Join the native peer research network | [AttestNode v0.1.0-rc.3](https://github.com/amiller/apple-attest-p2p/releases/tag/v0.1.0-rc.3): signed/notarized Mac app; current joining blocked at seed recovery. Scoped shared-key exchange and participation receipt are the release’s intended journey. |
| Redeem a coupon for inference | [Abalone v0.1.0-preview.4](https://github.com/amiller/abalone/releases/tag/v0.1.0-preview.4): updated Linux client and signed wallet-epoch inputs pinned to this release; **redemption paused** until the full five-cent coupon document canary passes and the owner handoff is ready. Do not redeem a NEAR coupon while this gate remains closed. |
| Operate a coupon issuer | [Mac issuer deployment profile](../packaging/coupon/public-testnet.md): operator setup and qualification, not an automatic capability granted by native joining. |

## Install after the coordinator confirms recovery

You need Apple silicon, macOS 27, Full Security and SIP enabled. Joining the
publisher-signed app does not need Xcode, your own Apple Developer membership,
a funded wallet or gas. A VM or hosted macOS runner is not qualified by passing
ordinary build tests.

1. Open the RC3 release page above and download
   `AttestNode-macOS27-arm64-v0.1.0-rc.3.zip` and `SHA256SUMS`. Compare the ZIP with
   its checksum: in Terminal, type `shasum -a 256` followed by a space, drag the
   downloaded ZIP into the window, and press Return.
   The expected SHA-256 is
   `d546375abf7a92b04ede2127bbc159cd504a60078af3ef4cf4c2f20e5c0152db`.
2. Quit the previous peer through its Testnet menu, if installed. Extract the ZIP
   and replace the old app with `Node.app`. Preserve Application Support and
   Keychain data; copying another person's identity is not joining.
3. Open `Node.app` through the normal macOS confirmation. Do not disable
   Gatekeeper, SIP or Full Security. The app uses its pinned network, relay and
   seed, enrolls its own identity, and requests the current scoped key.
4. Wait for **You’re in.** The separate **Participant / #… confirmed** line
   reports the receipt, which may arrive later. Neither means coupon service
   is enabled. New receipts may have no Fold artwork.
5. Choose **Quit peer**, reopen and confirm the same personal account/receipt
   returns. Closing only the window leaves the peer running.

The [friend guide](https://github.com/amiller/dsmack/blob/761cd18dc87f26b5fa72ccc8639ab7a0fbd74982/release/friend-guide.md) explains receipt/artwork behavior
and the optional [independent builder flow](https://github.com/amiller/dsmack/blob/761cd18dc87f26b5fa72ccc8639ab7a0fbd74982/release/builder-guide.md).
Independent signing needs a different paid Apple Developer team and its own
acceptance run; it is not required for ordinary native joining.
To reproduce RC3, use the original public
[`amiller/apple-attest-p2p` RC3 source](https://github.com/amiller/apple-attest-p2p/tree/v0.1.0-rc.3)
at commit `6a3cca34f53a3cf8fe241aca4a8d8b3e0c76ef81`. The historical builder
guide's “fork this repository” instruction refers to that original repository;
the fresh `amiller/dsmack` repository does not contain the RC3 tag.

If stuck, save and review **Save diagnostic report…** before sharing it. It can
contain public account identifiers. Preserve identity/state; deleting them is
not a retry procedure. Report the release, OS, failing step and observation time,
without posting credentials. Contact the person who invited you for the current
support window; the historical release does not commit to an uptime or response
time. Reviewed non-sensitive bug reports can go to the
[public issue tracker](https://github.com/amiller/dsmack/issues).
A relay or seed outage can prevent joining; this
release does not promise autonomous alternative-peer discovery.

## Updates today: download and replace

RC3 has no implemented in-app update check, update notification or automatic
updater. The release coordinator sends you the next admitted release link.
Download that exact signed/notarized ZIP, check its published checksum, choose
**Quit peer**, replace `Node.app`, and reopen it. Keep Application Support and
Keychain data. App Attest enrollment may expire and renew as a new member.
Personal-account and receipt continuity depends on retaining the original personal
signing identity and linked-account metadata; verify it after reopening. A source commit
or a new ZIP alone does not mean the network admits that build.

If the replacement cannot join, save the diagnostic report and contact the
coordinator. Keep your identity and both release files. An earlier app is a
recovery option only when the coordinator confirms it remains admitted and
compatible with the current network; do not reset your account or silently
switch to an older policy.

## What this currently proves

The [exact RC3 verification](https://github.com/amiller/dsmack/blob/761cd18dc87f26b5fa72ccc8639ab7a0fbd74982/release/v0.1.0-rc.3.json) records successful
exchange and restart on the operator Mac, with two processes on that device.
A clean independent friend's first-open and independently operated second-Mac
journey remain required. The receipt is a research artifact with no monetary
value, not proof of a unique human or physical Mac.

To qualify your run, follow [milestones 2 and 3](operator-testnet-milestones.md):
record the exact artifact, real device/operator independence, policy/epoch/public
key agreement, quit/rejoin and outage/recovery observations. Do not expose the
shared key. The [protocol profile](protocol-profile-v1.md) explains the native
and coupon transports, which state is shared, and remaining operator powers.

## Check published inputs before opening the app

This optional diagnostic is for someone with the reviewed Dsmack source checkout
and Python 3. Ordinary joining uses the signed download above and requires neither
a clone nor Python. From the repository root, run the read-only release checker:

```sh
python3 tools/check_participation_release.py --output /tmp/participation-check.json
```

It checks the published ZIP checksum and observes relay/chain configuration.
A pass does **not** launch the app, perform admission or prove independent syncing.
See the [checker instructions](../packaging/participation/README.md) and
[dated public observation](../packaging/participation/qualification-20261011.json).
The [Mac package verification](../packaging/participation/mac-package-verification-20261011.json)
records signature and stapled-ticket checks, not independent first-open acceptance.
