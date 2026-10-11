# Join the Dsmack testnet

There are two different packages. Status below was checked against their release
notes on 11 October 2026; it is not a live endpoint-health claim.

| I want to… | Package and current scope |
| --- | --- |
| Join the native peer research network | [AttestNode v0.1.0-rc.3](https://github.com/amiller/apple-attest-p2p/releases/tag/v0.1.0-rc.3): signed/notarized Mac app, scoped shared-key exchange and a participation receipt. |
| Redeem a coupon for inference | [Abalone v0.1.0-preview.2](https://github.com/amiller/abalone/releases/tag/v0.1.0-preview.2): client maintenance preview; **redemption paused** pending a usable provider authorization/path. Do not redeem a NEAR coupon while this gate remains closed. |
| Operate a coupon issuer | [Mac issuer deployment profile](../packaging/coupon/public-testnet.md): operator setup and qualification, not an automatic capability granted by native joining. |

## Install the tagged native release

You need Apple silicon, macOS 27, Full Security and SIP enabled. Joining the
publisher-signed app does not need Xcode, your own Apple Developer membership,
a funded wallet or gas. A VM or hosted macOS runner is not qualified by passing
ordinary build tests.

1. Open the RC3 release page above and download
   `AttestNode-macOS27-arm64-v0.1.0-rc.3.zip` and `SHA256SUMS`. Compare the ZIP with
   its checksum using `shasum -a 256 AttestNode-macOS27-arm64-v0.1.0-rc.3.zip`.
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

If stuck, save and review **Save diagnostic report…** before sharing it. It can
contain public account identifiers. Preserve identity/state; deleting them is
not a retry procedure. Report the release, OS, failing step and observation time,
without posting credentials. A relay or seed outage can prevent joining; this
release does not promise autonomous alternative-peer discovery.

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
