# Sample app first-run contract

This is the target release acceptance specification; the table includes planned
states rather than claiming that every rejection/preflight screen is implemented.
The currently admitted download is [RC3](friend-guide.md). The Mac GUI now implements automatic
connection, key receipt, persistent participation, menu-bar status and retry
delays capped at 60 seconds. RC3 can still retry permanent Apple errors; it does
not yet implement all rejection/preflight states in the table below. Isolated real-device tests cover restart and onward exchange; the clean
Mac, visual layout, launch-at-login preference and iOS flow remain release gates.

Supported Macs require Apple silicon, macOS 27, Full Security, and SIP enabled.
Apple documents the key policy in its
[App Attest overview](https://developer.apple.com/videos/play/wwdc2026/201/?time=671).
Further Mac work should state these prerequisites before reporting generic
attestation failure, preserve existing identities, and stop repeated terminal
Apple failures with one shareable diagnostic. Users should follow the
[friend guide](friend-guide.md) if they encounter repeated errors.

Opening the app begins enrollment automatically. No network chooser, configuration
editor, wallet connection or gas purchase. The distributed bundle pins the network
identity and compatible protocol/policy; operational HTTPS endpoints are published.

| State | Visible message | Evidence needed to advance |
|---|---|---|
| Preflight | Checking your Mac… | Supported OS/device/API and valid configuration |
| Connecting | Connecting to the testnet… | Expected chain/network and reachable relay |
| Attesting | Verifying this app… | Authentic evidence accepted under current policy |
| Admitted | Getting the shared testnet key… | Authenticated key parcel, matching on-chain public-key commitment and verified exchange receipt |
| Discovering | Finding a peer… | Authenticated peer/session binding |
| Active | You're connected | Verified exchange with a peer; timestamp visible |
| Waiting | Admitted; waiting for a peer | Admission holds, no current peer exchange |
| Offline | Network unavailable; retrying… | Bounded backoff; preserve identity and pending submissions |
| Rejected | This build isn't admitted | Stop authorization; show release/update details |
| Unsupported | This device doesn't support this testnet | Explain macOS/iOS 27 evidence requirement |

The current Assembly window shows the shared-key receipt, NFT confirmation and
current state. The target experience also includes peer count and last verified
exchange. Technical details expose code identity,
signer, policy, transaction IDs and explicit RPC/admin trust. Logs and agent JSON
status report the same state, not guessed UI progress.

Closing the Mac window leaves a visible menu-bar participant; Quit stops it.
Launch at login is a separate explicit preference. Do not promise pre-login
daemon support. On phones, explain that participation requires the foreground.

The faucet distributes the shared testnet signing key, with a verifiable receipt.
The participant's App Attest identity is generated locally and remains distinct
from that shared key. Show the network, key epoch, public-key fingerprint and
receipt transaction; never display or log the shared private key. Participation
has no monetary value and does not require a token claim.

Persist the App Attest identity and interrupted enrollment evidence; keep the
shared signing key in memory and reacquire it from a live peer after restart.
If all key holders stop, show that the faucet is unavailable. Recovery requires
an explicit administrator epoch change and a new bootstrap, recorded on chain.
An epoch change does not erase old key copies. Expired attestation identities
need explicit renewal under the verifier policy; do not silently claim continuity.

Developer/agent acceptance: one documented build command, one launch command
through LaunchServices (App Attest is unsupported for the directly exec'd SSH
binary in the retained experiment), structured status, explicit errors, and the
same protocol as the GUI. No mock attestation fallback on unsupported hardware.
