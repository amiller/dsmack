# Join the testnet, then become an independent builder

Status: RC3 Assembly prerelease, 7 October 2026. The exact signed/notarized Mac
ZIP is admitted on the live Base Sepolia network and has restored the operator’s
existing account/NFT after restart. The persistent seed serves the current epoch.
The release preserves the original account policy and both existing NFT owners.
RC2 users need the new app. See [release verification](v0.1.0-rc.3.json) and the
[friend guide](friend-guide.md).

A clean second-Mac installation/restart capture and real independent-team Level 2
acceptance remain unverified. New participants receive a receipt first; automatic
artwork publication for subsequent receipts remains pending.

## The story to send a friend

“Open AttestNode on your Mac. It joins our research network automatically and
gives you a participant NFT as a receipt. If you want to go further, build and
sign the same app using your own Apple Developer team. Run that copy to earn the
independent-builder NFT. Both receipts are testnet souvenirs with no monetary
value.”

Supported Macs need Apple silicon, macOS 27, Full Security, and SIP enabled;
see the [friend guide](friend-guide.md) for requirements and the failure-report path.
The first experience requires no developer account, terminal commands, wallet
setup, gas purchase, or network configuration. Download access and the normal
macOS first-open confirmation are separate from application setup. The [friend handoff](friend-guide.md) provides a public release download without
a GitHub account and states the supported Mac/OS requirements. The
[repository and release](https://github.com/amiller/apple-attest-p2p) are now public
for direct downloads and Level 2 forks.

## Level 1: participant

1. Download, extract, and open the signed, notarized app.
2. See “Connecting.”, followed by “Verify the app.” and “Finding a peer.” Progress describes verified events.
3. See “You’re in.” (or “Your Fold.” for a known bundled receipt), a verified key receipt, and the participant NFT after
   its claim transaction confirms. Claiming is automatic and sponsored.
4. Open the NFT receipt to inspect its network, contract, token, recipient, and
   transaction. The receipt explains what was proven.
5. Close the window to keep participating from the menu bar. Quit stops the peer.
   Reopen to reconnect without duplicating a completed claim.

The NFT belongs to a participant-specific identity/account. The relay pays gas
but must not receive the participant's NFT. The shared network signing key cannot
serve as personal ownership: every participating peer intentionally receives it.
The app creates a separate personal P256 key in its device-only Keychain and a
testnet account controlled by that key. There is no sponsor recovery or key
export. Moving control to the independently signed copy requires approval from
both copies; losing the original key before that handoff loses account control.
A lost installation must not silently be represented as the same participant
or as a provably new physical device.

## Level 2: independent builder

1. From the connected app, choose “Become an independent builder…”.
2. Follow one concise guide to fork/build the pinned source and sign locally
   with Xcode, or configure the protected GitHub signing workflow. Keep Apple
   credentials in Xcode/Keychain or the user's own CI secrets.
3. Use the participant invitation’s account-specific bundle identifier and
   verify that the unsigned executable matches the published reproducible build.
4. Register/admit the independently signed copy under the code policy, then run
   it and prove its signing identity through verified attestation.
5. Link the new installation to the original participant with an authenticated
   handoff, and confirm the builder NFT. A typed Team ID alone is not evidence.

The first independent-builder demonstration requires a signing team different
from the release publisher's team. A developer team may represent an organization
with multiple people. The badge proves a verified independent signing team and
admitted code, not a unique human. The signed bundle identifier is bound to the participant
account, so somebody else’s generic signed download cannot qualify. Admission requirements and any manual operator
step must be visible in the guide; a successful CI build alone is insufficient.

## Identity and repeat claims

| Identifier | What it establishes | What it does not establish |
|---|---|---|
| App Attest key / member ID | An enrolled app key; claims can be idempotent for that key | Permanent Mac identity or unique owner |
| Personal NFT recipient | Continuity of the chosen personal account | One person or one physical Mac |
| Verified Apple signing team | The team bound to an admitted signed app | One human; one machine |
| Shared testnet key | Participation in the current key epoch | Individual identity or exclusive ownership |

Apple documents that App Attest keys survive app updates but are invalidated by
reinstall or device restore. Its fraud metric is a risk signal, not an exported
stable hardware identifier. Therefore this release must not advertise “exactly
one signup per Mac mini owner”. Claim limits must name their actual scope.
If stronger anti-duplicate admission becomes a requirement, it needs a separate
policy and evidence source; this PRD does not pretend App Attest supplies it.

Source: [Apple: Secure your apps with App Attest](https://developer.apple.com/videos/play/wwdc2026/201/).

## Administrative trust

The operator can pause admission, change admitted code/category policy, and
advance the shared-key epoch after complete loss of in-memory key holders. The
relay sponsors testnet gas and transports messages; relay and RPC availability
are required. The app trusts RPC responses rather than verifying a light-client
proof. Apple attestation roots and the pinned Apple build toolchain are trust
assumptions. The sponsor has no personal-account recovery function; historical
NFTs are not a promise that an app remains admitted forever.

## Failure states

- Network or faucet unavailable: explain the delay and retry automatically;
  preserve enrollment and pending claims.
- Unsupported Mac/OS/security state: explain why participation cannot proceed.
- Unadmitted build: show the admission/update step; do not show success.
- Submitted NFT transaction: show “Claim pending” until confirmed; never equate
  transaction submission with ownership.
- Already claimed: show the existing receipt, including after retry/restart.
- Developer-team setup incomplete: retain Level 1 and identify the remaining step.

## Definition of done

- [ ] A friend can access the exact signed release and complete Level 1 on a
  second Mac with Gatekeeper enabled, without developer assistance.
- [ ] The confirmed participant NFT belongs to the friend-specific recipient,
  and duplicate/restarted submissions do not mint another claim for that identity.
- [ ] A second Apple signing team completes Level 2 with an authenticated link
  back to that participant and a confirmed builder NFT.
- [ ] The short friend guide includes real screenshots of first launch,
  connected/claimed state, developer setup, and builder success. Mockups and
  screenshots from an earlier app version cannot substitute for acceptance.
- [ ] A redacted agent transcript records exact release/commit, launch/build
  commands, structured events, expected versus observed results, NFT ownership,
  transaction links, retries, and both signing identities. Include failures.
- [ ] Reproduction instructions let another agent check the same claims without
  Apple passwords, private keys, or undocumented operator knowledge.
- [x] Documentation explicitly names the claim-limit scope, ownership/recovery
  behavior, administrative trust, hardware prerequisites, and remaining limits.

The goal stays open while screenshots or either NFT journey are unverified.
Existing evidence: [Mac release checklist](README.md),
[current shared-key user flow](user-flow.md), and
[published release manifest](v0.1.0-rc.3.json), and
[current acceptance audit](acceptance-audit.md).

## Implementation order

1. Resolve participant ownership and secure continuity across signing teams.
2. Add participant-owned claims with replay protection; the legacy Claim action
   currently mints to the sponsor in the sponsored flow and cannot be reused as-is.
3. Add verified builder eligibility and Level 1-to-Level 2 linking, including
   rejection tests for arbitrary team labels, wrong code, and replayed handoffs.
4. Implement the simple status/receipt screens and the fork-and-sign guide.
5. Run both journeys, capture screenshots/transcript, and package the friend handoff.

iOS 27/TestFlight is an active distribution track, requested for friends with
compatible iPhones. Simulator validation is recorded in
`iphone-simulator-validation.md`; it does not establish physical-device admission. Its device/account and
review requirements must be documented and tested separately; the first friend
acceptance run is macOS.


## iPhone user journey under validation

The iOS 27 app opens directly into “Connecting to the testnet”, then “Verifying
this app”, “Joining the network”, and “You’re connected”. After the participant
NFT confirms, “View NFT receipt” opens its explorer page. Participation requires
the app to remain in the foreground. An unsupported device or terminal Apple
error stops automatic attempts and offers “Share diagnostic report”; the report
includes app/OS versions, the failing Apple operation, and bounded error-domain
and code chains. A network interruption shows the retry delay. Simulator
scenarios always carry a visible warning and never prove an NFT claim.

After connection, “Developer upgrade” offers “Save invitation” (available after
Level 1) and “Import upgrade file”. Uploaded TestFlight build 5 contains these controls and an encryption
declaration. Apple reported successful upload and processing; tester access and
a positive physical-iPhone run remain unverified:

1. Save the invitation in the original app, preserving that app and its keys.
2. Build and sign the same admitted source with an independent Developer team
   and the exact account-specific bundle identifier in the invitation.
3. Distribute the independent iPhone copy through TestFlight and have its actual
   installed code admitted under the iPhone policy. A development-signed build
   is a different validation category and is not admitted by the present policy.
4. Join from that copy, import the invitation, and save the generated request.
5. Return the request to the original app using Import upgrade file. It checks
   the network, account, key signature, receipt, team, and expiry before asking
   for consent. Oversized and malformed files receive an error without consent.
6. Compare the new-key fingerprint with the independently signed copy. The
   original app displays the account, fingerprint, and team-proof prefix plus
   the consequence: control moves to the new copy. Cancel changes nothing.
7. Approve handoff explicitly. The app checks eligibility again before signing.
8. Continue in the new copy, which waits for approval and claims the builder NFT.
   Verify its original Level 1 parent and independent team on chain.

The positive physical-iPhone and second-team runs remain required. Simulator
consent/file-picker checks do not establish signing, TestFlight measurement,
network admission, or handoff success. Neither the builder badge nor App Attest
establishes a unique person or permanently unique physical device.

Build 5 also offers Technical details → Prepare code evidence → Share code
evidence for the release coordinator. It exports public installed-code inputs
without a provisioning profile or private keys. This local measurement is not
Apple attestation. The simulator refuses this export, and the actual iPhone
export still needs verification. For an error, use Share diagnostic report and
send the copied text once; do not ask a friend to reset identities or run a
sequence of terminal diagnostics. See [current TestFlight steps](testflight-review.md).


## Selected NFT art direction: Fold

The selected direction is a single porcelain sculpture with a vermilion-glazed
interior, broad folded surfaces and restrained studio lighting. The NFT image
should work as a small thumbnail and reward a larger view. The earlier garden
scene is not the chosen art direction.

The [Fold prototype](../artwork/fold/README.md) generates geometry from public
chain/contract/token identity, keeping art stable across restarts and ownership
checks. It includes the renderer, local reproducibility checks and an initial
render for Gabe's participant token 2. It is a visual prototype, not approved
final art, a live app integration or a change to deployed NFT metadata.

The remaining design work includes the Level 2 relationship to its parent art
and the explicit path for displaying artwork in wallets without misrepresenting
or replacing existing historical receipts. Artistic variation does not indicate
trust, rarity, uptime, a unique human or a permanently unique physical device.


### Main collection publication — 2026-10-07

The selected Fold direction is now published in the main **Attest Testnet Research
Badges** collection, without a version label. Both existing participant tokens
have images in their on-chain metadata, at the same IDs and owners as the original
receipts. The [collection handoff](main-collection.md) includes the live links,
image, source and verification evidence. Original receipts remain the claim and
account-consent engine. This does not complete the app artwork journey: RC2 still
opens the original receipt, and future claims still require artwork publication
until an automatic renderer/publisher is operated.
