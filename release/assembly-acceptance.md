# Assembly acceptance scope

## Current release: RC3

The exact signed/notarized RC3 ZIP is admitted on Base Sepolia. At verified block
47831271, the seed and participant used the RC3 code, epoch 1 key-receipt transactions
succeeded, the original account/token was restored after restart, both original
owners were unchanged, and nextId remained 3. Relay writes were resumed with an
empty pending queue. The actual ordinary app displays Fold 001 for the existing
operator receipt. See [sanitized release verification](v0.1.0-rc.3.json).

RC2 is no longer admitted. Existing users must replace the app while preserving
saved state and Keychain items. New participant artwork automation, clean friend
Gatekeeper first-open, and a real independent-team upgrade remain unverified.
The recorded Assembly videos below describe earlier isolated test candidates;
they are not recordings of this production cutover.

## Earlier isolated acceptance evidence

The 17-screen journey is a design prototype. The native Assembly work implements
a subset of that experience; a polished mockup is not evidence that enrollment,
independent signing or first installation succeeded. This matrix records the
current source scope and the recorded local-chain acceptance run. Recording
provenance is kept separate from design mockups and historical public receipts.

| Journey step | Native implementation | Observed acceptance |
|---|---|---|
| Download and first macOS open | Existing signed RC2 download; redesigned acquisition page is a mockup | Previous download checks exist; clean second-Mac Gatekeeper capture remains pending |
| Verify app, find peer, exchange key | Existing real participant loop, newly styled native status and geometric stage | Real Apple-attested Assembly participant exchanged the key with a separate seed process on the same Mac; local Anvil receipts verified |
| Claim participant receipt | Existing contract-backed account/claim flow and confirmation label | Recorded local Anvil claim succeeded after HTTP503 and stale-chain-clock retries; token 1 owner is the personal account, not sponsor |
| Fold reveal | Bundled images only for verified original Base Sepolia receipts 1 and 2; other receipts display “ARTWORK NOT LOADED” | Recorded local-token screen accurately says ARTWORK NOT LOADED; public-Fold rendering is verified only in explicitly simulated native display states; future artwork automation remains pending |
| Inspect NFT | Explorer button maps the two known receipts to the reissued collection; arbitrary/local receipts are not presented as published artwork | Native action check pending; custom browser receipt page is a concept |
| Quit and reopen | Existing persisted identity/account and menu-bar lifecycle | Same-binary restart restored the same account/token with no mint and nextId 2; updated local candidate also restored the receipt in a separate 26-second clip |
| Developer introduction and invitation | Existing native alert explains setup; exports invitation and exact App ID | Production export/check methods saved and round-tripped a real 330-byte invitation with owner/factory binding and wrong-network rejection; native save/import/cancel picker interaction remains unverified |
| Developer portal, build and registration | External builder guide and existing tools | Independent Apple Developer team acceptance remains pending |
| Import invitation/request and approve | Existing file panels, validation and explicit account-control consent | Real independent-team consent/handoff and builder receipt remain pending |
| Report failure | Native events/backoff, technical-details drawer and new save-report panel | Recorded claim-pending state preserved real retries; later exporter passed synthetic secret-redaction/file-roundtrip tests; native picker and terminal-error pause remain unverified/unimplemented |

Raw recordings, event logs and source snapshots stay in the local evidence
archive; local evidence paths below are not public download links.

Sources: [native GUI](../node/mac/GUI.swift), [build packaging](../scripts/release/build_mac.py),
[builder guide](builder-guide.md), [prior acceptance audit](acceptance-audit.md),
[Assembly concept source](../design/mac-journey/README.md).

A local Anvil chain is a real contract execution environment, but is not Base
Sepolia. Apple proof validation, local contract receipts, simulated previews and
production/testnet participant receipts must each be identified separately in
any recording. Another certificate from the publisher team is not evidence of
an independent-team builder upgrade. Preview/capture hooks are separately
compiled; ordinary releases do not select a simulated journey.

## Recorded join, including recovery

Verification (local evidence: `data/assembly-native-20261007/verification.json`) independently
checks local mint status, personal ownership and sender/recipient key receipts.
Participant events (local evidence: `data/assembly-native-20261007/participant.jsonl`) and
seed events (local evidence: `data/assembly-native-20261007/seed.jsonl`) accompany the run.
The continuous 141-second AppKit content capture runs at its captured rate of
one frame per second with no cuts or speedup. It contains five distinct visual
states, all reviewed: attesting, receiving key, connected with claim pending,
claiming, and confirmed participant. It does not include the macOS desktop,
installation dialogs, signing setup, or a real independent-team handoff.

The first claim attempt received HTTP503 from the local relay; the next detected
a stale Anvil chain clock. The coordinator repaired the disposable test
infrastructure and the existing retry loop eventually confirmed the claim.
This is recorded recovery, not a claim of a frictionless first attempt. The app
kept its verified peer key while the claim was pending.

## Release boundary

At the time of these isolated recordings, the Assembly candidate was not yet
admitted to the public network. The
existing registry permits one approved code baseline; replacing that baseline
would stop admitting the RC2 binary. Public deployment therefore required a
coordinated cutover plan that preserves the original factory and
personal-account key namespace. This local acceptance run does not by itself validate
that public cutover. The persistent public peer remains separate.

Parcel crypto checks (local evidence: `data/assembly-native-20261007/parcel-crypto-tests.json`)
exercise production transport authentication and pre-RPC import guards. They
are unit-level negative checks, not independent-team or whole-chain acceptance.

## Updated candidate reconnect

A separate, uncut 26-second recording shows the later candidate with refined
controls. Its native events (local evidence: `data/assembly-native-20261007/polished-participant.jsonl`)
record a new successful Apple attestation, epoch 1 key verification and the same
participant account/token with no new mint transaction. The local registry
baseline was changed deliberately for this candidate; this is not proof of a
seamless public RC2 upgrade. The earlier join clip retains its original controls.

## Findings retained in the recordings

The captured candidates display “Peer found” upon entering the key-request
stage, before observing a reply. Review identified this premature wording; the
subsequent source changes it to “Finding a peer.” The videos retain the captured
wording, rather than presenting a later UI build as the recorded executable.

## Additional checks without a movie

Admission checks (local evidence: `data/assembly-native-20261007/polished-admission-checks.json`)
rejected different unadmitted code and a tampered executable page before the
local candidate was admitted. These are measured-code policy negatives, not a
recorded independent-team upgrade.

In-place verification (local evidence: `data/assembly-native-20261007/in-place-verification.json`)
then verified the same existing enrollment/member under another newly admitted
local binary: new assertions succeeded without generating or attesting a new
App Attest key, the personal account/token stayed the same, nextId remained 2,
and no new mint transaction was emitted. This additional result is log/chain
evidence, not part of the two real video clips. The local seed epoch changed
for instrumentation; the public network admission was not changed.

## Candidate provenance

The real join and refined reconnect movies use different executables. Their
signed executable SHA-256 values and unsigned/signed payload comparisons are in
join signing (local evidence: `data/assembly-native-20261007/candidate-builds/join-signing.json`)
and refined signing (local evidence: `data/assembly-native-20261007/candidate-builds/polished-signing.json`).
The corresponding candidate build manifests record compiler inputs and flags.
These captures do not imply that the final working-tree GUI is the exact binary
shown in every movie. The native simulated preview is a separately compiled
visual test, and never an Apple enrollment or a new on-chain mint.

## Explicit simulated native preview

The preview movie uses the separately compiled, watermarked display harness and
eight actual AppKit captures, held for three seconds each. It shows the known
public token 2 and its matching bundled Fold image. No Apple enrollment, peer
exchange, transaction or mint occurs. The corrected “Finding a peer” wording is
visible here. The first two movies remain genuine protocol runs on local Anvil.

## Invitation export business flow

Invitation verification (local evidence: `data/assembly-native-20261007/upgrade-export/verification.json`)
used the existing real local account and Keychain with production
`exportUpgradeInvitation`/`checkInvitation` methods. A public 330-byte invitation
was written and read back exactly; account/factory ownership binding passed and
a wrong-network invitation was rejected. No private key was exported. This is
business-flow evidence through a signed helper, not proof that the native
file-picker, import/cancel UI or independent-team approval journey worked.

## Diagnostic export privacy check

Exporter verification (local evidence: `data/assembly-native-20261007/diagnostic-report-tests/verification.json`)
exercised the actual exporter with synthetic sensitive fields, then wrote and
read the resulting file. It uses no real credentials, network, Keychain or
production mutation. The test found and drove a fix for configured RPC
credentials echoed into an error string. This privacy fix postdates the video
candidates. It is a unit/file check, not an automated native save-panel journey.
