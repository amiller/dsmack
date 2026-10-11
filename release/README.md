# Mac release and TestFlight checklist

Status: Mac `v0.1.0-rc.3` is the current admitted Assembly build. The exact
Developer ID signed, notarized ZIP completed a live Base Sepolia shared-key
exchange and restored the original participant account/NFT on restart. The
persistent seed is on the same current build and epoch. RC2 is no longer admitted;
existing users need the new app while preserving their app data and Keychain.

[Download and first-run instructions](friend-guide.md) ·
[RC3 release](https://github.com/amiller/apple-attest-p2p/releases/tag/v0.1.0-rc.3) ·
[exact release verification](v0.1.0-rc.3.json).

Supported Macs require Apple silicon, macOS 27, Full Security and SIP enabled.
No wallet, gas purchase or developer account is needed to join. New participants
receive a receipt first; automatic Fold artwork publication is still pending.

The signing Mac has Gatekeeper assessment disabled. Notarization and ticket
validation do not establish an unassisted clean-Mac first-open experience.
Independent-team builder acceptance and physical-iPhone/TestFlight acceptance
remain separate outstanding work.

## Build without an Apple account

On an Apple Silicon Mac with the exact Xcode/SDK/compiler in `toolchain.json`:

```sh
python3 scripts/release/build_mac.py --gui --version 0.1.0 --build-number 4 --out build/unsigned
```

Choose an unused output directory. RC3 was compared across two clean source paths
and module caches on one Mac. The generic `check_repro.py` and candidate workflow
still default to build `3`; their default bundle metadata is not byte-identical
to the RC3 build `4`. Independent-host RC3 reproduction remains unverified.
 Set `DEVELOPER_DIR` to the matching Xcode when
several are installed. The scripts fail on toolchain drift. They compile the
native participant with optimization, a fixed module name, stable relative source
names, path remapping and no code signature. No package downloads are needed.
The unsigned bundle cannot run App Attest: that requires signing/provisioning.

`build-manifest.json` records source commit, dirty state of build inputs, hashes of all direct
build inputs, flags, toolchain, bundle identity/version, and every output file.
`check_repro.py` copies build inputs to two differently named roots, uses separate
module caches, and compares all unsigned bundle files. This is a same-host test;
independent builders must compare their own manifests too. A GitHub workflow or
provenance statement is not itself proof of reproducibility.

Historical CLI milestone on mini-mesh: both builds matched. Unsigned executable SHA-256:
`89697437b904571409a94ada5f64a68c9e72078b2606ee9c64bb619adb635f72`.
GitHub run 37545040726 independently reproduced both unsigned bundle files;
see `independent-build-20261006.json`. These measurements apply to commit
`d827cfa` and its unchanged CLI build inputs.

Historical earlier GUI evidence (not RC3): the GUI was independently reproducible from clean source `ee74923` on
GitHub and the mini, with unsigned executable SHA-256
`56b618d28494cfefb4841261709ccd16a2f45b2a8dc27361d7099483b0f81c1f`.
See `gui-independent-build-20261006.json` and `gui-build-manifest-20261006.json`.
Signing and stapling preserve that payload (`gui-payload-verification-20261006.json`).

## Fork and build with GitHub resources

1. Fork [amiller/apple-attest-p2p](https://github.com/amiller/apple-attest-p2p)
   and check out `v0.1.0-rc.3` when reproducing the admitted Mac app. Use version
   `0.1.0`, build `4`, and the tag’s exact toolchain. Do not substitute a later
   `main` checkout or the generic workflow’s default build metadata.
2. Enable Actions. `mac-build.yml` builds on `xcode-27` without Apple credentials.
   GitHub's image moves; the checked-in toolchain lock must still match. Change
   that lock only as a reviewed build input, then obtain fresh measurements.
3. Create an `apple-release` GitHub environment restricted to reviewed release
   refs; protect it against untrusted branches. Forks do not inherit secrets.
4. Add the following secrets and variables. Private keys are required, not just IDs.
5. Run **Signed Mac candidate** manually on the reviewed commit. It builds,
   signs, notarizes, staples, verifies Gatekeeper, and uploads a candidate ZIP
   plus checksums and evidence. It does not tag or publish an unfinished app.

| Kind | Name | Value |
|---|---|---|
| Secret | `MAC_CERTIFICATE_P12_BASE64` | Exported Developer ID Application certificate **with private key**, base64 |
| Secret | `MAC_CERTIFICATE_PASSWORD` | Password protecting that P12 |
| Secret | `MAC_PROFILE_BASE64` | Developer ID provisioning profile granting CDhash, base64 |
| Secret | `ASC_KEY_P8_BASE64` | App Store Connect API private key authorized for notarization, base64 |
| Variable | `APPLE_TEAM_ID` | Your team ID |
| Variable | `APPLE_BUNDLE_ID` | Your explicit App ID's bundle identifier |
| Variable | `MAC_SIGNING_IDENTITY` | Full `Developer ID Application: …` certificate identity |
| Variable | `ASC_KEY_ID`, `ASC_ISSUER_ID` | API key ID and issuer ID |

The signing job uses a temporary keychain, deletes it in `finally`, and runs on
an ephemeral hosted runner. It does not run on PR events. Actions are pinned to
commit IDs. Configure GitHub environment protection before adding secrets.

Changing the signing team does not require changing executable source. Changing
bundle metadata changes the sealed identity and CDHash. The registry permits
identity metadata differences when the code and normalized entitlement policy
still match; the new CDHash must be registered. Successful building/signing does
not automatically admit a fork to the shared network.

For local signing, use `scripts/release/sign_mac.py --help`. Unlock an existing
keychain in the same session beforehand. Development mode creates a **private**
archive that may embed device identifiers; never publish it. Developer ID mode
requires an all-devices profile and successful notarization. The script emits
only the required entitlements and never enables debugger access.

### Xcode managed signing alternative (measured locally)

Xcode's saved account session successfully exported the development-signed
candidate under **Developer ID Application: Honey Badger Coop. Labs Inc.
(DC9JH5DRMY)** even though the local keychain listed no Developer ID private key.
The exported executable matches the reproducible unsigned payload and produced
verified category-6 App Attest evidence. Apple completed notarization. The exported app passes strict signature and
stapled-ticket validation, preserves the reproducible payload, and produced
fresh verified category-6 App Attest evidence. Gatekeeper is disabled on the
build mini; a clean Mac download-and-open test remains required.

```sh
python3 scripts/release/export_mac_xcode.py --app build/development/Node.app \
  --team DC9JH5DRMY --out build/developer-id
python3 scripts/release/export_mac_xcode.py --app build/development/Node.app \
  --team DC9JH5DRMY --out build/notary --submit-notarization
# After Apple finishes processing:
xcodebuild -exportNotarizedApp -archivePath build/notary/Node.xcarchive \
  -exportPath build/notary/notarized
```

This wrapper accepts `ASC_KEY_PATH`, `ASC_KEY_ID`, `ASC_ISSUER_ID` instead of a
saved Xcode login. The API-key version is not yet tested on GitHub. It still
requires an initially signed app archive and a preexisting App ID with the
capability enabled; do not describe it as a fully verified key-ID-only fork flow.
The certificate-based workflow above remains a separate, unrun CI configuration.

## Reproducibility and signer independence

Keep three checks distinct:

- Rebuild the same source with the pinned compiler/SDK and compare unsigned bytes.
- Check the shipped bundle's signature, entitlements, resources, CDHash and
  notarization. `verify_signed_payload.py` compares every original executable byte,
  allowing only an appended signature load command and validated LINKEDIT sizes.
  The signing script also checks original resource hashes. This narrow comparator
  deliberately rejects unexpected layouts rather than ignoring new differences.
- Capture live App Attest evidence from that exact distributed app, bind its RP
  identity and CDHash to the appropriate policy, and demonstrate network admission.

Final ZIP bytes, timestamped signatures, provisioning profiles and notarization
tickets are not expected to reproduce independently. Do not strip arbitrary
differences or call two independently compiled apps equivalent merely because
their source commit matches. The current code-page comparison handles specific
re-signing differences, not arbitrary compiler output differences.

Bitcoin Core is a useful precedent: its documented Guix release process separates
reproducible unsigned macOS output from attaching signatures. Our Swift/DeviceCheck
app still trusts Apple's pinned binary toolchain and SDK; it is not a bootstrappable
Guix build.

## Release gates

- [x] Locate current implementation and successful Base Sepolia peer evidence.
- [x] Build the unsigned Mac peer twice from isolated paths; compare bytes.
- [x] Add credential-free CI and a separate signing/notarization candidate job.
- [x] Run the workflow on an independent GitHub host and compare with the mini.
      Both downloaded bundle files match the recorded mini hashes.
- [x] Unlock existing development keychain; sign and run the new candidate.
- [x] Match unsigned payload to signed executable; negative mutation tests pass.
- [x] Capture actual App Attest and verify Apple chain, nonce, production profile,
      Mac ACL and code-page/CDHash correspondence. Category 3 was observed; this
      is development signing, not Developer ID distribution. No chain transaction
      was submitted by the capture harness.
- [x] Export through Xcode managed Developer ID signing and capture category-6
      evidence. The deployed Mac adapter pins category 3, so the live network
      still needs a separately tested category-6 admission configuration.
- [x] Replay the real Developer ID enrollment through the Solidity adapter;
      accept under category 6 and reject under category 3. Register both the
      development and Developer ID copies under one code baseline successfully.
- [x] Notarize and export using the saved Xcode account; strict signature and
      stapled-ticket checks pass. Fresh App Attest from that exact export verifies
      against its binary, with category 6 and the same Developer ID CDHash.
- [ ] Browser-download and open the exact ZIP in a clean Mac account with
      Gatekeeper enabled. The mini assessment reports `override=security disabled`.
- [x] Implement automatic Mac enrollment/key receipt, persistent participation,
      status JSON and a durable HTTPS relay. Live Base Sepolia launch passed.
- [x] Persist enrollment identity, serialize each identity across processes, journal
      relay transactions, and retry with bounded backoff. Restart/outage tests pass.
- [ ] Exercise certificate expiry/renewal and long-running behavior end to end.
- [x] Confirm faucet semantics: shared testnet signing key with a verifiable
      receipt. No wallet or token-claim flow is needed.
- [x] Add explicit administrator key epochs for complete RAM-key loss; test recovery
      without changing network/member identity. No silent network or key reset.
- [x] Test identity-preserving restart, onward transfer, relay disconnect/reconnect
      and explicit epoch recovery on the real Mac with an isolated chain.
- [ ] Test Mac lock/unlock, logout/login and release update installation.
- [x] Prepare tagged prerelease ZIP, checksum, source/build manifests,
      network configuration, known limits and measured results.
- [ ] Friend signs a copy; independently verify its evidence and peer exchange.

## TestFlight is an active release track

Yesterday's retained record confirms **AppAttest Lab dsmack**, app ID
**6819392473**, bundle **dev.dsmack.provider**, **build 2**, internal group **Lab**.
It was installed and exercised on an iPhone XS/iOS 18.5. This establishes an iOS
upload/install path, not the current App Store Connect state, external approval,
macOS availability, or an iOS 27 network run.

- [ ] Query the existing app record/build/group status using the existing account.
- [ ] Reuse its iOS record for the node if the product/bundle identity remains suitable;
      choose a new monotonically increasing build number from live state.
- [x] Generate the node's iOS Xcode project with the existing lab icon and create
      an unsigned device archive on Xcode 27. See the commands below.
- [x] Sign/export a local App Store Connect IPA; sanitized signing evidence is
      in `iphone-app-store-export.json`. The configured version 0.1.0/build 3 was
      subsequently uploaded successfully; see `iphone-testflight-upload.json`.
- [ ] Finish beta description, review contact/instructions and accurate encryption
      declaration; select the upload build number against live account state.
- [ ] Add a macOS platform/version to the record if supported and desired; do not
      assume the iOS TestFlight build supplies a Mac build. Mac Store signing and
      sandbox requirements are a separate distribution configuration.
- [ ] Internal install and capture first; external group/review/public link next.
- [ ] Match the **installed** Apple-distributed executable/CDHash and evidence
      profile, not only the upload. Store processing can change the signature.
- [ ] Verify on iOS 27 hardware. Yesterday's XS cannot validate the authenticated
      code measurement required by this admission policy.

The older plan's “no TestFlight” constraint is superseded by Andrew's October 6
instruction. iPhone participation is foreground-only for the first release.

The authorized prior Claude session confirms yesterday's successful upload used
Xcode's saved account session with `-allowProvisioningUpdates`, `app-store-connect`
export and `destination=upload`. An API key is not required to reuse that local
path. Automated fork CI still needs each fork owner's own credentials.

Prepare the peer project and check its unsigned device archive:

```sh
python3 scripts/release/make_node_project.py
xcodebuild -project node/ios/AttestNode.xcodeproj -scheme AttestNode \
  -configuration Release -destination 'generic/platform=iOS' \
  -derivedDataPath build/ios-dd -archivePath build/AttestNode-unsigned.xcarchive \
  CODE_SIGNING_ALLOWED=NO archive
```

The checked-in project is generated deterministically and targets iOS 27. The
SwiftUI participant now starts automatically using the pinned network, preserves
its participant identity, and provides a shareable diagnostic report. Simulator
UI scenarios and injected native callback tests are recorded in
[iPhone simulator validation](iphone-simulator-validation.md). This is not yet
a friend-installable TestFlight release: signing and upload succeeded, but
processing/distribution, installed-build admission and a physical iOS 27
acceptance run remain unverified. Version/build defaults are placeholders; query
live App Store Connect state before assigning the upload build number.

Measured evidence is in `reproducibility-20261006.json`,
`payload-verification-20261006.json`, and `appattest-verification-20261006.json`.
`developer-id-appattest-20261006.json` records the separate Developer ID capture.
Full private development packages remain on the mini and are not public artifacts.

Historical validation for the earlier milestone: 70 Python tests and all 42 contract tests passed, including
three Developer ID tests and five epoch tests. Swift V1/V2 request hashes match
independently generated ABI vectors. Generated iOS project regeneration is
byte-identical. The first hosted unsigned CI job passed
([run 37545040726](https://github.com/amiller/apple-attest-p2p/actions/runs/37545040726));
its downloaded unsigned bundle matches the mini byte for byte. The later GUI
also matches independently (run 37549470397) and passed live zero-setup receipt
on Base Sepolia. External TestFlight distribution remains pending.

Release work is isolated on `release/mac-distribution`; the active visualization
checkout is untouched. The public sample repository is `amiller/apple-attest-p2p`. The confirmed faucet
is the shared testnet signing key with a verified exchange receipt; its
all-holders-restart recovery uses explicit administrator action. `DemoV2` implements
explicit administrator-controlled key epochs, with five passing policy tests.
The Swift peer supports the V2 context and opt-in saved enrollment identity and
compiles on the pinned Mac toolchain; live isolated-chain restart and recovery
validation passed. Existing V1 network deployments are unchanged.

## Primary references

- [GitHub Xcode 27 hosted ARM64 image](https://github.blog/changelog/2026-09-10-xcode-27-runner-image-now-runs-on-macos-27/)
- [GitHub Apple signing setup](https://docs.github.com/en/actions/how-tos/deploy/deploy-to-third-party-platforms/sign-xcode-applications)
- [Apple notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow)
- [Apple TestFlight overview](https://developer.apple.com/help/app-store-connect/test-a-beta-version/testflight-overview/)
- [Apple adding platforms](https://developer.apple.com/help/app-store-connect/create-an-app-record/add-platforms/)
- [Bitcoin Core reproducible builds and separate signing](https://github.com/bitcoin/bitcoin/blob/master/contrib/guix/README.md)
- [Recorded TestFlight experiment](../data/iphone-20261005-xs18/RESULTS.md)
- [Recorded peer network run](../data/p2p-run-20261006/RESULTS.md)

Notarized export evidence: `notarized-payload-20261006.json` and
`notarized-appattest-20261006.json`. These describe the original CLI candidate
whose unsigned hash begins `89697437`, not the later recovery or future GUI build.

## Native participant candidate (October 6 continuation)

`python3 scripts/release/build_mac.py --gui --out build/gui` builds the native
Mac window/menu-bar participant. Normal launch starts the configured release
network automatically. Close keeps serving; Quit stops. Agent status is written
to `~/Library/Application Support/AttestNode/status.json` from the same protocol
events as the UI. The default build pins RPC, chain, contract, category, relay and
protocol in measured executable code; developer config cannot override them.

The operator seed uses the same executable through LaunchServices, with a public
config and the `seed` role. It retains the group key in memory while recovering
from connection failures and renewing an expired identity. After complete loss
of all RAM key holders, an explicit administrator epoch change is still required.
No test STOP message is honored by persistent participant/seed modes.

Real-device isolated-chain evidence: `../data/gui-release-20261006/RESULTS.md`.
The GUI received the key, served an onward peer, resumed the same identity after
restart, and recovered after the durable relay restarted. The relay journals
signed transactions before submission and stores bounded, expiring mailboxes.
Its source and locked dependencies are in `node/relay-hosted`.

The separate Base Sepolia release deployment is recorded in
`contracts/network/deploy-release-base-sepolia.json`; its dedicated sponsor is
`0xe45C80da8A992447E9Da6d2d82Fe4b6Fa2d48C61`. The HTTPS relay is
`https://pod.dstack.soc1024.com/apple-attest-p2p-relay`. The sponsor credential was
explicitly approved for this pod and is excluded from source and build artifacts.
The exact protected Developer ID GUI is now registered and admission enabled;
see `gui-network-activation-20261006.json`. The exact notarized GUI completed
normal zero-argument enrollment/key receipt; see `gui-live-network-20261006.json`.
