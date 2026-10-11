# TestFlight handoff and review preparation

Status: version 0.1.0/build 5 uploaded successfully from public source
`42a0beba0e650c118332472399443877e2f730d0`. It includes developer upgrade UI,
installed-code evidence export, improved diagnostic sharing and the exempt-
encryption declaration. Xcode last reported that the package was processing.
Build 3 (shown as Missing Compliance) and build 4 are older candidates; processing
completion, compliance status and tester assignment have not been observed for
build 5. This is a diagnostic candidate, not a claim that friends can already
join from it. The iPhone category remains disabled pending installed-build
admission. Do not use the public-beta text below until the positive device run
passes. See [export inspection](iphone-build5-export.json),
[upload receipt](iphone-testflight-build5-upload.json) and
[simulator evidence](iphone-simulator-validation.md).

## Proposed beta description

Apple peer testnet is a research demonstration of peers verifying the software
running on other Apple devices. Open the app on an iPhone running iOS 27 and keep
it in the foreground. It verifies its app identity, contacts a verified peer,
and obtains a shared test-network key with a verifiable receipt. It then claims
a participant research NFT on Base Sepolia for a personal account created by the
app. No payment, deposited funds, wallet import, or in-app account signup is
required. These are test-network research receipts with no monetary value.

If participation fails, choose Share diagnostic report, then Copy, and send the
text to the person coordinating your test. It includes app/OS versions, public
network information and error codes. Do not send Keychain contents or Apple
Developer credentials. Keep the app installed while testing: deleting an app or
losing its account key can lose control of its research account.

## Reviewer instructions to use after validation

- Requires a physical iPhone supporting iOS 27 and App Attest. Simulator support
  is limited to UI testing; unsupported devices stop with a diagnostic report.
- Install through TestFlight and open the app. No app login is required.
- Keep it open through attestation, connection and participant-NFT confirmation.
- View NFT receipt opens the public Base Sepolia explorer. There are no purchases
  or mainnet transfers in this flow.
- Share diagnostic report opens the system share sheet; copying the report is an
  explicit user action. Peer participation is foreground-only on iPhone.
- Contact/review fields must use the existing account's verified information;
  they have not been invented or submitted in this preparation document.

## Operator sequence

1. Inspect App Store Connect app 6819392473 for the latest uploaded build. Verify
   processing, export-compliance status and the existing Lab internal group.
2. On build 5 or later, open Technical details → Prepare code evidence → Share
   code evidence to obtain the installed app's public measurement JSON. This
   export omits profiles, enrollment state and private keys; its positive
   physical-device path is not yet verified. Export failures appear in the
   ordinary diagnostic report. Treat the JSON as untrusted input, not proof of
   provenance or attestation. Compare
   its actual CodeDirectory and signed attestation profile with the uploaded
   executable; Apple re-signs distributed apps. Expect validation category 2.
3. Admit only the verified code under the new iPhone registry and validate the
   category/account policy. Keep the Mac code baseline unchanged.
4. Run the complete physical-iPhone flow: join, shared-key receipt, personal
   account, NFT, quit/reopen without duplication, and copied diagnostic report.
5. Finish external-beta metadata/review/group setup and verify a friend-accessible
   TestFlight link. Publish that exact tested link and the observed limitations.
6. Complete the independent-team signing and upgrade flow separately. Source
   and build 4 include invitation/request import/export and explicit account-
   transfer consent. They do not yet have a positive second-team device run.

The app encrypts peer parcels with Apple's CryptoKit (P256 key agreement, HKDF,
AES-GCM), uses system TLS, and stores personal keys through Security/Keychain.
The local Keccak implementation is hashing, not an encryption implementation.
Apple's [encryption documentation table](https://developer.apple.com/help/app-store-connect/reference/export-compliance-documentation-for-encryption/)
identifies OS-only encryption as not requiring uploaded encryption documentation.
Build 3 lacked an explicit `ITSAppUsesNonExemptEncryption` entry and the screenshot
showed Missing Compliance. Builds 4 and 5 include
`ITSAppUsesNonExemptEncryption=false`, verified in both signed IPA exports. Reassess this
classification if a fork adds encryption implementations or libraries.
