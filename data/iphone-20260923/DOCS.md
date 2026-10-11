# Source map — App Attest CDHash on iOS (checked 2026-09-23)

Apple does not document the CDHash fields or the opt-in on any platform. Everything
about their layout and meaning comes from our captures ([RESULTS.md](RESULTS.md),
[macOS](../macos/RESULTS.md)).

| Source | What it says | Covers CDHash? |
|---|---|---|
| [Validating apps that connect to your server](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server) (JSON refetched 2026-09-23) | Documents `apple_validation_category_01` (UInt32, categories 0–10), `apple_bundle_version_01` (string) and the macOS ACL blob OID `1.2.840.113635.100.8.6` | No. No `cd_hash`, no opt-in |
| `documentation/bundleresources/entitlements/com.apple.developer.devicecheck.app-attest-opt-in` | Page does not exist (HTML shell) | — |
| iPhoneOS27.0.sdk, `DeviceCheck.framework` (Xcode 27.0, 27A266a) | `DCAppAttestService` availability unchanged: `ios(14.0)`. No opt-in or CDHash string anywhere in the framework | No |
| [WWDC26 session 201](https://developer.apple.com/videos/play/wwdc2026/201/) | "new signals in iOS 27"; App Attest now on macOS 27; names validation category and bundle version | No |
| Developer Portal, App ID `dev.dsmack.provider` (read 2026-09-23) | Capability "App Attest Opt-In", entitlement `com.apple.developer.devicecheck.app-attest-opt-in`; platforms iOS, tvOS, watchOS, macOS, visionOS; provisioning Development, Ad hoc, App Store Connect, Developer ID | Opt-in exists; fields not described |
| [Forum thread 836329](https://developer.apple.com/forums/thread/836329) (via tag listing) | Developer reports the capability with value `CDhash` on macOS 27 beta | Opt-in only |
| [Apple security releases](https://support.apple.com/en-us/100100) | iOS 27 released 14 Sep 2026 for iPhone 11 and later; iOS 26 on 15 Sep 2025 | — |

## Unresolved

- Which iOS release added the fields. Tested device: iOS 27.x (reported, build
  unconfirmed). iOS 26 untested on hardware, but see the ipsw diff below: the field
  names first appear in the iOS 27.0 beta 1 system library.
- Short hashes: Darkbloom reports Apple sometimes returning type 2 as the 20-byte
  CandidateCDHash prefix instead of the full 32 bytes (macOS). Our verifier accepts
  only 32 bytes; every iPhone and Mac capture we have is 32 bytes.
- iPadOS: listed by the same portal capability, no device tested.
- The iOS meaning of leaf OID `1.2.840.113635.100.8.6`, documented only for macOS.
- App Store / TestFlight builds: Apple re-signs them, so the reference hash would
  come from Apple's signed build, not the uploaded one. Untested.

## Third-party prior art (GitHub search 2026-09-23; all read, not snippets)

Nobody outside Apple documents these fields in prose (no blog posts, no HN/Reddit/Mastodon/X
discussion found), and the general App Attest verifier libraries (takimoto3/app-attest,
appattest-swift, swift-app-attest and others) parse category and bundle version but not
`apple_cd_hash_*`. Three code bases do:

- **Darkbloom**, [Layr-Labs/d-inference](https://github.com/Layr-Labs/d-inference),
  macOS only. `coordinator/appattest/code_measurement.go` (first commit 2026-09-15)
  parses `apple_cd_hash_hash_01`/`_type_01` and pins provider builds by CodeDirectory
  hash, Developer ID category 6. `docs/reference/app-attest-shadow.md`: SDK 26.5 builds
  returned no measurement, SDK 27 builds did; the 32-byte value matched `codesign`
  CandidateCDHashFull; a later proof carried the 20-byte prefix.
- **hellas-ai/hellas**, `crates/attestation/src/apple.rs` (first commit 2026-07-21,
  during the beta), macOS: requires the 32-byte hash, type 2, category 6, and an
  allowlist. `hellas-ai/gate` `docs/SIGNING.md` names the `CDhash` opt-in.
- **blacktop/ipsw-diffs**: the iOS 26.5 (23F77) → 27.0 beta 1 (24A5355q) diff of
  `AppAttestInternal` adds all four `apple_*_01` extension strings. The `CDhash`
  opt-in string itself already appears in an iOS 18.5 beta diff (2025).

No iOS use of the fields was found anywhere; ours is the only iPhone capture we know of.
