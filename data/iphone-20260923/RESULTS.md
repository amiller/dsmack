# iPhone App Attest code identity — 2026-09-23

**Answer.** On the tested iPhone, an ad hoc build that opts in with
`com.apple.developer.devicecheck.app-attest-opt-in = [CDhash]` gets the full
SHA-256 of its CodeDirectory inside Apple-signed App Attest evidence, in both
enrollment and every assertion. The key survives an in-place install of different
code, and the next assertion reports the hash of the code running at that moment,
not the code that enrolled the key. A verifier that checks the hash on every
assertion therefore admits only approved executables, whichever developer team
signed them, as long as it has the exact signed build to compute the reference
value from.

The substitution was tested in both directions with a retained key. Row 12: key E,
enrolled by the honest build, asserted by the modified build installed over it.
The assertion is valid under E's enrolled key (counter 2) and carries the modified
hash, so identity-only policy accepts it and the approved-hash policy rejects it.
Row 5 is the reverse (key enrolled by modified code, asserted by honest code, honest
hash reported). This matches the Mac result ([macos/RESULTS.md](../macos/RESULTS.md)).

## Conditions

- Phone: papi's iPhone, registered UDID `REDACTED_DEVICE_IDENTIFIER`.
  iOS 27.x as reported by papi ("like 27.2"; not in the evidence, not screenshotted).
  Apple's security-release list shows only iOS 27 (14 Sep 2026) so far, so the exact
  build is unconfirmed. iOS 26 is untested; no Apple source says which release added the fields.
- App ID `DC9JH5DRMY.dev.dsmack.provider`, bundle version 1, production environment.
  App ID capabilities: App Attest + App Attest Opt-In. The portal lists the opt-in for
  iOS, tvOS, watchOS, macOS and visionOS, with Development, Ad hoc, App Store Connect
  and Developer ID provisioning (read 2026-09-23). Apple's public documentation does not
  mention the opt-in or the `apple_cd_hash_*` fields as of the same date.
- Ad hoc export, Xcode-managed profile `7a691543-fd07-4680-a15a-235a2afb2dc7`, cloud-managed
  Apple Distribution certificate. `get-task-allow = false`. Installed over the air
  (`itms-services`) from the verifier host; updates were in place, no uninstall.
- Two builds differing only in code pages (honest `double(2) = 4`, modified `= 5`).
  Info.plist, requirements, resources and entitlements slot hashes are identical
  ([digests.json](digests.json), [BUILD.md](BUILD.md)).

```
honest   5395bf39ecded47ab804eb78b7f878c246baa4860ca32cad1c63ed468783b591
modified 85678f245cf838860723c1374e78a9321fa4c87c91900e4921e5877ed0f31b2c
```

These are recomputed by `replay.py` from the main executable inside each IPA, with
every code-page hash checked, and agree with `codesign` CandidateCDHashFull on the Mac.

## Authenticated schema

Same layout as macOS 27. The authenticator data's extension flag is set (`0xc0`) and
its CBOR extensions map is covered by the enrollment nonce and by each assertion signature:

| Field | Type | Observed |
|---|---|---|
| `apple_cd_hash_hash_01` | 32-byte string | full CodeDirectory SHA-256 of the running main executable |
| `apple_cd_hash_type_01` | 1-byte string | `0x02` (SHA-256) |
| `apple_validation_category_01` | UInt32 LE | 5 (ad hoc / enterprise) |
| `apple_bundle_version_01` | string | `"1"` |

The iPhone enrollment certificate also carries OID `1.2.840.113635.100.8.6`, which
Apple documents only as the macOS key access policy. Not yet decoded for iOS.

## Session matrix

Twelve rows, all accepted by the live verifier under an identity-only policy and
re-verified offline. Key labels are per generated key.

| Row | Evidence | Key | Running build | Counter | Attested CDHash | Approved-hash policy |
|---|---|---|---|---|---|---|
| 1 | enrollment | A | honest | — | honest | accept |
| 2 | assertion | A | honest | 1 | honest | accept |
| 3 | enrollment | B | modified | — | modified | reject |
| 4 | assertion | B | modified | 1 | modified | reject |
| **5** | **assertion** | **B** | **honest, installed over modified** | **2** | **honest** | accept |
| 6–7 | enrollment, assertion | C | honest | —, 1 | honest | accept |
| 8–9 | enrollment, assertion | D | modified | —, 1 | modified | reject |
| 10–11 | enrollment, assertion | E | honest | —, 1 | honest | accept |
| **12** | **assertion** | **E** | **modified, installed over honest** | **2** | **modified** | **reject** |

Every rejection is a policy rejection of valid, Apple-rooted evidence, not a
signature or chain failure. The identity-only policy accepts every row.

## Replay

```sh
python3 data/iphone-20260923/replay.py
```

Expected output: [replay-expected.json](replay-expected.json). Evidence snapshot
`captures/papi-20260923-snapshot.sqlite` (SHA-256 `bd2f6186…da51f4c7`) holds the raw
attestation and assertion bytes, challenges and client data. The live
`captures/papi.sqlite` keeps receiving rows. Certificates expire; after that, pass
`--at-time 1790209000` (2026-09-24 00:16 UTC, just after the session) for explicitly historical replay,
never for admission.

## What this does and does not establish

- The hash covers the bundle ID, team ID, the designated requirement (which names
  `Apple Distribution: Honey Badger Coop. Labs Inc. (DC9JH5DRMY)` in these builds), entitlements,
  Info.plist and resources as well as the code pages. Changing only the provisioning
  profile changed both hashes (re-export `a904c14d…` / `e50ac09d…`, not installed).
  Reference values must be computed from the final signed IPA, not the compiled binary.
- The check has to run on every assertion. Enrollment-only checking misses substitution,
  since keys survive code changes.
- Secrets delivered to an approved execution are not protected from a later
  substituted build. On the Mac, modified same-identity code read the tested Keychain
  item ([custody](../macos/custody/RESULTS.md)); iPhone custody is untested.
- One phone, iOS 27.x (build unconfirmed). iOS 26 untested; the ipsw diff in
  [DOCS.md](DOCS.md) suggests the fields first shipped in iOS 27. iPadOS: same App ID
  capability listing, no device tested.
- One developer team. That a second team's build gets its own hash, computable from
  its signed IPA, follows from what the CodeDirectory covers; it was not tested.
- Reference values come from the published signed IPA. Linking that IPA to audited
  source needs a reproducible build and a re-signing check; not attempted.
- Ad hoc distribution requires each phone's UDID in the team's profile: 100 iPhones
  per team per membership year, 24–72 h processing per new device. App Store and
  TestFlight builds are re-signed by Apple; untested.
- The developer can still revoke the certificate or profile, which stops the app
  from launching. That denies service; it does not forge admission.
- Darkbloom reports Apple sometimes returning a 20-byte truncated hash on macOS. The
  verifier rejects it; not observed here.

## Proposed manuscript edits

Apple subsection, replacing the macOS-only CDHash result:

> With the App Attest Opt-In capability, Apple includes the SHA-256 of the app's
> CodeDirectory in the authenticator data of both the enrollment and every assertion.
> We observed this on macOS 27 and on an iPhone with an ad hoc build. The key survives
> an in-place update, and later assertions report the hash of the currently running
> executable, so a verifier that checks the hash on every assertion admits only
> approved builds. The hash covers the signing team and certificate name, so each
> developer's signed build has its own reference value, computable from the published
> IPA.

Compact table qualification: Apple row, code identity column: "CDHash per assertion
(opt-in; macOS 27, iPhone ad hoc)" instead of "signer only".
