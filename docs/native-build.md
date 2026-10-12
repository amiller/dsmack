# Mac builds and signing

The native participant app requires Apple Silicon and the exact Xcode, SDK and
Swift versions in [node/mac/toolchain.json](../node/mac/toolchain.json).
The current target is macOS 27. Keep platform security settings enabled.
The participant app and the coupon workload runner are separate components.

## Unsigned builds

From the repository root, with an unused output directory:

```sh
python3 scripts/release/build_mac.py --gui --out build/mac-unsigned
python3 scripts/release/check_repro.py --gui --out build/mac-repro
```

Omit `--gui` for the CLI. The builder checks the toolchain lock, hashes direct
inputs and records every unsigned bundle file. Reproducibility compares two
source paths and module caches on one host; independent builders must compare
their own manifests. Select `--version`, `--build-number` and `--bundle-id` to
match the release or invitation being reproduced. A generic checkout is not
necessarily admitted to a deployed network.

The [unsigned Mac workflow](../.github/workflows/mac-build.yml) runs without
Apple credentials. Its runner must still match the toolchain lock. The GUI's
[Fold images](../node/mac/assets/README.md) are required bundle resources.

## Sign and notarize

Use `python3 scripts/release/sign_mac.py --help` for local signing. Public Mac
admission uses Developer ID signing (validation category 6); Apple Development
category 3 belongs to a separate lab profile. Signing requires real authorized
certificates, profiles and capabilities, rather than a Team ID string.

The manually dispatched [signed candidate workflow](../.github/workflows/mac-candidate.yml)
uses a protected `apple-release` environment. Configure these for the selected team:

| Kind | Names |
| --- | --- |
| Secrets | `MAC_CERTIFICATE_P12_BASE64`, `MAC_CERTIFICATE_PASSWORD`, `MAC_PROFILE_BASE64` |
| Secrets | `ASC_KEY_P8_BASE64` |
| Variables | `APPLE_TEAM_ID`, `APPLE_BUNDLE_ID`, `MAC_SIGNING_IDENTITY` |
| Variables | `ASC_KEY_ID`, `ASC_ISSUER_ID` |

Protect release refs before providing credentials; forks do not inherit secrets.
The job signs, notarizes, staples and verifies a candidate ZIP, checksums and
payload evidence. Independent execution with another team's credentials remains
an acceptance requirement. Development archives can contain device identifiers;
keep them private.

`scripts/release/export_mac_xcode.py` supports an existing authorized Xcode
session or the documented App Store Connect API-key inputs. It requires an
initially signed archive and an App ID with the required capability.

Changing team or bundle identity changes sealed metadata and CDHash. The registry
must admit that build under its code/entitlement policy. A notarization ticket,
a matching executable or a successful CI build does not by itself establish
fresh App Attest admission or a clean-Mac first-open journey.

Source changes also require a newly qualified build, including changes to embedded
GUI links such as the independent-builder guide URL. This repository cleanup does
not replace or requalify an existing signed release. Rebuild, sign and qualify the
new executable against the selected network's admission policy before recommending
it to participants.

See [independent-builder handoff](native-builder.md) and [release acceptance](release.md).
