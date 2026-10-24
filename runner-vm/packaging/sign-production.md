# Production signing

DsmackRunner.app is signed on the Mac mini with an Apple Development identity
and a device-bound provisioning profile. [sign.sh](sign.sh) does the signing and
admission checks; this file names the production identity and entitlements.

## Identity and profile

- **Codesigning identity**: `Apple Development: Andrew Miller (QJUJ9F2UE4)`,
  SHA-1 `7B08CCB90D02268C501CF0B19FC5611617C882E2`, in
  `~/Library/Keychains/dsmack.keychain-db`. Certificate subject
  `UID=4AUJZCB85R / CN=Apple Development: Andrew Miller (QJUJ9F2UE4) / OU=DC9JH5DRMY / O=Honey Badger Coop. Labs Inc. / C=US`,
  Apple WWDR G3 issuer, valid 2026-09-08 to 2027-09-08.
- **Team**: the certificate OU, `DC9JH5DRMY`, equal to `signing_policy.TEAM_ID`
  and every profile's `TeamIdentifier`. `QJUJ9F2UE4` in the CN is a
  per-certificate identifier. The signed app verifies as
  `TeamIdentifier=DC9JH5DRMY`.
- **Profile**: `dsmack provider dev`
  (`~/Library/MobileDevice/Provisioning Profiles/595bfc2d-….provisionprofile`),
  macOS, app id `DC9JH5DRMY.dev.dsmack.provider`, created 2026-09-08, expires
  2027-09-08, provisioned for one device (this Mini). Its embedded
  DeveloperCertificate is the identity above. Profile entitlements:
  `com.apple.application-identifier`, `com.apple.developer.team-identifier`,
  `com.apple.developer.devicecheck.app-attest-opt-in = [CDhash]`,
  `keychain-access-groups = [DC9JH5DRMY.*]`.

The `Mac Team Direct Provisioning Profile: dev.dsmack.provider` (expires 2044,
`ProvisionsAllDevices`, carries `com.apple.security.virtualization`) embeds
Developer ID Application certificates (SHA-1 `34BC8D65…`, `5291F798…`,
`4CEB3FD8…`) that are not on this Mini, so it cannot be used with this identity.

No profile carries `com.apple.security.hypervisor`; the HVF entitlement comes
from the embedded entitlements plist. A development-signed diagnostic with these
five entitlements and this profile created and destroyed an empty HVF VM on
2026-10-22 (`hvf-entitlement-probe-20261022` on zed `/data`). If
`hv_vm_create` is denied, regenerate the profile with the Hypervisor capability
or use the team's Developer ID route.

## Entitlements

[DsmackRunner.entitlements](DsmackRunner.entitlements) holds the five keys
admitted by `check_entitlements(...)`:

- `com.apple.application-identifier` = `DC9JH5DRMY.dev.dsmack.provider`
- `com.apple.developer.team-identifier` = `DC9JH5DRMY`
- `com.apple.developer.devicecheck.app-attest-opt-in` = `[CDhash]`
- `keychain-access-groups` = `[DC9JH5DRMY.dev.dsmack.provider]`
- `com.apple.security.hypervisor` = `true`

The hypervisor key is `com.apple.security.hypervisor` (`com.apple.vm.hypervisor`
is not an entitlement). `com.apple.security.cs.*`, including
`disable-library-validation`, is forbidden: the binary links 40 Apple-platform
dylibs (`/System/Library/...`, `/usr/lib/...`, `/usr/lib/swift/...`), the Rust
backend is statically linked, and nothing calls `dlopen`/`dlsym`, so library
validation holds. `com.apple.security.virtualization` is omitted because the app
calls no Virtualization.framework API; VM creation is the Rust HVF archive
(`hv_vm_create`).

## Sign

Unlock the keychain with `local-data/mac-signing/unlock-existing.py` and sign in
the same SSH Python process on the Mini. Start from the accepted unsigned build
and record its digest first:

```bash
shasum -a 256 build/DsmackRunner.app/Contents/MacOS/dsmack-runner
KEYCHAIN=~/Library/Keychains/dsmack.keychain-db \
SIGN_IDENTITY="Apple Development: Andrew Miller (QJUJ9F2UE4)" \
ENTITLEMENTS=runner-vm/packaging/DsmackRunner.entitlements \
PROFILE=".../595bfc2d-….provisionprofile" runner-vm/packaging/sign.sh
```

The bundle is `Contents/MacOS/dsmack-runner`, `Contents/Info.plist`
(`CFBundleIdentifier` `dev.dsmack.provider`) and
`Contents/embedded.provisionprofile`. `sign.sh` signs with `--options runtime
--generate-entitlement-der --timestamp=none`, runs `codesign --verify --strict`,
and checks the signed entitlements and metadata with `check_entitlements` and
`check_metadata`, writing `build/admission.json`. Flags must include `runtime`
and not `adhoc`/`linker-signed`. Record the full 32-byte `CandidateCDHashFull`
and the signed binary's SHA-256; signing rewrites the binary, so both differ from
the unsigned digest.

The operator App Attest policy accepts AAGUID environment PRODUCTION, category3
(Apple Development signing, independent of AAGUID environment), app
`DC9JH5DRMY.dev.dsmack.provider` and the signed CDHash, with the Apple App Attest
DER root SHA-256
`1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932`.

Keep signing records to public metadata: digests, fingerprints, entitlements,
team fields, codesign output and the unlock adapter's exit code.
