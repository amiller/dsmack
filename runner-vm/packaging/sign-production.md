# Endgame procedure correction, 2026-10-22

This isolated procedure candidate requires exact-source review. Andrew already
authorized demo signing/recording. No new routine approval, owner password or
GUI confirmation is required. Exact joined source/artifact review still applies.

Run configured `local-data/mac-signing/unlock-existing.py` and signing in the
SAME Mini SSH Python process. Never source/print build-probe.sh, disclose its
credential, change keychain ACLs or ask Andrew for an agent-created password.
Consult configured recovery records if the bounded adapter genuinely fails.

Use accepted final unsigned/source/archive handoff digests, `--timestamp=none`,
`--generate-entitlement-der` and the exact five-key DsmackRunner.entitlements.
Do not reuse the old early unsigned binary with the E01 pointer escape. Verify
strict signature, actual entitlements/team/bundle and full32-byte CDHash.

Operator AppAttest AAGUID policy is explicitly PRODUCTION plus category3,
app DC9JH5DRMY.dev.dsmack.provider and the final signed CDHash. Category3 is
Apple Development signing, independent of AAGUID environment. Pin DER root
SHA256 1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932.

The same existing five-key entitlement/profile signed diagnostic successfully
created/destroyed its own empty HVF VM: hvf-entitlement-probe-20261022 evidence
on Zed/data. That is not final runner, guest or AppAttest qualification. Leave
the two existing Runner.app VMs alone. Keep recording/video/evidence on Zed
/data. Stage authorized caller subscription immediately before live execution;
require lifetime covering run budget plus headroom and avoid refresh rotation
by other clients during that bounded run. No credentials/settings in evidence.

---

# sign-production.md — WAITING Astra gate (do not execute)

This lane has NOT signed anything and will not. Production signing activates
only after an independent Astra gate re-reviews this exact source set —
including the versioned HVF admission policy introduced 2026-10-20
(`verifier/signing_policy.py` v2, `DsmackRunner.entitlements`). Nothing in
this file is an approval: the v2 profile and this procedure are PROPOSED, and
the `review/astra-gate.json` gate explicitly records
`production_signing_authorized: false`.

## Measured identity and provisioning status (Mini public metadata, 2026-10-20)

Read-only measurement: `security find-identity`/`find-certificate` (public
certificate export only), `security cms -D` profile decode with a public-fields
allowlist (no device UDIDs, no certificate blobs, no private-key access). The
one keychain unlock needed for the certificate read used the exact configured
adapter (`unlock-existing.py`, batch-authorized); evidence is its exit code
only.

1. **Codesigning identity (exactly one valid)**:
   `Apple Development: Andrew Miller (QJUJ9F2UE4)`,
   SHA-1 `7B08CCB90D02268C501CF0B19FC5611617C882E2`, in
   `~/Library/Keychains/dsmack.keychain-db`.
2. **Team reconciliation (was open, now MEASURED — do not re-derive)**: the
   certificate subject is
   `UID=4AUJZCB85R / CN=Apple Development: Andrew Miller (QJUJ9F2UE4) / OU=DC9JH5DRMY / O=Honey Badger Coop. Labs Inc. / C=US`
   (Apple WWDR G3 issuer, valid 2026-09-08 → 2027-09-08). The `QJUJ9F2UE4` in
   the CN is a per-certificate identifier, **not** the team. The certificate
   OU — the actual signing team — is `DC9JH5DRMY`, equal to
   `signing_policy.TEAM_ID` and to every profile's `TeamIdentifier`. The
   identity NAME string above is used verbatim with `codesign --sign`; the
   signed artifact must verify as `TeamIdentifier=DC9JH5DRMY`.
3. **Admissible provisioning profile**: `dsmack provider dev`
   (`~/Library/MobileDevice/Provisioning Profiles/595bfc2d-….provisionprofile`,
   macOS, app id `DC9JH5DRMY.dev.dsmack.provider`, created 2026-09-08, expires
   **2027-09-08**, device-bound: 1 provisioned device — must be this Mini). Its
   single embedded DeveloperCertificate matches the identity SHA-1 above, so
   this exact identity can sign under it. Its profile entitlements include
   `com.apple.application-identifier`, `com.apple.developer.team-identifier`,
   `com.apple.developer.devicecheck.app-attest-opt-in = [CDhash]`,
   `keychain-access-groups = [DC9JH5DRMY.*]`.
4. **NOT admissible with the current identity**: `Mac Team Direct Provisioning
   Profile: dev.dsmack.provider` (expires 2044, `ProvisionsAllDevices`, carries
   `com.apple.security.virtualization`) embeds **Developer ID Application**
   certificates (SHA-1 `34BC8D65…`, `5291F798…`, `4CEB3FD8…`) that are NOT on
   this Mini. Using it would require importing a Developer ID identity — out of
   scope, never attempted by this lane.
5. **Profile-endorsement constraint on HVF (the one open risk)**: NO existing
   profile on the Mini carries `com.apple.security.hypervisor`; the only
   virtualization capability any profile carries is `com.apple.security.
   virtualization` (VZ, Direct profile). The HVF entitlement therefore comes
   from the embedded entitlements plist, and whether a development-signed app
   under profile (3) is runtime-granted HVF **cannot be established from
   metadata alone** — it is an execution-time fact, deliberately unverified
   here. If the future gate's first `hv_vm_create` probe is denied, STOP and
   report; recovery is operator/portal work (regenerate a profile with the
   Hypervisor capability, or use the team's Developer ID route), never a
   policy or doc adaptation to fit the outcome.

## Hard preconditions (all must be true, in order)

1. **Fresh Astra approval** naming: this policy text (`signing_policy.py` v2 +
   unchanged v1), `DsmackRunner.entitlements`, this file, and the exact
   unsigned build digest below. `approved_unsigned_build: true` from
   `review/astra-gate.json` covers the UNSIGNED artifact only.
2. **Backend finality**: use exact accepted v3 archive/source and unsigned build
   handoffs. Historical archive/binary digests are not current pins. Rebuild
   after pointer-scope/ABI fixes, then match the selected exact gate.
3. **Identity (existing only, no changes)**: the measured inventory above is
   still exactly what `security find-identity -v -p codesigning` shows, and the
   keychain unlock (if needed) runs ONLY the configured adapter; no reset,
   no ACL change, no guessing. If the identity is not valid/unlockable, STOP
   and report — that is a blocker, not a workaround situation.
4. **Provisioning**: profile (3) present, unexpired, and its embedded
   certificate still matches the identity fingerprint. Device-bound: confirm
   the run Mini is the provisioned device before signing.
5. **App identity unchanged**: `DC9JH5DRMY.dev.dsmack.provider` everywhere
   (`signing_policy.py`, Info.plist CFBundleIdentifier, embedded profile). If
   any measured value conflicts with these constants, STOP and report the
   exact mismatch — never adapt identity to discovered metadata.

## Entitlements for signing (policy v2)

Use `DsmackRunner.entitlements` verbatim — the exact five keys admitted by
`check_entitlements(...)`:

- `com.apple.application-identifier` = `DC9JH5DRMY.dev.dsmack.provider`
- `com.apple.developer.team-identifier` = `DC9JH5DRMY`
- `com.apple.developer.devicecheck.app-attest-opt-in` = `[CDhash]`
- `keychain-access-groups` = `[DC9JH5DRMY.dev.dsmack.provider]`
- `com.apple.security.hypervisor` = `true`

Corrections vs the previous revision of this file (and vs the retained
`mar-release.entitlements` template, kept only as the recorded build-time
intent of the unsigned cycle — it is REJECTED by both policy profiles):

- `com.apple.vm.hypervisor` is not an entitlement; the real one is
  `com.apple.security.hypervisor`. (`app/build.sh` injected the wrong key
  into its six-key plist, which its own exact-set policy check would then have
  rejected — build.sh now injects only the real key and calls the v2 profile.)
- `com.apple.security.cs.disable-library-validation` is FORBIDDEN
  (`com.apple.security.cs.*`) and NOT needed: the retained binary links
  exactly 40 dylibs, all Apple-platform (`/System/Library/...`, `/usr/lib/...`,
  `/usr/lib/swift/...`; no third-party dylib), the Rust backend is statically
  linked into the executable, and the sources contain no `dlopen`/`dlsym`/
  bundle loading. Hardened-runtime library validation therefore holds with no
  exception. If a future build ever loads a non-Apple library, that is a NEW
  explicit profile review — never a silent exception.
- `com.apple.security.virtualization` (VZ) is dropped: the app calls no VZ API
  (no `import Virtualization` in Swift sources; VM creation is the statically
  linked Rust HVF archive, `hv_vm_create`). Linkage of
  `Virtualization.framework` in the binary is vestigial and grants nothing
  without the entitlement.

## Procedure (after the gate) — unsigned provenance first, signed bytes separately

**Step A — record unsigned provenance (before any signing):**

```bash
# Resolve unsigned path/digest from the accepted joined build handoff.
# Assert SHA256 equals that exact handoff; do not reuse historical early binary.
shasum -a 256 "$APPROVED_UNSIGNED_BINARY"
# Signed binary has distinct provenance/CDHash.
```

This digest describes the UNSIGNED artifact and is retained as provenance only.

**Step B — sign:**

```bash
# app bundle layout first (mar is a CLI executable inside the signed app):
#   DsmackRunner.app/Contents/MacOS/dsmack-runner      <- the exact unsigned binary from step A
#   DsmackRunner.app/Contents/Info.plist     <- CFBundleIdentifier dev.dsmack.provider
#   DsmackRunner.app/Contents/embedded.provisionprofile <- profile (3), copied verbatim
codesign --force --timestamp=none --options runtime \
  --entitlements DsmackRunner.entitlements \
  --sign "Apple Development: Andrew Miller (QJUJ9F2UE4)" \
  --keychain ~/Library/Keychains/dsmack.keychain-db \
  DsmackRunner.app
```

**Step C — verify and record the SIGNED artifact as a NEW artifact:**

```bash
codesign --verify --strict --verbose=2 DsmackRunner.app
codesign -d --verbose=4 DsmackRunner.app 2> codesign-signed.txt
   # TeamIdentifier=DC9JH5DRMY (the OU team — never QJUJ9F2UE4)
   # flags must carry runtime and must NOT carry adhoc/linker-signed
codesign -d --entitlements - --xml DsmackRunner.app > entitlements-signed.plist
spctl -a -vvv DsmackRunner.app                   # Gatekeeper assessment (informational)
shasum -a 256 DsmackRunner.app/Contents/MacOS/dsmack-runner    # the SIGNED bytes digest
```

Admission checks on the signed extraction (as in `app/build.sh`):
`check_entitlements(entitlements-signed.plist)` and
`check_metadata(codesign-signed.txt)` must both pass. Record: codesign output,
signed entitlements, the signed-bytes digest, `CandidateCDHashFull`, the
signing timestamp, and a signed-bundle manifest (every file + sha256).

**The signed digest WILL differ from `275bc839…`.** Signing rewrites the
CodeDirectory and signature into the binary; equality with the unsigned digest
is impossible, and the previous revision's "must equal" requirement was a
defect that would have forced either no signing or false evidence. The
unsigned digest is provenance (step A); the signed artifact is a NEW artifact
whose own digest, CDHash and manifest are what a fresh gate must name.

## Gate boundary (from review/astra-gate.json, binding)

- Any signing operation that changes executable bytes requires a separately
  authorized signing closure and a fresh gate naming the resulting executable
  digest and matching executor manifest. Do not reuse the build digest, alter
  a gate informally, or sign a launch copy after supervisor validation.
- The launch-binding defect (MORNING-LAUNCH-BYTES-TOCTOU) must be repaired and
  re-reviewed before ANY signed executable is launched.
- No App Attest acceptance, enrollment staging, or admission activation is
  authorized by signing. Evidence records public codesign/provisioning
  metadata only — digests, fingerprints, entitlements, team fields; never key
  values, credential material, device UDIDs, or unlock diagnostics.

## Evidence retention

`evidence/` under the signing lane gains: `RELEASE-DIGESTS-signed.txt`
(=Step A provenance digest, Step C signed digest, CDHash, timestamp),
`codesign-signed.txt`, `entitlements-signed.plist`, the signed-bundle manifest,
and the adapter's unlock exit-code JSON. Anything else (keys, profile device
lists, credential output) must never be written.
