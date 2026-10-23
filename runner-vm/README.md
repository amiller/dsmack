# Generic VM runner: selected source join

This directory imports the **actual qualified app3 source**, not the older
`../runner` implementation. The original import contains 556 source/fixture files:
96 Swift/control/contract/packaging files and 460 native build-source files.
The selected final-app derivation checks 557 inputs under explicit derivation
SHA-256 `55f235c383e7312f96b862bfdd0709cb7f5f16001691eb29699ec2f1d5106178`;
use that selector for the current source rather than the original-import default.
The extra input is `app-src/Sources/mar/V3TemplateCapacity.swift`. The derivation
also changes the existing `V3Launch.swift`, `disks_v3.rs` and `spec_v3.rs` inputs;
it is not a claim that all 556 original bytes remain unchanged.
`SOURCE-DERIVATION.json` records those before/after hashes.
`SOURCE-IMPORT.json` records each original hash and relocated path. This is a
local release candidate awaiting selected-source/publication review; source
assembly is not a new signed release or a second-Mac qualification.

The generic app is here. Base images and their container/guest policy belong in
independent image releases. Bounty selection, credentials, progress feedback,
GitHub integration and reward claims belong in an application client outside the
signed app. No image, native archive, OAuth input, VM disk, signing key, personal
provisioning profile or historical Git repository is embedded in this import.

## Selected final-app source and build lineage (22 October 2026)

The selected 557-input derivation produced native archive SHA-256
`e10fef08b757f6f97a286696ea7f8e5b38be8b27c8b5c11f8d775e60327b2ed6`
and unsigned executable
`effdba5c14a01b9867ed7c922e4540d4b2498adc581ffa610480a49ca1feb56a`.
Subsequent independently selected Developer ID signing and Apple notarization
export produced the final executable
`7616deeb7a461ada6a4dc9b092177229295a9059c6f9acdf117b4c580c1ebd17`
with full CodeDirectory digest
`6b9baf8b20a1212adb6e9d08a36b8dd66c471dffb9d870ef1ac75413bfebd64d`.
These are distinct build/signing identities. Source inspection alone does not
establish the signing/export correspondence; retain the selected original build
and independent signing/notarization records. This is local measured provenance,
not hosted Sigstore provenance or a reproducible-build claim.

The same final app has run on the selected Mini with independently verified
retained evidence. D9 and the B44 broker-timeout derivative are separately
measured base images; changing the base does not change the app identity.
Distribution assessment passed, but normally secured fresh-Mac Gatekeeper
enforcement and a second-Mac first-launch journey remain unqualified. Source,
tag and binary publication are still separate approval steps.

### Historical original-import build (before the final derivation)

The selected source export completed an actual offline native cross-build on
Linux in 24.25 seconds and an actual fresh unsigned Swift build on the Mac in
84.32 seconds. The rebuilt native archive is SHA-256
`684ae43fe72c74e0749d45c723aa76ec61aa1a8cbc83994f08a24feb4aed204e`;
the new unsigned executable is
`203b8940f30892c8afffd4fc4ea3d56df8c6f217af19f92f24529bc47d6057a2`.
The independent selection review bound that exact native build record and output.
Ten source/selection/cleanup controls also passed on Linux and the actual Mac.
No imported implementation bytes changed. The different output hashes are
explicitly new candidate identities. No new signing, App Attest enrollment,
VM execution, hosted provenance or friend distribution was performed here.

## Inspect without a build

From the repository root, with standard-library Python:

```sh
python3 runner-vm/source_check.py \
  --source-derivation-sha256 55f235c383e7312f96b862bfdd0709cb7f5f16001691eb29699ec2f1d5106178
python3 -m unittest discover -s runner-vm -p 'test_source_join.py' -v
```

The explicit selector checks the 557 selected inputs, preserves original-import
provenance and rejects an unselected derivation. These checks inspect file hashes, reject unexpected compile inputs and
check the native inventory against the historical archive's source lock. They
make no network requests, launch no VM, sign nothing and use no subscription.
The release/build adapters are outside the immutable imported directories.
They replace machine-specific placement without editing historical source.

## Native archive build (Linux build machine)

Use a build machine with adequate disk/RAM, the exact Rust compiler recorded in
`QUALIFIED-INPUTS.json`, its `aarch64-apple-darwin` standard library, and a prepared
Cargo cache containing the pinned dependencies. Do not build on a small laptop.
The original native build is an SDK-free staticlib cross-compile. The later
Swift/Mach-O link requires the actual Mac SDK. There is no automatic dependency
or toolchain installer here.

```sh
python3 runner-vm/build_native.py \
  --source-derivation-sha256 55f235c383e7312f96b862bfdd0709cb7f5f16001691eb29699ec2f1d5106178 \
  --work-dir /absolute/external/fresh-native-build \
  --toolchain-dir /absolute/rust-toolchain \
  --cargo-home /absolute/prepared-cargo-cache --check-only
```

Remove `--check-only` to build. The work directory must not already exist and
must be outside the source checkout. The adapter reuses the original bounded
Linux supervisor, including exact compiler version, offline/locked resolution,
resource/time/disk bounds, isolated staging, group cleanup and persistent residual
ownership. It relocates toolchain/work/cache paths only. Its output contains a
new source/build provenance record. This record is local build evidence, not a
GitHub/Sigstore attestation. A different resulting archive hash is a new candidate requiring an independently
selected build record and archive pins; do not quietly accept it as the original.

## Unsigned app build (Apple silicon Mac)

The currently reviewed input lock names the actual historical native archive
SHA-256. Obtain that exact archive through a separately verified artifact channel
or rebuild and independently review/select its new native build record. This checkout supplies source, not a pretend
release download. Use the exact Xcode/Swift versions in `QUALIFIED-INPUTS.json`.

```sh
python3 runner-vm/build_unsigned.py \
  --source-derivation-sha256 55f235c383e7312f96b862bfdd0709cb7f5f16001691eb29699ec2f1d5106178 \
  --archive /absolute/verified-input/libdsmack_hvf_returning.a \
  --out /absolute/external/fresh-unsigned-build --check-only
```

For a fresh rebuilt archive, keep `QUALIFIED-INPUTS.json` unchanged. Independently
review the native build record and select its raw SHA-256 and actual archive
SHA-256. Add all three arguments to the command above:

```text
--native-build-record /absolute/selected/BUILD-PROVENANCE.json
--expected-native-build-record-sha256 INDEPENDENT_RAW_BUILD_RECORD_SHA256
--expected-native-archive-sha256 INDEPENDENT_NEW_ARCHIVE_SHA256
```

The gate joins the exact original native source inventory, qualified compiler,
offline/locked ARM64 target command, confirmed-empty build group, artifact length
and the independently selected record/artifact digests. It never auto-discovers
or trusts a hash supplied only by the candidate. These are operator-selected
local build records, not cryptographic hosted-build provenance; a production
release must add its reviewed GitHub/Sigstore chain. A caller choosing its own
pins has not obtained independent approval. A newly built app needs its own
frozen-candidate/signing/hardware qualification; it does not inherit the original
app's CD digest or enrolled identity.

Preflight checks source membership, native archive bytes, all 19 ABI symbols and
actual Swift/Xcode versions, without compiling or signing. Apple nm currently
returns nonzero for some Rust archive members while still reporting all required
definitions; the preflight retains that exit status and makes no full-archive
parse claim. Actual linking remains a separate build check. Remove `--check-only`
to build a fresh source copy outside the checkout. The Swift package locks are
preserved. Resolving the already pinned dependencies may require network/cache
access; this is development activity on the build Mac, not a model call. Inspect
`compile.log` and `UNSIGNED-BUILD.json`. The adapter packages DsmackRunner.app,
records actual hashes, and does not invoke the app or any signing operation. The
checked archive bytes are staged under the exact library basename the Swift
link consumes and checked again afterward. Swift child cleanup reuses the
original group-based escalation and persistent residual-owner logic, with a
portable process-group observer; an exited leader alone is not a cleanup pass.
A matching historical executable is reported as an observation; reproducible
builds are not assumed. Changed package metadata and file paths can change output.

`packaging/build.sh`, `packaging/sign.sh` and historical signing documentation are
preserved evidence of the original build, including stale stage comments and
maintainer-specific paths. They are **not the portable entrypoints** and are not
an instruction to unlock a maintainer keychain. Signing must use a separately
reviewed frozen candidate and the release procedure in
[the release runbook](../docs/release/runner-release.md).

## Licensing and remaining release gates

The imported libkrun tree retains its Apache-2.0 `LICENSE`, copyright notices and
per-file license headers. Consult [dependency notes](THIRD-PARTY.md); this is not
an assertion that the repository's top-level MIT license replaces upstream
licenses or that an SBOM/legal review has finished.

Before distributing: selected-source/fixture/license review; a clean public-only
build rehearsal; new source/artifact provenance; safe archive extraction;
external helper/image/client integration; an explicitly qualified distribution
profile; and the complete second-Mac inspect → doctor → enroll → private import
→ task → verified result journey. A production App Attest environment is distinct
from signing certificate category. No bounty or reward settlement is enabled by
this source import.
