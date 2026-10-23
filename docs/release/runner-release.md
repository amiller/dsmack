# DsmackRunner release and first-run gates

This runbook prepares a tagged release that a contributor and their agent can
inspect before running. **There is not yet a friend-install-ready release of the
qualified VM runner in this checkout.** The successful 22 October 2026 Mac demo
used a reviewed, separately assembled candidate. `runner/sign.sh` builds the older
runner; running it or tagging this checkout does not recreate that candidate.
The exact selected generic app/native source is now assembled in [runner-vm](../../runner-vm/README.md), with standalone inspect and unsigned-build adapters. Its source checks, actual Linux native rebuild and actual Mac unsigned build pass; a clean public-release/friend distribution rehearsal remains unqualified. The tooling below is usable now. Publishing/signing a new release is a separate
maintainer operation after selected-source review.

## What each check establishes

| Check | Establishes | Does not establish |
| --- | --- | --- |
| Protected version tag + source commit | Which source the reviewer selected | Binary correspondence |
| GitHub artifact attestation / Sigstore OIDC | Artifact bytes were attested by the expected workflow at the pinned source commit | Code safety, reproducible build, Apple trust, task success |
| Apple signing + strict bundle verification | Code signature and bundle seal, with independently checked identity | That this binary executed a task |
| CodeDirectory analysis | Actual Mach-O code pages agree with each embedded CodeDirectory; identity and full primary SHA-256 CD digest match policy | Apple CMS trust, external bundle resources, source correspondence |
| Genuine App Attest enrollment/assertions | Accepted Apple environment/category/app identity and enrolled key with freshness/replay checks | A useful or correctly specified bounty |
| VM/image/workload + independent task checker | Selected environment and authenticated outputs meet the frozen task policy | Payment settlement or economic fairness |

Obtain the expected tag, commit, workflow, release archive SHA-256, full CD digest,
Team ID, bundle ID and entitlements policy from a separately reviewed release
policy. Values supplied only by the downloaded candidate are observations, not
an independent trust anchor. Audit the repository's verification scripts before
using them. No `curl | sh`, sourcing a downloaded release script, or disabling
Gatekeeper is part of this runbook.

## Current qualified Mini identity (22 October 2026)

The final notarized Developer ID app has executable SHA-256
`7616deeb7a461ada6a4dc9b092177229295a9059c6f9acdf117b4c580c1ebd17`
and full CodeDirectory SHA-256
`6b9baf8b20a1212adb6e9d08a36b8dd66c471dffb9d870ef1ac75413bfebd64d`.
Team is `DC9JH5DRMY`, bundle is `dev.dsmack.provider`. Its all-device profile,
strict signature, stapled ticket, distribution assessment, fresh production
category6 enrollment and actual Mini execution/full verification have passed.
These are distinct from a public source-build attestation or another Mac's
quarantined first-open. The qualification Mini had Gatekeeper globally disabled;
no global security setting change is part of installation.

The Linux base and OCI workloads are separately selected measured inputs. D9
historical evidence and the B44 broker-timeout derivative must not be described
as different app signatures. B44 retains buffered responses, idle timeout10s and
32MiB response bounds; its210/220s watchdogs do not guarantee provider billing
cancellation. Consult the selected release's exact resources and provenance.

Use the [inventory/2 staging contract](../pilot/alpha-install.md) and
[versioned runtime profiles](../pilot/alpha-runtime.md) for current operator
interfaces. Public release tags/artifacts, fresh-Mac acquisition and hosted
Sigstore source-build proof remain pending. Full paid acceptance/payment is a
separate graph of original evidence, not implied by these release checks.

## Historical engineering source correspondence

The known successful executable is SHA-256
`85b15fde15253600ffd5b59fb755731aeca58f7cd5d60ad1b238b2c9ab1b8032`,
with full primary CodeDirectory SHA-256
`bd7aadb4eafeaa9a4c27572c5bd84ff3af98b5eb8f4e83c1192c3cfc728f22db`.
This records a historical qualification, not an allowlist for every future build.

The actual app candidate has 96 source/fixture/packaging files: `app-src` (24),
`control-src` (23), `io-contract-consumer` (40), and `packaging` (9). Its original
source inventory SHA-256 is
`2b7094db85a835bbdc86cb4975dfb1ed3b8b1977dd395224ff186dbb8d5fd01d`.
A selected import should preserve this inventory and explicitly record every
path relocation and subsequent change. The intended self-contained layout is:

```text
runner-vm/
  app-src/                 # generic signed Swift runner, target mar
  control-src/             # local Swift control/attestation packages
  io-contract-consumer/    # shared contracts, fault tests, reference vectors
  native/                  # exact native source + pinned upstream/lock/build inputs
  packaging/               # unsigned build, signing gate, Info/entitlements
applications/bounty/       # task client, credential import, progress UI; outside app
images/                    # independent image/build/checksum lock
helpers/                   # host network launcher + pinned upstream gvproxy
verification/              # full evidence checker and immutable task acceptance
```

The runner-vm app/control/contract/packaging/native source is now present under this layout. The separate application, image, helper and verification release joins remain proposed targets.
Review selected source and fixtures before importing; do not upload private
history, raw operator state, provisioning secrets or credential-bearing files.
The native archive used by the successful app is SHA-256
`327b75b2c77359e010d0ca0793581ce4f3d323739cf0f496dcf5d98b0deda819`;
its source inventory is
`c43d67366eee743c0ea7d0084b995dad0bee5d5308f9d9ba4ac975862da5fdf6`.
An opaque archive alone is insufficient for a source-auditable release.

The qualified unsigned entrypoint is `candidate/packaging/build.sh`, not the old
`runner/sign.sh`. It compiles `app-src` (`swift build -c release --product mar`)
and links the independently pinned native archive, checking the complete 19-symbol
v1/v2/v3 ABI. It currently has maintainer-specific native paths. The new `runner-vm/build_native.py` and `runner-vm/build_unsigned.py` adapters preserve those original files and relocate build inputs explicitly, retaining source/digest/symbol gates. Review the adapters and qualify their actual builds; do not use the original machine-specific script as the portable entrypoint. Qualify a clean public-only
clone build with a pinned SDK/Swift/dependency lock before creating a tag. The
qualification used macOS 27, Xcode 27 and Swift 6.4; matching versions is not a
claim of bit reproducibility.

The image, workload/container, gvproxy, helper, coordinator and verification
application have their own source/build/output locks. Version and distribute
them independently. Do not hide application policy inside the generic signed
runner or imply that its CD digest identifies an arbitrary task container.

## Maintainer: tag, build, sign, attest, retain

1. Select a reviewed source commit containing the joined, portable source and
   runbook. Use a protected immutable version tag (`vX.Y.Z`); record its full
   commit SHA and workflow source SHA. Never move a released tag or replace an
   existing asset under the same version.
2. Build **unsigned** from that exact commit in the reviewed pinned build
   environment. Record source inventories, toolchain, dependency locks, native
   inputs, unsigned executable and artifact hashes. Build tests do not replace
   independent review. No signing key is available to pull-request jobs.
3. Independently review the frozen unsigned candidate, then sign in the
   explicitly authorized Apple signing environment. Keep the operation separate
   from compilation. Preserve the unsigned bytes and record the exact final
   signed executable, full SHA-256 CD digest, Team ID, bundle, complete
   entitlements, provisioning profile and signing operation. Re-signing changes
   the admitted identity and requires new enrollment/qualification.
4. Verify the final app and qualify a fresh contributor Mac as below. Publish a
   release archive only after a selected-source/export review. Retain the exact
   final archive hash as well as the inner executable hash.
5. Generate provenance for **the final distributed bytes**. An attestation of an
   unsigned build does not cover its later Apple-signed replacement. A two-stage
   pipeline needs separate unsigned build provenance and final package provenance
   plus a signed manifest binding both, the source revision and the signing step.
   GitHub OIDC attestation of a manually uploaded local binary is a packaging
   assertion; it is not evidence GitHub built that binary from source.
6. Package the archive, release policy, checksum inventory, source/native/image/
   helper locks, SBOM/license notices, review/qualification summaries, attestation
   bundle and first-run instructions. Publish without OAuth keys, private runtime
   disks, device-key exports or signing secrets. Keep an offline archive of the
   exact assets and provenance. A revoked version gets an advisory and a new
   version; an immutable download is never silently repaired.

**Workflow activation remains gated.** This checkout intentionally does not add
an automatic release workflow that builds the obsolete runner. The eventual
reviewed workflow needs least permissions (`contents: read` for build;
`id-token: write` and `attestations: write` only in the attesting job), actions
pinned by full commit SHA, protected environments for signing/publication, and
immutable source/artifact transfers. Review reusable builder identity separately:
the helper below deliberately supports only the same-repository same-commit
release workflow profile and rejects self-hosted provenance. A Mini-built app
needs an explicitly reviewed different profile; do not remove that check merely
to accept the historical demo. No successful hosted attestation is claimed here.

## Contributor: inspect first, then spend capacity

Use an agent-reviewed clone at the selected commit, a new private downloads
folder, and independently supplied policy values. Download the release archive
as data. **Do not open it or import credentials yet.** The standard-library
verifier snapshots a current-user-owned, regular single-link file, rejects unsafe
permissions, checks its expected hash, then asks trusted GitHub CLI to verify the
cryptographic provenance with every identity boundary pinned:

```sh
python3 tools/release/verify_provenance.py /absolute/path/DsmackRunner.zip \
  --repository amiller/dsmack --workflow release.yml \
  --tag vX.Y.Z --commit FULL_APPROVED_COMMIT_SHA \
  --expected-sha256 INDEPENDENT_ARCHIVE_SHA256
```

The capitalized arguments and version are placeholders for a real approved
release; this command is **not runnable against today's unreleased candidate**.
The trusted GitHub CLI must be stable 2.102.0 or newer: earlier versions had
source-ref case and signer-workflow prefix policy bugs. A checksum match or an
empty `gh` result is not a pass. Online lookup avoids the repository-name reuse
ambiguity of an offline bundle; plan offline policy/root updates separately.
The helper makes no installation, archive extraction or candidate subprocess.

Only after provenance verification, inspect the archive member list for absolute
paths, traversal, duplicate names, links, unexpected files and unreasonable
expansion. Extract with an independently reviewed safe extractor into a fresh
private directory. An app bundle can legitimately contain links; any exception
must be explicitly reviewed against a manifest, not a blanket archive allowance.
The reviewed [inventory/2 installer](../pilot/alpha-install.md) implements the
bounded authenticated extraction route. This inspection helper alone does not.

On macOS, without launching the app, inspect the extracted bundle:

```sh
codesign --verify --deep --strict --verbose=4 /absolute/path/DsmackRunner.app
codesign --display --verbose=6 /absolute/path/DsmackRunner.app
codesign --display --entitlements - --xml /absolute/path/DsmackRunner.app
spctl --assess --type execute --verbose=4 /absolute/path/DsmackRunner.app
python3 tools/release/inspect_runner.py \
  /absolute/path/DsmackRunner.app/Contents/MacOS/dsmack-runner \
  --expected-cdhash INDEPENDENT_FULL_SHA256_CD_DIGEST \
  --expected-team INDEPENDENT_TEAM_ID --expected-bundle INDEPENDENT_BUNDLE_ID
```

Compare the exact certificate authority chain, Team ID, bundle, hardened runtime,
full CD digest and complete entitlements against policy, including unexpected
extra entitlements. The analyzer reuses `contracts/cd_args.py`, checks all declared
CodeDirectories and all code pages (including the partial final page), and checks
embedded special slots. Its output explicitly leaves Apple signature trust and
external bundle-resource verification **false**; the separate bundle/Apple checks
are required. Thin ARM64 is the supported profile; unsupported/scatter layouts
fail instead of being silently accepted. Legacy `cd_args.py` argument export
remains argument extraction, not full-page verification.

### Apple Development versus friend distribution

The successful app used Apple Development signing on the already provisioned
Mini. That does **not** establish download-and-run on an arbitrary friend's Mac.
Apple documents development distribution to registered devices; a friend may
need device registration and an appropriate provisioning profile. Repackaging or
changing the profile needs a fresh sealed-bundle and genuine enrollment check.
Developer ID plus notarization is the normal direct-download route, but App
Attest capability/profile compatibility and the resulting evidence category must
be qualified on hardware before selecting it. Do not assume category 3 from the
Development demo applies to another signing route or hardcode category 6 without
checking the actual evidence. Certificate category is separate from the App
Attest environment: the successful Development app produced **production**
environment evidence with category **3**. Gatekeeper assessment is a distinct
check, not something Sigstore or App Attest replaces. Do not bypass a failed
assessment with `xattr -d`, reduced security, or an undocumented exception.

### Incremental first-run acceptance

Before asking someone for their subscription, the shipped application client must
make these individually runnable and understandable (the public CLI/UI is still
a release blocker, not an existing set of commands):

1. **Inspect:** source/provenance/Apple/bundle/page checks above; no candidate
   execution or credentials. Show which release, what permissions and what remains
   unqualified.
2. **Local doctor:** explicitly launch the verified runner for a bounded empty
   VM test; check ARM64/macOS/HVF, disk/RAM, image/helper hashes, actual required
   network reachability and clean shutdown. No account import or model call.
3. **Enroll:** disclose Apple network activity and persistent local key; verify
   genuine production/category/app-CD policy at the service. Show a readiness
   receipt. NFT issuance, if offered, is separate and optional.
4. **Private import:** preview only allowed credential fields and destinations;
   refuse short lifetime, exclude Claude settings/hooks, never publish secrets or
   plaintext private disks. Explain that this demo does not protect VM memory
   from a sufficiently privileged host. Import only after these checks.
5. **Small task:** show reward eligibility, immutable verifier/version, effort
   and timeout limits, network policy, maximum local capacity/subscription usage,
   private/public outputs and interruption semantics before starting. Progress is
   observable telemetry, not proof of success; declare what the host may see.
6. **Review and claim:** show returned changes, browser/test evidence, genuine
   evidence-verifier verdict and immutable task acceptance separately. Explain
   rejection reasons and retry/refund rules. A valid execution is not automatically
   accepted work, and accepted work is not a confirmed payment.

The first friend rehearsal must run these from a fresh clone and actual release
asset on a second Mac, with no private planning checkout or maintainer-only paths.
Keep the recording and machine-readable results. Until it passes, label the
release a maintainer-qualified preview, not self-serve bounty enrollment.

## Tool checks

```sh
python3 -m unittest discover -s tools/release -p 'test_*.py' -v
```

The tests cover changed nonzero/final code pages, embedded entitlement corruption,
wrong identity/CD policy, malformed/duplicate signature layouts, unsafe input
files, missing verified provenance and unpinned policy. Actual read-only inspection
of the signed demo executable also verified all 3,494 code pages without launching
it. These checks do not substitute for the unperformed friend install and hosted
release-provenance rehearsals.

## References

- [GitHub CLI attestation verification and policy flags](https://cli.github.com/manual/gh_attestation_verify)
- [Source-ref policy fix, CLI 2.102.0](https://github.com/cli/cli/security/advisories/GHSA-4mq3-hpgx-9cx8)
- [Signer-workflow policy fix, CLI 2.102.0](https://github.com/cli/cli/security/advisories/GHSA-wjmr-j3rp-mh2g)
- [Apple development distribution to registered devices](https://developer.apple.com/documentation/xcode/distributing-your-app-to-registered-devices)
- [Apple Developer ID distribution](https://developer.apple.com/developer-id/)
- [Apple notarization](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)
