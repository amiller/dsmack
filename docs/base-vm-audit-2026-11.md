# Base VM audit, 2026-11

Audited at `origin/main` e6ea9ca3 (2026-11-06). Source audit only; no VM was
booted.

## The rule

The base image (`os_image_hash`) should not change. Applications change in their
own OCI images and measured compose manifests, which are pinned per task and can
change without re-signing the Mac app or re-tagging the base. Code in the base
that names a provider, product, application or experiment breaks this rule, and
so does a large base subsystem with no design doc. The base keeps the guest's
own boundary: boot and verity, disk encryption, egress enforcement, attestation,
and admitting and launching one measured compose. Decision 0007 (branch
`docs/guest-network-visibility`, not on main) says the same thing: "Change the
base image only when the guest's own boundary must change."

The base changed eight times between 2026-10-25 and 2026-11-05 (`image.sha256`
at b69bf4db, c6bd160e, e6477533, a9856ec8, 7f6264b3, d20726f5, 545d7c98,
fa807bae).

## What is in the image

`derive.py` runs `derive-in-container.sh`, which does not build a rootfs. It
unpacks the B44 base (`derive-in-container.sh:6`; `os_image_hash` b44abf14…,
release `runner-v0.1.0-alpha.1`, 2026-10-23), rebuilds the kernel with dm-crypt
(lines 11-25), and overlays a list of files (lines 27-45):

- `supervisor-dstack-trixie.sh` → `/usr/bin/dsmack-supervisor`
- `nft`, `cryptsetup`, `mkfs.ext4` and their libraries from Debian snapshot debs
  (`builder/Dockerfile:20-24`)
- all of `source/guest/sentinel/` → `/usr/local/lib/dsmack/sentinel/`
- `dsmack_guest_io/{public_inputs,public_toc}.py`
- `dsmack_compose_contract/{manifest,lowering,egress,security}.py` and `browser-sandbox-v1.json`
- `dsmack_compose_runner/lifecycle.py`
- `dstack-compat/{agent,guest_attest,dsmack_dstack,secret_box}.py` → `/usr/local/lib/dsmack/dstack-agent/`

Every other file under `/usr/local/lib/dsmack` comes from B44 unchanged: the
rest of the runner (`runner.py`, `identity.py`, `workspace.py`, ...), the rest of
guest-io, the rest of the contract library, both `/usr/local/bin` wrappers,
`/usr/local/lib/dsmack/net/guest-network.env` and `/etc/docker/daemon.json`. B44
also supplies 128 Debian packages (docker.io, containerd, runc, python3.13,
iproute2, iptables, busybox-static, ...). It has no browser, no Node and no
gVisor. The recipe that built B44 (`source/build/BUILD.sh`, 719 lines) and its
provenance files (`SOURCE-ORIGIN.json`, `SOURCE-LOCK.json`) were deleted in
7bdebe27 (2026-10-24). The deleted `SOURCE-ORIGIN.json` says
`"reproducible_clean_build_claimed": false`.

The package list and the inherited file list above come from a locally staged
rootfs, `local-data/runner-release-alpha3-20261106/stage/base/`
(`os_image_hash` 8783a3be…). That hash is not any committed `image.sha256`
value, so it is corroboration only. I did not inspect B44 itself.

Three consequences:

1. **Repo source is not always what runs.** f28e58d1 (2026-10-25) changed
   `lowering.py` to rewrite image refs to `127.0.0.1:5005/<name>@<digest>` and
   `runner.py` to call `ensure_image(control, local_image_ref(pin), …)`.
   `lowering.py` is in the overlay list; `runner.py` is not. A derived image
   therefore carries the new `lowering.py` next to B44's `runner.py`, which
   predates the commit and calls `ensure_image(control, pin, …)`. The staged
   rootfs has exactly that older `runner.py`. Its
   `workspace.py` creates a `shared/` directory that the repo `workspace.py` has
   never had (last changed 3cb07a26). `image-repro` checks the output digest,
   not whether the image matches `source/`.
2. **Stale inventories.** Line 46 regenerates `compose-runner/SHA256SUMS` only.
   The overlay replaces files under `sentinel/` and `guest-io/` and leaves their
   inherited `SHA256SUMS` alone. In the staged rootfs, `sentinel/SHA256SUMS`
   fails `sha256sum -c` on 4 entries and `guest-io/SHA256SUMS` on
   `public_toc.py`.
3. **Unsourced config.** The supervisor sources `guest-network.env`
   (`supervisor-dstack-trixie.sh:146-151`), and `daemon.json` sets
   `insecure-registries: ["127.0.0.1:5005"]`. Neither file is in the repo. The
   staged copy of `guest-network.env` names the Zed and Mini NIC MACs and cites
   `loop40-native-nat-repair3/net-helper/GUEST-IMAGE-PROFILE-HANDOFF.md`, which
   does not exist.

Only `browser-sandbox-v1` exists under `base-vm/`. 7bdebe27 deleted
`broker-timeout-v1`, `browser-ffmpeg-v1` and `public-file-commitments-v1`. The
name comes from the seccomp preset. There is no browser in the image.

## Findings

Line counts are from `origin/main` source. Paths are relative to
`base-vm/browser-sandbox-v1/` unless they start with `dstack-compat/`,
`applications/` or `docs/`.

| Component | path:line | What it is | Belongs in base? | LoC | Proposed home |
| --- | --- | --- | --- | --- | --- |
| Credential sentinel (#103) | `derive-in-container.sh:31-33`; `source/guest/supervisor-dstack-trixie.sh:420-425` | Per-run HTTP proxy that holds a provider credential | No. `sentinel.py:174` sets `anthropic-version` on every forwarded request; `sentinel.py:375-388` names `claude-api-key/1` and `claude-subscription/1`; `sentinel.py:97` limits the CONNECT path to `api.anthropic.com` | 543 | Sentinel OCI image, digest-pinned in the app compose |
| Subscription OAuth refresh | `source/guest/sentinel/harness/sentinel/sentinel_oauth.py:119` | Claude subscription token refresh; hardcodes Claude Code's OAuth client id as `FALLBACK_CLIENT_ID` | No | 371 | Same sentinel image |
| `claudeAiOauth` validator | `source/guest/sentinel/harness/adapter/claude_subscription_document.py` | Validator for Claude Code's credential file format | No. A byte-identical copy is at `applications/pilot-client/workload/reference/claude_subscription_document.py` | 266 | Sentinel image; delete the base copy |
| Sentinel CONNECT branch | `sentinel.py:89-102` | Tunnels through `HTTPS_PROXY` | No. The supervisor never sets `HTTPS_PROXY`. The callers are `applications/agent-turns/find.py:180` and `applications/compute-node/workload.py:29`, both app containers. Added in 545d7c98 | 14 | Sentinel image |
| Broker launch in supervisor | `supervisor-dstack-trixie.sh:486-555, 618-628, 652-653` | Reads `credentials.adapter.profile` and maps `claude-subscription/1`/`claude-api-key/1` to sentinel modes (514-518); runs the sentinel as uid 1000 on `0.0.0.0:5100` | No | ~85 | Delete; the app compose starts the sentinel |
| Anthropic credential profiles | `source/runner-content/lib/dsmack_compose_contract/manifest.py:98-132, 1934-2033, 721-736` | `ADAPTER_PROFILES` with `provider_route: https://api.anthropic.com`, env names `ANTHROPIC_API_KEY` and `CLAUDE_SUBSCRIPTION_OAUTH`; D07 forces bridge networking because "the sentinel transport is bridge-only" | No. The header calls `claude-subscription/1` a "PROPOSED DELTA ... pending independent review" (104-105) | ~150 | Profiles become opaque, shape-checked strings; the meaning lives in the sentinel image |
| Anthropic client prose in lowering | `source/runner-content/lib/dsmack_compose_contract/lowering.py:255-345` | Rendered plan text that names "Anthropic SDK / Claude Code", `ANTHROPIC_BASE_URL` and `api.anthropic.com` URLs | No | ~90 | Delete; the sentinel image documents its own endpoint |
| `--broker-endpoint` | `source/runner-content/dsmack_compose_runner/cli.py:91-95, 156`; `runner.py:87-90, 211-218, 268, 290` | Passes the sentinel endpoint into the run | No, once the sentinel is a service | ~30 | Delete; services address the sentinel by service name |
| Verifier-only contract modules | `lib/dsmack_compose_contract/attestation.py`, `report_adapter.py`, `ed25519.py`, `schema_check.py`, `__main__.py` | App Attest report verification, verifier-report adapter, host CLI | No. No guest code path calls them; they load only through `__init__.py:17-29, 85-93, 107`. They exist for `applications/pilot-client/verifier-browser/runresult_ref/frozen.py:11-21` | 1915 | Stay in the repo, outside the guest install; split the package so the guest imports only what it runs |
| Transitional `docker load` | `supervisor-dstack-trixie.sh:404-415` | Loads `images/*.tar` without RepoDigest, "kept so the current Zed path still functions" | No. Self-described fallback | 12 | Delete; OCI layout is the only delivery |
| Scratch probe | `source/runner-content/dsmack_guest_io/scratch_probe.py:45-46`; supervisor 326-347 | Samples Docker scratch usage; refuses unless `/dev/vdb` is exactly 1 GiB ("selected Mini scratch capacity differs") | No. `README.md:38` says the scratch template is 4 GiB, so on that template the probe always raises and the supervisor prints `DSMACK_SCRATCH_STATS_UNAVAILABLE`. Not checked on a booted VM | 55 + 22 | Delete |
| gVisor runtimes | `manifest.py:81-92`; `source/runner-content/dsmack_compose_runner/identity.py:7, 86-92` | Registers `runsc` and `runsc-hostnet` | No. B44 has no `runsc` and `daemon.json` registers no runtime, so these manifests can only fail | 53 lines mention `runsc` | Delete until a base ships gVisor |
| `agent-sandbox-v1` preset | `lib/dsmack_compose_contract/security.py:8-9, 28-43`; `lowering.py:435-439`; `lifecycle.py:120, 146` | Runs the service as root with CHOWN/FOWNER/DAC_OVERRIDE/SETUID/SETGID/KILL and moves the dstack socket to `/root/dstack.sock` | No. Its one user is `applications/compute-node/workload.py:44`. Added in a23d26d8 | ~30 | Generic per-service security fields, checked against a fixed ceiling, declared in the compose |
| `browser-sandbox-v1` preset | `security.py:7, 14-25, 44-53, 56-98`; `browser-sandbox-v1.json` | Playwright seccomp policy pinned by size and digest; requires `network: none` and no broker | Mechanism yes, preset no. The base should enforce "this service runs with the seccomp file whose digest the manifest names", not ship one app's policy | 98 + 831 | Seccomp JSON delivered on vdc and named by digest in the manifest |
| `public_inputs.py` | `source/runner-content/dsmack_guest_io/public_inputs.py:1-4` | Public envelope channel "for credential-free browser-sandbox-v1 only" | The channel is generic; the browser-only restriction is not | 93 | Keep; drop the preset coupling |
| `update-runtime.{py,sh}` | `update-runtime.py`, `update-runtime.sh` (a23d26d8) | Second build path: keeps the prior kernel and overlays three files | No. `image-repro.yml` never runs it, so its outputs have no committed digest. `applications/compute-node/README.md:55` uses it | 46 | Delete; `derive.py` is the only path |
| Host-side packer | `source/smoke/launch_vm_dstack_arm64.py` | Workload-disk packer and QEMU launcher used by `applications/pilot-client/workload/transport_loader.py` | Not in the image; filed under `base-vm/` | 1821 | `tools/` or `applications/pilot-client/` |
| Host-side test | `source/tests/verify_manifest.py` | Host manifest check | Not in the image | 168 | Same |
| Product names in comments | supervisor 394-396 (`dsmack-claude-harness`); `oci_publish.py:3-4` and `dsmack_guest_io/__init__.py:22` (Zed, Mini); supervisor 133-144 | Comments | Comment only | — | Rewrite with the next base change |
| Inline network defaults | supervisor 147-151 | Hardcoded `192.168.127.2/24`, gw and DNS, overridden by `guest-network.env` "when present" | The values belong in base (gvproxy NAT). Two definitions do not | 5 | One source file in the repo; supervisor fails if absent |
| Canary guest key | supervisor 577 `--canary-key`; `dstack-compat/agent.py:162-167, 181-182` | P-256 key in guest-root tmpfs, published as the `canary-guest-key` event | Yes. It is a bounty for compromising this image's guest root (`docs/canary/CLAIMING.md:34`, `contracts/src/Canary.sol:24`), so it has to live in base | — | Keep |
| dstack guest API shim | `dstack-compat/agent.py`, `guest_attest.py`, `dsmack_dstack.py`, `secret_box.py` | `/v1/GetKey`, `/v1/Attest`, `/v1/GetSecret` on `/var/run/dstack.sock` | Yes. Attestation and key release are the guest's boundary (decision 0005, on branches only) | 597 | Keep; publish 0005 on main with a threat model |
| `harness` manifest field | `manifest.py:165, 1218-1371`; `identity.py:281-357` | Pins one file inside the image by path and sha256 and requires `entrypoint[0]` to equal it | Generic in effect, product-named. The image digest already measures those bytes | ~230 | Keep for manifest v4. Rename or drop in the next manifest version |
| Supervisor core | supervisor 1-418, 560-617, 629-783 minus rows above | Mounts, dm-crypt scratch, vdc admission, boot observation, OCI publisher, egress, runner loop, boundary probe, closure | Yes | ~600 | Keep |
| Compose runner, guest-io, remaining contract | `dsmack_compose_runner/`, `dsmack_guest_io/`, `manifest.py`, `lowering.py`, `receipt.py`, `image_admission.py`, `runtime_inputs.py`, `canonical.py`, `oci_index.py`, `egress.py`, `errors.py` | Admission, lowering, launch, receipts, private transport | Yes. Large: `manifest.py` 2059, `receipt.py` 1522 | ~11,000 | Keep; size is a separate question |
| Boot | `source/guest/init-dstack-arm64.sh`, `source/profile/.../kernel-cmdline.sh`, `source/build/assemble_leg.sh` | Initramfs verity boot, cmdline, image assembly | Yes | 289 | Keep |

## When each piece entered

- Sentinel: already in the B44 rootfs before this repo existed. Its source was
  published at 98c13eab (2026-10-25), "from the 0.7.1.broker-timeout-v1
  rootfs"; derive began installing it from the repo at 545d7c98 (2026-10-28),
  which also modified `sentinel.py`.
- Sentinel CONNECT branch: in the base copy since 545d7c98. The error string
  first appears in 0feb6994 (2026-10-27).
- dstack agent install: 45878762 (2026-10-25). Canary key: 597f76c5
  (2026-10-25). `secret_box.py` and `--secret-key`: c6bd160e (2026-10-25).
- `agent-sandbox-v1` and `update-runtime.{py,sh}`: a23d26d8 (2026-10-30).
- nft, cryptsetup, the kernel rebuild and the egress overlay: 545d7c98.
- Scratch probe, transitional `docker load`, `ADAPTER_PROFILES`, `runsc`,
  `harness`, the Anthropic prose in lowering, and the verifier modules: all
  arrived in the 3cb07a26 import (2026-10-23) as "selected" source. The deleted
  `SOURCE-ORIGIN.json` (7bdebe27^) gives their origin as
  `dstack-runner-join/source/` and `provenance/IMAGE7-SOURCE-INVENTORY.json`,
  neither of which is in the repo.

## Missing design docs

Searched `origin/main`, all branches of `private` (fetched to
`refs/audit-private/*`), all branches of `local-store`, every path in
`git log --all`, and `find /home/amiller` by filename.

| Referenced doc | Cited from | Found |
| --- | --- | --- |
| `contract10/candidate/interfaces/compose-runner-interface.md` (D07, "FROZEN") | `sentinel.py:4-6`, `sentinel_oauth.py:5-6`, `manifest.py` | Nowhere. No path containing `contract10` exists in any ref. `BUILD.sh` at 7bdebe27^:612-618 refers to `$CAND/contract10-candidate` on a build host |
| `claude-adapter-interface.md` | `sentinel.py:6`, `sentinel_oauth.py:6` | Nowhere |
| `interfaces/mac-attestation-interface.md` | `attestation.py` (3 times) | Nowhere |
| `interfaces/base-vm-handoff.md` | contract library | Nowhere |
| `../../integration/claude-subscription-1.patch` | `sentinel_oauth.py:9` | Nowhere |
| `../research/claude-2.1.187-subscription-auth-evidence.md` | `claude_subscription_document.py:8-9` | Nowhere |
| `adapter/claude_subscription_importer.py` | `claude_subscription_document.py:4` | Nowhere |
| `GUEST-IMAGE-PROFILE-HANDOFF.md`, `NATIVE-NETWORK-INTEGRATION(.json)` | `guest-network.env` (B44), supervisor 172, `oci_publish.py:3` | Nowhere |
| `trusted-verifier-inputs/verifier/core.py` | `report_adapter.py:6` | Nowhere under that path |
| `dstack-runner-join/source/build/BUILD-DELIVERY.md` | runner comments | Added 22ec953b/a4bc7388 (2026-10-22), deleted 7bdebe27; still on local branches such as `review/primary-worker-20261022` |
| `docs/decisions/0005-dstack-guest-api.md`, `0007-guest-network-visibility.md` | issue #83 | Local branches only (`couch-browse`, `docs/guest-network-visibility`), not main |
| `docs/guest-api-v1.md` | `dstack-compat` | Upstream dstack (`~/installing/dstack/docs/guest-api-v1.md`); not a gap |

The code also cites roughly 70 requirement IDs that resolve to none of these
docs: R01-R09, S01-S07, D01-D11, C01-C10, E01-E10, F01-F11, GIO01-GIO11,
T02-T05, U01-U03, plus "astra" (17 times), "contract3" and "contract4". The
most cited are R01 (23), GIO03 (19), S04 (19), R06 (18) and GIO01 (18).

`docs/architecture.md:29-30` says the base "supplies ... the credential broker".
`SECURITY.md` is 12 lines. No doc on main gives a threat model for the
supervisor, the sentinel, the dstack agent or the egress rules.

## Remediation plan

Steps 1-5 each yield a new `os_image_hash`. Old images stay valid for manifests
that pin them: manifests name `base_vm.os_image_hash` (`manifest.py:10-13`) and
the signed release inventory admits images (`docs/versioning.md:13`), so the app
can admit old and new bases side by side. No step changes an existing image, and
no new image keeps an old code path for compatibility. Tasks move by being
repinned, with the cost #101 describes (repack, new class, broker redeploy).

**1. Make the image match the repo.** Change `derive-in-container.sh` to install
the whole `source/runner-content` tree, both `bin/` wrappers (add
`dsmack-guest-io` to the repo), and the B44 `guest-network.env` and
`daemon.json`, now committed under `source/`. Delete every `SHA256SUMS`; verity
already covers those bytes. Delete `update-runtime.{py,sh}`.
The base keeps what it has today, with every byte under `/usr/local/lib/dsmack`
now built from the repo.
*Check:* a test unpacks the derived rootfs and asserts that every file under
`/usr/local/lib/dsmack`, `/usr/bin/dsmack-supervisor`, `/etc/docker/daemon.json`
and `/usr/local/bin/dsmack-*` is byte-equal to a repo file, and that no
`SHA256SUMS` file remains. `image-repro` runs it.

**2. Stop shipping verifier code in the guest.** Split `dsmack_compose_contract`
into a guest part (manifest, lowering, egress, security, runtime_inputs,
receipt production, image_admission, canonical, oci_index, errors) and a
verifier part (attestation, report_adapter, ed25519, schema_check, CLI). Move
the library out of `base-vm/` into a top-level package. The guest installs the
guest part; `applications/pilot-client` imports both. The base keeps manifest
validation, lowering and receipt writing.
*Check:* `python3 -I -c 'import dsmack_compose_contract'` with the guest
install's `PYTHONPATH` loads no verifier module, and no verifier module appears
in the rootfs listing.

**3. Delete dead and transitional paths.** Supervisor 404-415 (`docker load`),
the scratch probe, the `runsc` runtimes, the inline network defaults at
supervisor 147, and the product names in comments. The base keeps OCI-layout
delivery and one network declaration file.
*Check:* `grep -nE 'TRANSITIONAL|scratch_probe|runsc|Zed|Mini|claude' ` over the
installed tree returns nothing; the existing pytest suite and an `image-repro`
run pass.

**4. Move the sentinel into the app (#103).** Build a sentinel OCI image from
`source/guest/sentinel` plus `claude_subscription_document.py`, and pin it by
digest in the agent-turns and compute-node composes as a service.
`applications/agent-turns/compose-private.yml:3-11` already runs it that way on
a plain Docker host, but it bind-mounts `${SENTINEL_SOURCE}`, a host path, and
uses top-level `networks`, `user` and `depends_on`. The compose subset accepts
none of those (`manifest.py:147-158` allows only top-level `services` and nine
service keys). The base then needs two generic mechanisms it lacks today:
- deliver a private input to one declared service. The `broker` audience in
  `runtime_inputs` and the `/run/dsmack` bind (`manifest.py:67`,
  `lowering.py:441-445`) already cover most of this;
- per-service egress, so only the sentinel service reaches the provider (#76,
  #78). Without it, moving the sentinel would let the agent container reach
  `api.anthropic.com` directly.

Then delete from the base: `source/guest/sentinel/`, `derive-in-container.sh:31-33`,
supervisor 420-425, 486-555, 618-628 and 652-653, `--broker-endpoint`,
`ADAPTER_PROFILES` and the Claude branches in `manifest.py`, the D07 bridge-only
rule, and `lowering.py:255-345`. `credentials.adapter.profile` and
`provider_route` stay in manifest v4 as opaque strings checked for shape only,
so old manifests still parse in the verifier. A v4 manifest that sets
`credentials.required` is refused by the new base with a named error. It keeps
running on the old base it pins. The base keeps "deliver a private input to a
declared service" and "enforce per-service egress".
*Check:* `grep -rniE 'anthropic|claude|oauth' ` over the derived rootfs
`/usr/local/lib/dsmack` and `/usr/bin/dsmack-supervisor` returns nothing, and an
agent-turns run on the new base gets its provider responses through the
sentinel service while a probe from the agent service to the provider IP fails.

**5. Replace named presets with declared fields.** Remove `browser-sandbox-v1`
and `agent-sandbox-v1` from `security.py`. The manifest names, per service, a
seccomp file by sha256 (carried on vdc under a new public channel), plus
`cap_add`, `user`, `tmpfs` and limits. The base checks these against one fixed
ceiling (for example: no `privileged`, no `SYS_ADMIN`, read-only root) and
applies them. Move the Playwright policy and its license to the browser checker
application. The base keeps the ceiling and the digest check.
*Check:* no file under `base-vm/` contains `browser-sandbox` or `agent-sandbox`
except the image directory name. The browser checker and compute-node manifests
validate and run with the declared fields.

**6. Move host tools out of `base-vm/`.** Move
`source/smoke/launch_vm_dstack_arm64.py` and `source/tests/verify_manifest.py`
to `tools/` or `applications/pilot-client/`. No image change.
*Check:* every file under `base-vm/` is either installed by
`derive-in-container.sh` or a build or test input for it.

**7. Write the base design doc.** One `base-vm/browser-sandbox-v1/DESIGN.md`
that lists each installed component, the supervisor's fail codes, the disk
channels, the dstack agent's ctl protocol, the egress model and the threat
model. Merge decisions 0005 and 0007 to main. Remove requirement IDs that
resolve to nothing, or define the ones worth keeping in DESIGN.md. Rename the
image directory, since nothing in it is browser-specific after step 5.
*Check:* every `.md` path and requirement ID cited from an installed file
resolves to a file on main.

Steps 1, 2 and 3 can ship as one base change. Step 4 depends on per-service
egress. Step 5 changes the manifest format and belongs with the next manifest
version (#39).

## Audit surface

Lines a reviewer reads to know what the base runs, counted from repo source:

| | Today | After steps 1-6 |
| --- | ---: | ---: |
| Build recipe (`derive*`, `Dockerfile`, `assemble_leg.sh`) | 263 | ~250 |
| Boot (`init`, `kernel-cmdline.sh`) | 125 | 125 |
| Supervisor | 783 | ~660 |
| Compose runner + wrappers | 2,914 | ~2,850 |
| Guest-io | 1,568 | ~1,510 |
| Contract library (Python) | 8,717 | ~6,550 |
| Seccomp preset JSON | 831 | 0 |
| Sentinel | 1,180 | 0 |
| dstack agent | 597 | 597 |
| **Total** | **~16,980** | **~12,540** |

The "today" column understates the work. A reviewer reading `source/` today
reads some files that are not the bytes in the image (consequence 1). The image
also contains about 30 lines of config that are in no repo file, plus a B44
rootfs whose recipe was deleted. After step 1 the column describes the image
exactly. The remaining 12.5k lines are mostly the compose contract
(`manifest.py`, `receipt.py`, `image_admission.py`, `runtime_inputs.py`,
`lowering.py`). Most of it is generic, and reducing its size would be a separate
proposal. Rebuilding B44's 128 Debian packages from a committed recipe is also
out of scope here.

## Not verified

- B44's contents. I did not download the bundle. Statements about what B44
  carries come from `derive-in-container.sh` and from the staged rootfs
  (8783a3be…), which matches no committed `image.sha256`.
- Which commit or branch produced the staged rootfs.
- Whether a23d26d8 (2026-10-30), which changed `security.py`, `lowering.py` and
  `lifecycle.py` (all installed by derive), was built before `image.sha256`
  moved to eb2b54ce in fa807bae. No `image.sha256` change falls between
  545d7c98 and fa807bae.
- Whether a run on an image derived from main succeeds with B44's `runner.py`
  and the f28e58d1 `lowering.py` disagreeing about image refs.
- The scratch probe failing on 4 GiB scratch. This is inferred from
  `scratch_probe.py:45-46` and `README.md:38`, not observed.
- Whether the `contract10` documents exist on a build host. They are not on this
  laptop, in either remote, or in git history.
