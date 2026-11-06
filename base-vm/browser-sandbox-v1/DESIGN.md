# browser-sandbox-v1 base: design

This describes the base image as it is on branch `base-vm-remediation` at
47780d72. Every claim cites a file and line at that commit. Paths starting
with `source/`, `install-guest.sh`, `derive*`, `check_rootfs.py` or `builder/`
are relative to this directory; all others are from the repo root.
"supervisor:N" means `source/guest/supervisor-dstack-trixie.sh` line N.

## 1. What the base is for

The base is the layer the signed Mac app boots for every task. It boots a
verity-checked root, encrypts Docker scratch with a per-boot key, configures
the guest network and enforces the manifest's egress list, attests through
the app over the `dsmack-ctl` port, and runs exactly one measured compose
manifest with the compose runner, writing receipts and outputs to the result
disk. Its identity is `os_image_hash`, the sha256 of `sha256sum.txt` over the
kernel, initramfs, `metadata.json` and the verity root
(`source/build/assemble_leg.sh:125-127`).

Applications, providers and products do not belong in it. They change in
their own OCI images and manifests, pinned per task, without a new base or a
re-signed app ([docs/versioning.md](../../docs/versioning.md), lines 3-6 and
10-17). Decision 0007 states the rule for base changes: "Change the base image
only when the guest's own boundary must change" (0007:173-175, on branch
`docs/guest-network-visibility`, b8d6ae86; not on this branch). Two things in
the image today break that rule and are slated to move (section 2).

The image has no browser. The name comes from the seccomp preset
(`compose-contract/dsmack_compose_contract/security.py:7`).

## 2. Installed components

`derive-in-container.sh` unpacks the B44 rootfs (line 6), rebuilds the kernel
(lines 10-24), installs four binaries and their libraries (lines 26-30), runs
`install-guest.sh` (line 31) and assembles the image (line 32).
`install-guest.sh:8` deletes `/usr/local/lib/dsmack` and `/usr/local/bin/dsmack-*`
before copying, so nothing under those paths survives from B44. `__pycache__`
is excluded (`install-guest.sh:7`). Directories are mode 0755 and files 0644
(`install-guest.sh:7`) except the wrappers and the supervisor (0755,
`install-guest.sh:16-17`).

`L` below is `/usr/local/lib/dsmack` (`install-guest.sh:6`).

### Repo files installed into the rootfs (`install-guest.sh`)

| Installed path | Repo source | What it does | Invoked by | Lines |
| --- | --- | --- | --- | ---: |
| `/usr/bin/dsmack-supervisor` | `source/guest/supervisor-dstack-trixie.sh` | PID 1 after `switch_root`; whole boot-to-poweroff sequence (section 3) | `source/guest/init-dstack-arm64.sh:80` | 740 |
| `/usr/local/bin/dsmack-compose-runner` | `source/runner-content/bin/dsmack-compose-runner` | Sets `sys.path` to `L/compose-runner{,/lib}` and calls the runner CLI | supervisor:183, 550, 565, 598 | 5 |
| `/usr/local/bin/dsmack-guest-io` | `source/runner-content/bin/dsmack-guest-io` | Sets `sys.path` to `L/guest-io` and calls the guest-io CLI | supervisor:225, 291, 330, 335, 435 | 5 |
| `L/compose-runner/dsmack_compose_runner/cli.py` | `source/runner-content/...` | Subcommands `validate`, `validate-inputs`, `hash`, `run` (`cli.py:124-137`) | wrapper above | 196 |
| `.../runner.py` | same | validate, admit, lower, resolve, deliver, execute, collect, receipt, cleanup (`runner.py:1-2`) | `cli.py` | 652 |
| `.../control.py` | same | The only path from the runner to Docker (`control.py:1`) | `runner.py`, `lifecycle.py` | 279 |
| `.../lifecycle.py` | same | Compose start, wait, stop, inspect, collect, down (`lifecycle.py:1`) | `runner.py` | 541 |
| `.../identity.py` | same | Resolves image digests and the `harness` pin against the live daemon | `runner.py`; `dsmack_guest_io/oci_identity.py` | 348 |
| `.../workspace.py` | same | Per-run workspace under `/run/dsmack-runs` | `runner.py` | 208 |
| `.../receipting.py` | same | Builds and self-validates `receipt.json` (`receipting.py:1-4`) | `runner.py` | 278 |
| `.../export_outputs.py` | same | Writes the `<name>/outputs/` tree and the `EXPORT-COMPLETE` marker on the result disk | `runner.py` | 334 |
| `.../errors.py`, `__init__.py`, `__main__.py` | same | Error types, package, `python -m` entry | runner modules | 19, 20, 8 |
| `L/compose-runner/lib/dsmack_compose_contract/manifest.py` | `compose-contract/dsmack_compose_contract/` | Validates `dsmack.app-compose/4` manifests; compose subset is nine service keys (`manifest.py:139-149`) | runner; `egress.py`; `public_inputs.py` | 1889 |
| `.../lowering.py` | same | Manifest to Docker Compose; also renders the nft egress table (`lowering.py:480-505`) | runner; `egress.py` | 739 |
| `.../egress.py` | same | Validates the manifest and pipes the rendered table to `/usr/sbin/nft -f -` (`egress.py:10-13`) | supervisor:556 | 17 |
| `.../security.py` | same | Presets `browser-sandbox-v1` and `agent-sandbox-v1` (`security.py:7-8, 32-53`) | `lowering.py` | 98 |
| `.../browser-sandbox-v1.json` | same | Playwright seccomp policy, pinned by size 12997 and sha256 (`security.py:10-23`) | dockerd via `seccomp:` option (`security.py:48`) | 831 |
| `.../runtime_inputs.py` | same | Validates runtime-input envelopes | runner `validate-inputs`; `public_inputs.py:78` | 751 |
| `.../image_admission.py` | same | External image admission and boot identity (`image_admission.py:1`) | runner | 924 |
| `.../receipt.py` | same | Validates `dsmack.receipt/4` (`receipt.py:1`) | `receipting.py` | 1522 |
| `.../canonical.py`, `oci_index.py`, `errors.py`, `__init__.py` | same | Strict JSON and hashing; OCI index membership; errors; package | contract modules | 226, 165, 103, 136 |
| `L/guest-io/dsmack_guest_io/cli.py` | `source/runner-content/dsmack_guest_io/` | Subcommands `extract-private`, `verify-private`, `admit-public-toc`, `boot-observe` (`cli.py:113-127`), plus `oci-verify`, `oci-serve` (`cli.py:143-144`, `oci_publish.py:301-305`) | wrapper above | 167 |
| `.../public_toc.py` | same | Admits the vdc tar from its headers before extraction (`public_toc.py:1-19`) | supervisor:225 | 112 |
| `.../private_transport.py`, `pt_limits.py` | same | Bounded ustar parser for vde; extracts into a fresh 0700 tree with 0600 files (`private_transport.py:1-35`) | supervisor:435 | 453, 59 |
| `.../public_inputs.py` | same | Picks the public envelope for a manifest, refusing unless every service uses `browser-sandbox-v1`, network `none` and no credentials (`public_inputs.py:65-73`) | supervisor:562 | 93 |
| `.../boot_observe.py` | same | Records admitted boot claims, checks live cmdline and verity table (`boot_observe.py:1-7`) | supervisor:291 | 156 |
| `.../oci_publish.py` | same | Verifies an OCI layout and serves it read-only on loopback | supervisor:330, 335 | 310 |
| `.../oci_identity.py` | same | Runs the runner's image resolver on one ref | supervisor:357 | 16 |
| `.../closure.py` | same | Per-attempt result closure: `prepare`, `collect`, `close` (`closure.py:90-108`) | supervisor:270, 547, 634, 731 | 116 |
| `.../__init__.py` | same | Package | | 30 |
| `L/dstack-agent/agent.py` | `dstack-compat/agent.py` | dstack guest API shim and ctl client (section 5) | supervisor:535 | 187 |
| `L/dstack-agent/guest_attest.py` | `dstack-compat/guest_attest.py` | Event log, client data, attestation encoding, P-256 | `agent.py:28` | 156 |
| `L/dstack-agent/dsmack_dstack.py` | `dstack-compat/dsmack_dstack.py` | dstack v1 KDF and worker-grant chain for `GetKey` | `agent.py:100`, only with a grant | 201 |
| `L/dstack-agent/secret_box.py` | `dstack-compat/secret_box.py` | Opens a task secret sealed to the agent's `secret-key` | `agent.py:96` | 53 |
| `L/net/guest-network.env` | `source/profile/dstack-trixie-arm64-minimal/guest-network.env` | `eth0`, `192.168.127.2/24`, gateway and DNS `192.168.127.1` | sourced at supervisor:138 | 6 |
| `/etc/docker/daemon.json` | `source/profile/dstack-trixie-arm64-minimal/docker-daemon.json` | json-file logs; `insecure-registries: ["127.0.0.1:5005"]` for the loopback publisher | dockerd (supervisor:189) | 5 |
| `L/sentinel/harness/sentinel/sentinel.py` | `source/guest/sentinel/` | **Slated to move (#103, needs #78).** Per-run credential proxy; CONNECT path limited to `api.anthropic.com` (`sentinel.py:97`) | supervisor:484 | 543 |
| `L/sentinel/harness/sentinel/sentinel_oauth.py` | same | **Slated to move.** Claude subscription OAuth refresh; hardcodes `FALLBACK_CLIENT_ID` (`sentinel_oauth.py:119`) | `sentinel.py` | 371 |
| `L/sentinel/harness/adapter/claude_subscription_document.py` | same | **Slated to move.** Parser for the `claudeAiOauth` credential document | `sentinel_oauth.py:93-95` | 266 |
| `L/sentinel/.../__init__.py` (3 files) | same | Packages | | 0 |

The Claude adapter profiles are not separate files. They live in installed
files that otherwise belong in the base, and are slated to move with the
sentinel:

- `ADAPTER_PROFILES` with `claude-api-key/1` and `claude-subscription/1`, both
  with `provider_route: https://api.anthropic.com`
  (`compose-contract/dsmack_compose_contract/manifest.py:89-123`), and the D07
  bridge-only rule (`manifest.py:21-23, 712`);
- the client configuration prose naming the Anthropic SDK and
  `api.anthropic.com` (`lowering.py:264-300`);
- the supervisor's broker launch, which maps those two profile names to
  sentinel modes (supervisor:444-513, 576-586, 611);
- `--broker-endpoint` (`dsmack_compose_runner/cli.py:91-95, 156`).

`docs/architecture.md:28-30` says the base "supplies ... the credential
broker". That is true at this commit and stops being true after #103.

### Installed by `derive-in-container.sh`, not from repo files

| Installed path | Source | Lines |
| --- | --- | --- |
| Kernel `Image`, `/usr/lib/modules/6.18.40-dstack` | Linux 6.18.40 tarball (sha256 checked at line 10) with B44's config plus `DM_CRYPT` and `CRYPTO_XTS` (lines 13, 18-24) | 10-24 |
| `/usr/sbin/mkfs.ext4`, `/etc/mke2fs.conf`, `/usr/sbin/cryptsetup`, `/usr/sbin/nft` | arm64 debs from the Debian snapshot 20260721T000000Z (`builder/Dockerfile:2, 18-24`) | 26-29 |
| every `*.so*` of those debs, over `/usr/lib/aarch64-linux-gnu/` | same | 30 |

### In the initramfs (`source/build/assemble_leg.sh:53-90`)

`/init` is `source/guest/init-dstack-arm64.sh` (81 lines, `assemble_leg.sh:86`),
plus busybox and `veritysetup` with its libraries copied from the rootfs, and
`sha256.ko` (`assemble_leg.sh:55-85`). `source/profile/.../kernel-cmdline.sh`
(44 lines) runs at build time only (`assemble_leg.sh:103-105`); its output is
baked into `metadata.json` (`assemble_leg.sh:108-121`).

### Everything else comes from B44

The rest of the rootfs, including Docker, containerd, runc, Python 3 and
busybox, is B44's. The audit counted 128 Debian packages from a staged rootfs,
not from B44 itself (`docs/base-vm-audit-2026-11.md:41-52`).
`assemble_leg.sh:160-161` writes the package list of each derived build to
`guest-packages.txt`.

## 3. Boot and run sequence

**Initramfs** (`source/guest/init-dstack-arm64.sh`). Mounts proc, sys, a 3 GiB
`/run` tmpfs (line 28; the header comment at line 12 still says 512 MiB) and
devtmpfs. Reads `dstack.rootfs_hash`, `dstack.rootfs_size` and
`dstack.rootfs_device` from the cmdline and stops if any is missing (lines
37-48). Loads `sha256.ko` if needed (61-68), opens the root with `veritysetup
... --panic-on-corruption` (70-71), mounts it read-only, moves the mounts and
`switch_root`s to `/usr/bin/dsmack-supervisor` (72-80). Any failure here exits
`/init` with a `FATAL` line (line 23), which panics the kernel.

**Supervisor.** All stderr goes to `/run/dsmack-supervisor.stderr` (49);
console lines from the shell are escaped (37). `fail N` prints
`DSMACK_SUPERVISOR_FAIL N`, stops the OCI publisher and sentinel, removes the
private tree, and powers off (58-65). In order:

| Step | Lines | Fail code: meaning |
| --- | --- | --- |
| Mount proc, sys, dev, devpts, `/dev/shm`, cgroup2 | 74-82 | 1-6: that mount failed |
| Enable cgroup controllers; require cpu, memory, pids | 90-97 | 19: a required controller is not enabled |
| dm-crypt vdb with a fresh key from `/dev/random`, mkfs, mount on `/var/lib/docker`; write `/run/dsmack/scratch-info` | 100-115 | 7: open, mkfs, mount or status failed |
| Mount vdd ext4 on `/run/export` | 122-125 | 8: result disk mount failed |
| Source `guest-network.env`; set address, link, default route; bind `/run/resolv-guest.conf` over `/etc/resolv.conf` | 136-162 | 9: profile missing, interface absent, or address/route not present after configuration |
| Check tools | 169-184 | 10 dockerd, 11 docker, 12 compose, 13 runc, 14 containerd, 17 python3, 18 runner CLI: not runnable |
| Start dockerd on `/run/rootcontrol/docker.sock` (dir 0700), wait up to 180 s | 166-203 | 15: not ready in time; 16: `docker version` failed |
| `cd /run/appcompose` | 209-211 | 20 |
| Admit the vdc tar from its headers, then extract | 224-227 | 25: admission refused; 21: extraction failed |
| Check vdc `SHA256SUMS` | 228-229 | 22: missing; 23: mismatch |
| Refuse `envelopes/` or `broker/` on vdc, any symlink or special file, any top-level entry outside the allowlist | 237-266 | 25 |
| `closure prepare` from `closure-context/context.json` | 269-270 | 30: context invalid or does not name exactly the vdc manifests (`closure.py:32-46`) |
| Capture `/proc/cmdline`, `dmsetup table --target verity`, `dmsetup info`; `boot-observe` against `base-bundle` | 279-302 | 29: dmsetup failed or observation refused |
| `oci-verify` the vdc OCI layout, start `oci-serve` on `127.0.0.1:5005`, pull every ref by digest and check the RepoDigest | 313-373 | 26: layout refused or publisher not ready; 24: no layout, a pull failed, the RepoDigest was not preserved, or the resolver failed (the subshell `exit 24` at 351-357 becomes `fail 24` at 359) |
| Extract vde, if present, into `/run/dsmack-private` | 433-440 | 28: vde present but refused |
| Find the `dsmack-ctl` virtio port | 525-527 | 31: no such port |
| Require exactly one `manifests/*.app-compose.json`; hash it | 530-532 | 35 |
| Collect service names from the compose | 533 | 32: manifest unreadable |
| Start the dstack agent; wait up to 30 s for `/run/dsmack-agent/sealed` | 534-542 | 33: agent exited or did not seal (including `DSMACK_MANIFEST_MISMATCH`) |
| Per manifest: check selector name | 544-547 | 27: no manifest; 30: bad name |
| `runner validate` | 550-553 | none: rc≠0 latches a failure and skips this manifest |
| Apply egress | 556-557 | 34: nft transaction failed |
| Pick the public or private envelope; `validate-inputs` | 562-575 | 28: `public_inputs` refused; validate rc≠0 latches and skips |
| Start the sentinel if `credentials.required` | 577-586 | none: start failure is printed and the runner then fails for lack of a broker |
| `runner run` | 598-613 | none: rc≠0 latches |
| `nft list table inet dsmack_egress` into diagnostics | 614 | 34: table gone |
| Check `EXPORT-COMPLETE` bytes; `closure collect` | 627-641 | none: missing marker or collect failure latches |
| No manifest ran | 643 | 27 |
| Stop the OCI publisher | 650 | none |
| Boundary probe: a `--network none` container from a digest-pinned local image checks that `/run/rootcontrol/docker.sock` is not visible | 660-697 | none: prints `DSMACK_BOUNDARY_OK_verified` or a `DSMACK_BOUNDARY_FAIL_*` line; does not latch |
| Remove private tree and diagnostics; stop publisher and sentinel | 710-718 | none: a residue latches |
| If nothing latched: `closure close` syncs, unmounts vdd, prints one `DSMACK_RESULT_CLOSED_V1 <json>` line | 729-734 | none: close failure prints `DSMACK_EXPORT_CLOSURE_FAIL` and powers off |
| Otherwise print `DSMACK_EXPORT_CLOSURE_REFUSED` | 735-737 | |
| Power off | 738-739 | 99 at line 740 is unreachable after `exec` |

"Latch" means `runner_rc_total=1`, which makes the supervisor skip
`closure close` (730). The closure line is the only success signal: it lists,
per manifest, the run id and the sha256 of `receipt.json` and `outputs/index.json`
(`closure.py:48-62, 64-71`).

`fail()` replaces the shell with `poweroff`, so the EXIT trap at 432 does not
run on that path; `fail()` calls the same three cleanups itself (60-62).

The per-manifest loop at 544 runs once, because 531 requires exactly one
manifest. The closure context allows up to 32 selectors
(`closure.py:40`).

## 4. Disk channels

| Device | Carries | Measured by | Guest handling |
| --- | --- | --- | --- |
| vda | squashfs root plus verity hash tree | `os_image_hash` (verity root hash on the cmdline in `metadata.json`) | `veritysetup open` in `/init` |
| vdb | Docker state | nothing; contents are discarded each boot | plain dm-crypt `aes-xts-plain64`, 512-bit key read from `/dev/random`, never on argv or disk; fresh ext4 (supervisor:105-108). The 4 GiB template's sha256 is bound into the cmdline (`kernel-cmdline.sh:37-42`), but the guest overwrites it |
| vdc | Public workload: an uncompressed tar at offset 0 (supervisor:205) with `manifests/`, `admission/`, `base-bundle/`, `images/`, `commitments/`, `oci-layout/`, `closure-context/`, `public-inputs/`, `WORKLOAD`, `SHA256SUMS` (`public_toc.py:25-28`) | see below | header admission, extraction to `/run/appcompose`, self-check, channel allowlist (supervisor:224-266) |
| vdd | Result: `<name>/receipt.json`, `<name>/outputs/{index.json, streams/, artifacts/, EXPORT-COMPLETE}` (supervisor:588-597) | the 256 MiB template's sha256 is bound into the cmdline (`kernel-cmdline.sh:37-42`) | mounted at `/run/export`; the exporter is its only writer (supervisor:594-597); unmounted by `closure close` |
| vde | Optional private inputs: runtime envelopes and the per-run broker channel, as a bounded ustar (`private_transport.py:1-9`) | nothing; kept out of every measured hash on purpose (`private_transport.py:7-8`) | parsed and extracted to a 0700 tree; removed with an absence check before poweroff (supervisor:418-428, 710) |

vdc's own `SHA256SUMS` (supervisor:228-229) only shows the tar is internally
consistent; whoever packs vdc also writes it. What ties vdc to the attested
task is this chain:

1. The app's `hello` reply names `manifest_sha256`; the agent exits with
   `DSMACK_MANIFEST_MISMATCH` unless it equals the sha256 of the one vdc
   manifest (`dstack-compat/agent.py:141-143`; supervisor:530-535). The
   supervisor runs that same file (supervisor:544).
2. The manifest pins image digests; the supervisor pulls each OCI ref by digest
   and checks the RepoDigest (supervisor:346-359).
3. A public envelope must name the manifest's sha256
   (`public_inputs.py:76-78` and `runtime_inputs.py`).

`base-bundle/` and `admission/` on vdc are host-supplied claims about the boot.
`boot_observe` records them as claims and checks only the live cmdline and
verity table against them (`boot_observe.py:1-7`; supervisor:273-278).

Diagnostics stay off vdd: runner and sentinel output go to `/run/dsmack-diag`
(supervisor:386-393), other diagnostics to `/run/dsmack-diagnostics` (39), and
the dockerd console to `/run/rootcontrol` (189-192, 720-722). All are tmpfs.

`docs/architecture.md:40-44` lists the same five devices.

## 5. The dstack agent

The supervisor starts `agent.py` before any workload container exists, with
`--ctl` (the `dsmack-ctl` virtio port), `--dir /run/dsmack-agent`,
`--canary-key /run/rootcontrol/canary-guest.key`, `--secret-key`,
`--manifest-sha256`, one `services=<hex>` event and the service names
(supervisor:535). It never passes `--grant`.

**ctl protocol.** Frames are `uint32_be(len) || JSON`, at most 4096 bytes, one
request in flight; a reply with an `error` key raises (`agent.py:30-69`). The
agent sends, in order (`agent.py:141-149`):

1. `{"op":"hello"}`. The reply carries `manifest_sha256`, `run`,
   `os_image_hash` and optionally `grant` (`agent.py:76-77, 142-144`).
2. `{"op":"grant"}`, only if `hello` offered one. The reply is
   `{"grant", "root_key"}` (`agent.py:101`).
3. `{"op":"event","name":N,"payload":hex}` for each system event: `services`,
   `canary-guest-key` (public half of a P-256 key whose scalar is written 0600
   to the 0700 `/run/rootcontrol`, `agent.py:162-167`), and `secret-key`
   (public half of a P-256 key held only in the agent's memory,
   `agent.py:183-185`).
4. `{"op":"seal"}`, then the agent creates `/run/dsmack-agent/sealed`.

After that the only ctl call is `{"op":"attest","caller":hex,"report_data":hex}`
(`agent.py:89`). That the app answers nothing else after the seal is stated in
`dstack-compat/README.md:27`; it is enforced in the app, not in this tree.

**Sockets.** One HTTP server per service at `/run/dsmack-agent/<service>.sock`,
mode 0666 (`agent.py:152-157`). Lowering binds a service's own socket to its
`/var/run/dstack.sock` only if the compose declares that volume
(`lowering.py:434-439`); `agent-sandbox-v1` gets it at `/root/dstack.sock`
instead (`security.py:9`). The caller tag is `sha256(service name)` of the
socket that accepted the call (`agent.py:155`). Caller identity therefore rests
on each container seeing only its own socket, not on socket permissions.

**Methods** (`agent.py:72-103`):

- `/v1/Info`, `/v1/Version`: always.
- `/v1/Attest {report_data}`: with `--ctl`. `report_data` is at most 64 bytes,
  zero-padded to 64 (`agent.py:84-88`). The agent forwards it with the caller
  tag; the app returns an App Attest `key_id`, `assertion` and the event list.
  The agent wraps them as a dstack `VersionedAttestation` with
  `platform.kind = "apple-app-attest"` and `stack.kind = "dsmack"`
  (`guest_attest.py:126-136`). The assertion is over client data
  `"dsmack.appattest.guest-attest/1" || os_image_hash || manifest_sha256 || run
  || event_head || caller || report_data`, 255 bytes (`guest_attest.py:67-71`);
  `event_head` is a hash chain over the event log (`guest_attest.py:56-64`).
  `verify()` requires the log to end in its only `system-ready` event
  (`guest_attest.py:150-151`); the agent never sends that event, so the app
  appends it.
- `/v1/GetSecret {task_id, epk, iv, ct}`: always on this image, since the
  supervisor passes `--secret-key`. P-256 ECDH, HKDF-SHA256, AES-256-GCM through
  libcrypto; `epk` is checked to be on the curve (`secret_box.py:46-53`).
- `/v1/GetKey`: only with a grant (`agent.py:99-102`).

Decision 0005 (on local branches such as `couch-browse`, 99bc5579; not on this
branch) is the reason for the shim: the guest serves dstack's guest API v1 so
one compose file runs on dstack and on a Mac.

## 6. Egress

The manifest's `network` has `mode` (`none` or `nat`), `listen_ports` and
`egress`, a list of up to 256 `{destination, protocol, port}` with a
destination IP or CIDR and protocol `tcp` or `udp`; `none` forbids egress
entries (`manifest.py` `_validate_network`, 1539-1567).

After `runner validate` succeeds and before inputs, sentinel or compose,
the supervisor installs one nft table, `inet dsmack_egress`, in a single
transaction, and powers off if it fails (supervisor:554-557;
`egress.py:10-13`). Rendering (`lowering.py:480-505`):

- hooks `output` and `forward`, priority -10, policy drop;
- `output` accepts `oifname "lo"`;
- both accept `ct direction reply ct state established,related`;
- both accept each listed `ip`/`ip6 daddr ... dport` tuple;
- everything else is counted and dropped. IPv6 is dropped unless listed.

The table covers guest processes (including the sentinel) and container
traffic forwarded through Docker. dockerd runs with `--iptables=true
--ip-masq=true` (supervisor:189-191); the dsmack table runs at priority -10,
so a drop there is final regardless of Docker's rules.

What the rules do not cover:

- There is no `input` hook. Containers can reach any guest listener through
  the bridge gateway. The sentinel listens on `0.0.0.0:5100`
  (supervisor:477, 485) and is addressed as `172.17.0.1:5100`. The OCI
  publisher binds `127.0.0.1` (supervisor:335) and published `listen_ports`
  bind `127.0.0.1` (`lowering.py:514`).
- The policy is guest-wide, not per service (`lowering.py:481-486`). Per-service
  egress is #76/#78 and is not on this branch.
- The NIC is configured at supervisor:146-155 and the table is installed at
  556. Between them run dockerd, the loopback OCI pulls and the agent. None of
  them uses the external network, but no rule is in place yet.
- DNS goes to gvproxy at `192.168.127.1` (`guest-network.env:6`). A manifest
  needs an explicit entry for it, and that entry permits queries for any name
  (`README.md:30-31`).
- Decision 0007 notes that `192.168.127.254` reaches the Mac's loopback
  (0007:39, citing `dstack-compat/secret_workload.py:6-7`). The base does not
  refuse it as a destination.
- gvproxy is a userspace NAT on the Mac that terminates guest connections
  (0007:26-27). Nothing in the attestation names gvproxy (0007:54-63).

## 7. Threat model

**Trusted.** macOS, App Attest and the signed Mac app (`mar`): the app supplies
`os_image_hash`, `manifest_sha256` and `run` in `hello`, signs `/v1/Attest`,
and signs launch and result evidence (`docs/architecture.md:20`; 0007:42-52).
The hypervisor is trusted to keep guest memory and tmpfs from the host; nothing
in this tree enforces that. The image builder: whoever produced B44 and whoever
runs the derive (section 8).

**The host owner.** Untrusted.

The host can see: the console (hvc0, `kernel-cmdline.sh:39`), including every
`DSMACK_*` marker; vdc and vde, which it supplies; the result disk vdd in
plaintext; all network traffic through gvproxy, and every DNS answer.

The host can change: vdc contents, limited by the chain in section 4; vde,
which is unmeasured and only parsed safely; the `base-bundle/` and
`admission/` claims on vdc, which the guest records but does not verify against
preboot bytes (`boot_observe.py:1-7`); network behaviour, including dropping or
answering any connection; whether the VM runs at all.

The host cannot, if the trusted parts hold: change the root filesystem
(verity, `--panic-on-corruption`); make the agent seal for a manifest other than
the one the app attested (`agent.py:142-143`); read Docker scratch off vdb
(per-boot dm-crypt key held only in guest memory, supervisor:105-106).

**A workload** runs in containers started by the runner through the 0700
`/run/rootcontrol/docker.sock`. It can reach: its own dstack socket, if
declared; `/run/dsmack` read-write or read-only, if declared
(`manifest.py:67`; `lowering.py:440-445`); destinations on the egress list;
guest listeners through the bridge (section 6).

It cannot reach: the Docker socket (checked after the run by the boundary
probe, supervisor:660-697); other services' dstack sockets (not bound); the
private tree in `/run/dsmack-private` or the canary key in `/run/rootcontrol`
(not bound).

**Gaps.**

- The sentinel runs as uid 1000 (supervisor:484). The workload user is also
  uid 1000 (`lowering.py:59-60`; `security.py:28-29`), and `/run/dsmack` is
  owned by 1000 (supervisor:104). A service that binds `/run/dsmack` can read
  `/run/dsmack/credential`. `agent-sandbox-v1` runs as root with
  `DAC_OVERRIDE` (`security.py:33-43`).
- No file in this tree writes `/run/dsmack/credential`. supervisor:456 says
  "the compute node writes" it; `README.md:78-79` and
  `applications/agent-turns/README.md:175` say "an in-guest writer".
- The boundary probe runs after the workload, and its failure does not latch:
  a `DSMACK_BOUNDARY_FAIL_*` line still ends in a closure line
  (supervisor:683-697).
- The guest does not sign the receipt. `receipting.py:14` keeps
  `attestation` null; the binding to the run is the app's result assertion,
  which is outside this tree.
- `SHA256SUMS` on vdc is self-consistency only (section 4).

**What a receipt proves.** By itself, nothing: it is unsigned JSON on a disk the
host can write. The guest's own statement about it is the closure line on the
console, which names `receipt.json` and `outputs/index.json` by sha256
(`closure.py:62, 68`). The app signs launch and result assertions over the
evidence it retains (`docs/architecture.md:20`); per decision 0007 the
result assertion covers `manifest_sha256`, an evidence digest and the challenge
(0007:47-50, citing `AssertionEvidence.swift:83-95`). Whether that evidence
includes the closure line is defined in the app, not in this tree, and was not
checked for this document.

**What `/v1/Attest` proves.** That the approved app, during run `run` of image
`os_image_hash` with manifest `manifest_sha256`, signed `report_data` for the
service whose socket was called, after the guest sealed the listed system
events (section 5).

## 8. Building and checking

`derive.py` extracts `git archive HEAD` into `<out>/repo` (`derive.py:22-25`),
so uncommitted and untracked files never enter the image, and runs
`derive-in-container.sh` in the builder image with `--network none`, 4 CPUs and
4 GiB, with the repo, B44 bundle, templates and kernel tarball mounted
read-only (`derive.py:7-14`). The builder image is Debian trixie pinned by
digest, with packages from snapshot 20260721T000000Z (`builder/Dockerfile:1-17`);
the arm64 debs installed into the guest are named by package, not by digest
(`builder/Dockerfile:18-24`). The kernel tarball is checked by sha256
(`derive-in-container.sh:10`); kernel and image builds use fixed
`SOURCE_DATE_EPOCH` and paths (`derive-in-container.sh:15-17`;
`assemble_leg.sh:12, 30-47`).

`check_rootfs.py ROOTFS` fails if any file under `/usr/local/lib/dsmack`,
`/usr/bin/dsmack-supervisor`, `/etc/docker/daemon.json` or
`/usr/local/bin/dsmack-*` is named `SHA256SUMS`, is not a regular file, or has
a sha256 that matches no tracked repo file (`check_rootfs.py:7, 14-23`). It
checks membership in the set of all tracked files' hashes, not that each file
sits at the path its source maps to. It does not cover the binaries and
libraries from `derive-in-container.sh:26-30`.

`.github/workflows/image-repro.yml` checks the B44 bundle against its
`sha256sum.txt` (51-52), runs `derive.py` (62-63), runs `check_rootfs.py` on the
unpacked root (67-69), and compares the digest with `image.sha256` (72-74).
`image.sha256` on this branch is still eb2b54ce from fa807bae; this branch's
install changes have not updated it.

B44's Debian packages cannot be reviewed from source. The recipe that built
B44 (`source/build/BUILD.sh`) and its provenance files were deleted in
7bdebe27, and the deleted `SOURCE-ORIGIN.json` says
`"reproducible_clean_build_claimed": false`
(`docs/base-vm-audit-2026-11.md:44-47`). B44 was itself an overlay: its build
installs one `sentinel.py` over a prior rootfs `f20ef2e7…`
(`base-vm-audit-2026-11-verification.md:171-174`, branch `base-vm-audit`). The
original `BUILD.sh` survives on zed at
`/data/amiller/dsmack/broker-timeout-v1-20261022/build-1/source/build/BUILD.sh`.

Tests: `python3 -m pytest base-vm/browser-sandbox-v1` (`README.md:69-71`);
`test_guest_install.py:22-25` runs `install-guest.sh` into a temporary root and checks the result.

## 9. Requirement IDs

Installed files cite IDs from interface documents that are not in this repo.
The audit found roughly 70 (`docs/base-vm-audit-2026-11.md:157-160`). The
verification report located the documents on zed under
`~/dsmack-sprints/attested-runner-20261019/joined-sprint/app-compose-20261020/contract10/candidate/interfaces/`
(`base-vm-audit-2026-11-verification.md:176-187`).

**Definitions were not read for this document.** Two attempts to read those
files over `ssh zed-mesh` on 2026-11-06 were refused by the shared connection
("Session open refused by peer"). The definition column below says "not read"
for that reason. It does not mean the ID is undefined. The one definition known
secondhand: `compose-runner-interface.md:214` heads "Sentinel lifecycle (D07)",
and the word FROZEN does not occur in that file
(`base-vm-audit-2026-11-verification.md:184`), while `sentinel.py:4-5` calls
the D07 lifecycle "FROZEN".

Counts are occurrences across installed files; locations are the first few.
Contract paths drop the `compose-contract/dsmack_compose_contract/` prefix,
runner and guest-io paths drop `source/runner-content/`.

| ID | Count | Cited at | Definition |
| --- | ---: | --- | --- |
| C02 | 5 | `lowering.py:9, 605`; `manifest.py:324` | not read |
| C03 | 8 | `lowering.py:410, 455`; `manifest.py:254` | not read |
| C04 | 7 | `receipt.py:260, 880, 910` | not read |
| C05 | 7 | `dsmack_compose_runner/control.py:3, 50`; `canonical.py:46` | not read |
| C06 | 4 | `receipt.py:880, 1264, 1395` | not read |
| C07 | 3 | `canonical.py:7, 25`; `manifest.py:1391` | not read |
| C08 | 10 | `canonical.py:156, 198, 214` | not read |
| C09 | 3 | `runtime_inputs.py:107, 482, 571` | not read |
| C10 | 1 | `manifest.py:89` | not read |
| D01 | 5 | `errors.py:66`; `receipt.py:260`; `image_admission.py:565` | not read |
| D03 | 6 | `errors.py:76`; `receipt.py:9, 133` | not read |
| D04 | 14 | `dsmack_compose_runner/workspace.py:98, 125`; `lowering.py:13` | not read |
| D05 | 13 | `canonical.py:217`; `manifest.py:17, 611` | not read |
| D06 | 13 | `dsmack_compose_runner/errors.py:5`; `receipt.py:27, 225` | not read |
| D07 | 7 | `sentinel.py:5`; `sentinel_oauth.py:5`; `lowering.py:18`; `manifest.py:21, 89, 712` | "Sentinel lifecycle", `compose-runner-interface.md:214` (secondhand) |
| D08 | 3 | `manifest.py:25, 1090, 1177` | not read |
| D09 | 16 | `receipt.py:16, 880, 894` | not read |
| D10 | 14 | `receipt.py:19, 880, 910` | not read |
| D11 | 1 | `dsmack_compose_runner/control.py:243` | not read |
| E01 | 7 | `image_admission.py:1, 12, 74` | not read |
| E02 | 11 | `receipt.py:70, 94, 275` | not read |
| E04 | 4 | `dsmack_compose_runner/control.py:3`; `lowering.py:519, 558` | not read |
| E05 | 3 | `manifest.py:1103, 1143, 1177` | not read |
| E06 | 7 | `receipt.py:160, 165, 925` | not read |
| E07 | 7 | `canonical.py:163, 223`; `receipt.py:956` | not read |
| E08 | 3 | `receipt.py:180, 1469`; `manifest.py:419` | not read |
| E09 | 3 | `receipt.py:133, 346, 743` | not read |
| E10 | 7 | `lowering.py:116, 129, 374`; `manifest.py:1699` | not read |
| F01 | 3 | `receipt.py:218, 294, 381` | not read |
| F02 | 7 | `dsmack_compose_runner/cli.py:92, 157`; `receipt.py:880` | not read |
| F04 | 5 | `dsmack_compose_runner/control.py:137`; `lifecycle.py:162, 215` | not read |
| F05 | 1 | `dsmack_compose_runner/control.py:50` | not read |
| F06 | 11 | `sentinel.py:57, 177`; `sentinel_oauth.py:329` | not read |
| F07 | 2 | `manifest.py:1407, 1652` | not read |
| F08 | 3 | supervisor:655; `runtime_inputs.py:437, 603` | not read |
| F11 | 2 | `canonical.py:3, 114` | not read |
| GIO01 | 14 | `dsmack_guest_io/private_transport.py:87, 158, 169` | not read |
| GIO02 | 6 | supervisor:50, 408, 429 | not read |
| GIO03 | 13 | `dsmack_guest_io/cli.py:63, 123`; supervisor:186 | not read |
| GIO04 | 3 | `dsmack_compose_runner/export_outputs.py:13, 272`; supervisor:588 | not read |
| GIO05 | 6 | `dsmack_compose_runner/export_outputs.py:36, 111, 328` | not read |
| GIO06 | 4 | `dsmack_compose_runner/control.py:162`; `lifecycle.py:330, 444` | not read |
| GIO09 | 6 | supervisor:141, 207, 304 | not read |
| R01 | 8 | `image_admission.py:20, 104, 115` | not read |
| R02 | 15 | `receipt.py:364, 502, 573`; supervisor:378, 444 | not read |
| R04 | 3 | `dsmack_compose_runner/export_outputs.py:77`; `receipt.py:826, 1174` | not read |
| R05 | 7 | `lowering.py:223`; `dsmack_compose_runner/identity.py:12, 273` | not read |
| R06 | 9 | `lowering.py:378`; supervisor:615, 664 | not read |
| R07 | 9 | `sentinel.py:62, 156`; `sentinel_oauth.py:302` | not read |
| R08 | 3 | `receipt.py:743, 765, 782` | not read |
| R09 | 2 | `lowering.py:259, 313` | not read |
| S01 | 6 | `receipt.py:364, 573, 625` | not read |
| S03 | 3 | supervisor:378, 465, 479 | not read |
| S04 | 5 | `image_admission.py:332, 353, 385` | not read |
| S05 | 1 | `manifest.py:952` | not read |
| S06 | 8 | `sentinel_oauth.py:104, 190`; `dsmack_compose_runner/errors.py:5` | not read |
| S07 | 6 | `lowering.py:269, 332`; `dsmack_compose_runner/identity.py:84` | not read |
| T03 | 1 | `lowering.py:264` | not read |
| T04 | 3 | `manifest.py:1478, 1486, 1594` | not read |
| T05 | 3 | `manifest.py:1368, 1411, 1657` | not read |
| U01 | 2 | `manifest.py:1478, 1482` | not read |
| U02 | 3 | `manifest.py:503, 535, 639` | not read |

Other labels in installed files that are not interface IDs:

- **R1-R5 in the supervisor** are defined in the file itself, as this lane's
  deltas from a prior supervisor (supervisor:9-32, 84). They are not R01-R05.
- **R1-R5 in `image_admission.py` and `receipt.py`** refer to a "boot-binding-spike
  DESIGN" (`image_admission.py:40-43, 631, 689, 702`; `receipt.py:70, 96`). No
  such file is in this repo; whether it is on zed was not checked.
- **astra** (12 occurrences, e.g. `dsmack_compose_runner/control.py:3`,
  `canonical.py:7`), **contract3**, **contract4**, **contract6**,
  **contract10** (`errors.py:1`, `receipt.py:1`, `image_admission.py:1, 20`,
  `sentinel.py:5`) and **JOIN-4**, **JOIN-5** (supervisor:380,
  `dsmack_guest_io/__init__.py:4`) name review rounds, contract versions or
  build lanes, not requirements.
- `L1` at `image_admission.py:29` is a verity hash-tree level.
- **GIO08** appears only in build-time files (`source/build/assemble_leg.sh:99-100`,
  `source/profile/.../kernel-cmdline.sh:26`), not in the image.

Until the next base change renames or removes them, these IDs resolve only
through this table.
