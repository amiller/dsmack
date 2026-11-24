---
status: proposed
date: 2026-11-24
---

# A dev-session profile lets a workload run its own rootless container engine

## Context

A dev session runs Claude Code and Codex with private login inputs. Then a build needs a container engine, and that step moves to another machine. Keeping it inside the guest would keep the source and build secrets inside the same run.

`agent-sandbox-v1` blocks the namespace and mount calls an engine needs. Masked proc paths prevent a fresh procfs mount; writable workspaces are tmpfs, which cannot back rootless overlay (`base-vm/browser-sandbox-v1/source/runner-content/dsmack_compose_runner/workspace.py:69-84`).

The per-run VM separates runs and protects the host. Its measured rootfs defines the profiles. Scratch is ext4 on encrypted vdb, mounted at `/var/lib/docker`, with a fresh, unstored key each boot (`base-vm/browser-sandbox-v1/source/guest/supervisor-dstack-trixie.sh:97-112`). Scratch is capped at 4 GiB; the result disk template is 256 MiB. VM memory and CPUs come from the manifest, checked against launch resources (`applications/compute-node/pool_mac_run.py:23-26`).

Egress depends on the guest's nftables table. Input, output and forward default to drop; forwarding permits declared tuples, replies and service traffic (`base-vm/browser-sandbox-v1/source/runner-content/lib/dsmack_compose_contract/lowering.py:327-358`, `render_egress_rules`). A loopback-only table precedes NIC setup. The supervisor swaps in the manifest's table before starting workloads and aborts on failure (`base-vm/browser-sandbox-v1/source/guest/supervisor-dstack-trixie.sh:514-517`). Host NAT supplies no additional egress restriction.

## Decision

Add `dev-session-v1`, selected through a service's `security_profile`. Callers cannot supply arbitrary security options. Lowering applies the preset, and the runner checks the normalized compose against it.

The fields are defined in `base-vm/browser-sandbox-v1/source/runner-content/lib/dsmack_compose_contract/security.py:36-62`:

| Field | `dev-session-v1` | `agent-sandbox-v1` |
|---|---|---|
| user | 1000:1000 | 0:0 |
| cap_drop | ALL | ALL |
| cap_add | none | CHOWN FOWNER DAC_OVERRIDE SETUID SETGID KILL |
| security_opt | `no-new-privileges:true`, measured seccomp, `systempaths=unconfined` | `no-new-privileges:true`, default seccomp and masks |
| tmpfs | `/workspace` rw,nosuid,nodev, 256 MiB, uid/gid 1000, 0700 | same |
| shm_size | 64 MiB | 64 MiB |
| pids_limit | 1024 | 128 |
| mem_limit | 2 GiB | 2 GiB |
| read_only root | required | required |
| credential broker | refused | refused |
| engine storage | rw bind at `/var/lib/dsmack-engine` | none |

The seccomp policy derives from Docker 28.1.1's default: remove the SYS_ADMIN, masked-clone, clone3→ENOSYS and CHROOT rules, then add one unconditional rule for 18 namespace/mount-related calls. This allows 17 previously refused calls and unmasks `clone`, while withholding seven SYS_ADMIN-gated calls; namespace flags remain unrestricted. The 11,713-byte policy is checked by size and sha256: `bc9b12c0526d1514aa690d34ea8e30b76dcf39b5e8205438b5f7068d9d1090e8`.

Lowering supplies an `engine` slot at `/var/lib/docker/dsmack-engine/<workspace dir name>/<service>`, owned by 1000:1000 with mode 0700. It exists only for this profile. Because the bind comes from inside dockerd's root, it uses `rslave` propagation, which Docker requires. The runner checks the exact lowered mount set after normalization (`base-vm/browser-sandbox-v1/source/runner-content/dsmack_compose_runner/lifecycle.py:132-155`).

The workload image must supply a rootless engine and runtime. The reference configuration uses a single uid mapping, overlay graphroot on scratch, runroot on tmpfs, and `ignore_chown_errors=true`. It uses the service's network namespace, disables inner cgroups and keyrings, and places temporary build files on scratch. Runtime state and HOME use `/workspace`. These settings belong to the workload image; the guest does not validate them.

## What the attestation claims

The VM boundary and externally signed launch identity are unchanged. The guest dockerd socket stays private; input delivery, workspace caps and the result format stay unchanged. The manifest and image hashes still identify what launched, and the app still signs the result disk hash. Guest-enforced restrictions now depend on a wider kernel surface: user namespaces and filesystem mounts become available, and proc/sys masks disappear.

What happens if the workload reaches guest root?

- **Egress:** it can replace the table. This matters to anyone releasing inputs under an egress restriction; host NAT does not preserve that restriction.
- **Events:** it cannot forge events after the seal. Events close before workload creation (`runner-vm/control-src/Sources/marAttest/GuestAttest.swift:45-68`; `base-vm/browser-sandbox-v1/source/guest/supervisor-dstack-trixie.sh:478-502`).
- **Caller and inputs:** it can impersonate another service and read its private inputs. This distinction matters in multi-service runs; a single-service run already gives that service the manifest's inputs and API authority.
- **Result export:** it can replace guest-written receipts and bypass export checks. The signed disk hash survives; guest observations about lifecycle and export limits lose their basis.

Inner containers have no attested boundary from their service. The Guest canary covers the whole image, so a break through this profile also affects other profiles sharing that image.

## How the profile appears in the run record

Today selection is implicit through `manifest_sha256`; its implementation is covered by `os_image_hash`. The proposed verifier prints every service's profile, including an absent selection, and refuses `dev-session-v1` unless explicitly allowed. No attestation-format change is needed.

Inner image digests count only when a measured input names them. The PoC pins one in its measured harness. Model-chosen pulls produce workload assertions; binding a pull log with an attestation proves that the service reported it.

## Alternatives

**Brokered docker outside the guest.** This avoids a base-image change, but sends source and build secrets to an owner-operated broker. Container execution falls outside the guest record, and the broker needs its own confinement policy.

**Exposing the guest dockerd.** A socket mount gives the workload guest-root authority immediately. Egress and service separation would then depend on a new API-filtering proxy.

**Nested VM.** This needs kernel support, a virtual machine monitor and device access, potentially changing the enrolled runner app. Nested virtualization availability remains unchecked; memory and startup costs increase.

**gVisor in the guest.** A userspace kernel could handle the added namespace and mount calls. It needs a runtime binary and supervisor registration; engine compatibility and build cost remain unmeasured.

**Status quo.** Container steps keep running elsewhere. The guest image stays unchanged, while credentials and source transfer span two machines.

## Risks

- User namespaces expose more kernel code. Removing proc/sys masks makes uid 1000 and zero initial-namespace capabilities essential.
- Engine storage shares scratch with dockerd; exhaustion can disrupt logs and results. The sampler currently rejects a 4 GiB disk.
- Single-uid ownership flattening can break package installs and non-root images. Shared networking lacks inner bridge isolation; socket compatibility remains untested.
- File-input mounts hit the existing missing-`slot` lookup bug. Dev sessions need this fixed for login inputs.

## Measures

| Dimension | Prior baseline | Target | Measured by |
|---|---|---|---|
| Run an image pinned by digest | No: clone refused | Yes, on guest | PoC run: rootless podman (overlay, crun, uid map 0→1000) pulled `sha256:7b3ccabf…627c` (arm64) and ran it as inner uid 0; `result.txt` bound by `/v1/Attest`, runner rc 0 |
| Build with package installs; run non-root `USER` image | No | Yes, or failure documented | Not measured in the PoC (rows to add to `run.sh`) |
| Pull time; service start to inner container | n/a | Recorded | Not measured separately; the whole VM run, boot to poweroff including the pull, took 22.9 s (4096 MB, 1 vCPU) |
| Profile setup overhead | 0 | Negligible against boot | Not isolated in the PoC (no run without the profile); whole VM run 22.9 s |
| Inner-container egress to forbidden address | Service blocked | Blocked; allowed tuple succeeds from same container | PoC run: from the inner container, the allowed registry tuple (tcp 443) connected and `1.1.1.1:443` was refused or timed out; drop counter not read |
| Syscalls beyond default at cap_drop ALL | 0 | 17 newly allowed + `clone` unmasked; 7 SYS_ADMIN-gated calls withheld | Policy diff against 28.1.1 default |
| Initial-namespace uid and capabilities | uid 0, 6 capabilities | uid 1000, 0 capabilities | Profile definition and unit test |
| Proc/sys masks | Default masks | None | Profile fields; PoC row: `/proc/sys` and `/proc/sysrq-trigger` writes fail; not measured in the PoC |
| Workload reaches guest root | Canary armed for `3bec88ca…`, a different image; burned state unchecked | Canary armed on profile image, not burned | New image's canary entry; none exists yet |
| Profile visible in verifier | Implicit | Printed per service | PoC run: `applications/dev-session/verify_run.py` printed `security_profiles: {dev: dev-session-v1}` for manifest `def9bab0…` |
| Inner digests in measured input | n/a | 1 of 1 in PoC; 0 guaranteed for model-chosen pulls | Manifest and image inspection |
| Engine within service limits | n/a | All inner pids in service cgroup; pids ≤ 1024, memory ≤ 2 GiB | `/proc/<inner pid>/cgroup`; not measured in the PoC |
| Engine scratch usage | Sampler unavailable on 4 GiB | Recorded, under 4 GiB including outer layers | Bind `df` before/after; not measured in the PoC |
| Base-image delta | — | 5 rootfs files; no supervisor, kernel, initramfs or runner-app changes | Source diff |
| Image identity | Installed base `7c1ebf67…` | Modified `55a8b8e5…`; control rebuild reproduces base | Runtime-update build; rerun on main image before release |

## Open questions

1. Separate image, or accept the shared canary consequence?
2. Can the engine work with network-namespace creation refused?
3. Should validation require a single service?
4. Should inner images come only from measured inputs, without registry egress?
5. Are 2 GiB memory and 4 GiB shared scratch enough for real builds?
6. Is a compatible engine socket required for acceptance, and when would gVisor replace this profile?
