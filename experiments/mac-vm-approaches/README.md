# mac-vm-approaches

## Question

How can a signed, App-Attested Mac app run measured Linux workloads, and what did each
approach we tried show?

## Answer

One process can hold the App Attest `CDhash` opt-in and `com.apple.security.virtualization`,
get an attestation and an assertion that carry its CDHash, and boot a Linux VM through
Apple's Containerization package, with the assertion's client data committing to a compose
hash (`vzattest/`, 2026-10-08). The one trap was that App Attest leaves the CDHash extension
out when the binary targets the macOS 26 SDK; macOS 27 for both min OS and SDK works. The
production runner (`../../runner/`) builds on that: a no-NIC guest per compose or per task,
egress only through a host proxy that holds the key, and receipts chained to the attested
boot. What the VM gives is code identity and isolation from the workload. It does not give
confidentiality from the Mac's owner: guest memory is host memory. A signed app run inside
a macOS guest VM cannot use App Attest at all (`macos-guest-appattest/`).

## Guides

The Mac runner (`../../runner/README.md`) and any Mac task or sandbox offering built on it.

## How it works

The host binary is the measured thing. App Attest signs `sha256(clientData)` and Apple's
certificate carries the binary's CodeDirectory hash, so a verifier learns "this exact binary,
on a genuine Mac with SIP and Full Security, said this clientData". The binary puts the
compose hash, image digests, and fresh RAM keys into that clientData. Everything the guest
runs is pinned from the host side: the kernel digest is compiled into the binary, the initfs
and images are pinned by `@sha256`, and the VM gets no network device, no Rosetta and no
virtiofs. The guest reaches the world only through a Unix socket relayed into it, where the
host proxy enforces an allowlist, injects credentials the guest never sees, and signs a
receipt per exchange.

## Approaches tried

| Approach | What it is | What was demonstrated | Evidence | Limits |
|---|---|---|---|---|
| VZ + App Attest spike (`vzattest`) | 60-line Swift app: App Attest `enroll`/`assert`, then boot alpine through Containerization 0.33.4 in the same process | Signed (Apple Development, hardened runtime) with `CDhash` opt-in + `com.apple.security.virtualization`: attestation and assertion both carry CDHash `f25f718f…8a02`, clientData commits to `sha256(compose.yaml)`, guest printed `uname` and the hash. AMFI accepted the VZ entitlement although the provisioning profile does not list it. Same code linked for macOS 26: attestation flags `0x40`, no CDHash extension | `vzattest/RESULTS.md`, `vzattest/captures/`, `vzattest/verification-vz27.json` | Compose hash binds what the app read, not what the guest ran. Kernel and initfs are unpinned files, initfs fetched from ghcr by tag. No network was configured, but the guest's interfaces were not checked. Challenge generated on the Mac, not by a verifier. Minimum OS and SDK changed together, so which one matters is not separated |
| Restricted compose runner (`runner`) | `Runner.app`: dstack `app-compose.json` (one service, digest-pinned image) in a no-NIC Containerization VM; egress via host proxy over a relayed Unix socket; KMS releases the API key sealed to an in-RAM key bound in the attestation; per-exchange receipts | Ad-hoc 34/34 then 52/52, signed `FAILED=0` across several CDHashes on 2026-10-08. Only `lo` in the guest, direct IP and DNS fail, allowlist/method/path/dot-segment refusals, guest auth headers stripped, key absent from rootfs/initfs/logs, TLS pinning refuses a system-trusted root outside the pin set, KMS refuses wrong CDHash/compose/replayed nonce, receipts verify and tampering is caught. Served an abalone peer with real paid chat turns, verified offline from Apple root to a NEAR quote admitted on Base | `../../runner/RESULTS.md` | KMS is `kms.py` on the owner's Mac and the parcel is not KMS-signed. Kernel/initfs/rootfs owner-writable between hash and boot (no dm-verity). Named volumes are plaintext ext4 the owner can edit or roll back. Quote helper's `node_modules` outside the CDHash. Plan and gaps: `<dsmack-workspace>/research/notes/mac-compose-runner-plan-fable-2026-10-08.md` |
| Per-task guest VMs (runner `/task/*`) | Each task is its own no-NIC VM started by the peer through the runner; `/in` read-only, `/out` collected into a deterministic tar; task boot bound by a runner assertion in domain `mac-compose-task-boot/1` | Ad-hoc 190/190 and signed `FAILED=0` (127 checks), CDHash `0a5a5c15…`. Three paid tasks on 2026-10-09, each `collect.tar` verifying independently from Apple root to `out_sha256`. Found and mitigated a Containerization relay stall (zero-byte connection while a task VM boots) and a SIGPIPE crash | `../../runner/RESULTS.md` ("Task guests", "Signed task pass failure and fix") | Task VM is not separately attested; its receipt key is trusted through the runner binary. `/in` and `/out` are plaintext host files. The relay stall's root cause in Containerization/VZ is not found |
| App Attest inside a macOS guest VM | Probe app run in a tart macOS 27 guest (Virtualization.framework) to see whether the app could live in a VM instead of hosting one | Guest serial is a deterministic function of the host-chosen ECID. A dev-signed build is killed by AMFI unless the profile lists the VM's provisioning UDID. With such a profile, `isSupported` is true but `generateKey` fails (DCError 0; devicecheckd cannot write the system keychain, AKS extended state unsupported). The same build on the host verifies | `macos-guest-appattest/RESULTS.md`, `macos-guest-appattest/vmtag/verification.json` | One host, one guest image. Dead end for App Attest in a guest, not a statement about other guest attestations |
| Not tried | Hypervisor.framework directly, Rosetta x86 guests, SIP-off capture | Hypervisor.framework only appears in the memory-protection note (a host process can map guest memory, so a VM is not evidence of confidentiality). Rosetta is deliberately disabled. A SIP-off capture is planned and has not been made | — | Whether a SIP-off Mac still attests with the SIP-on ACL decides whether code identity holds against the owner |


## Run

Mac only for the spikes: Apple silicon, macOS 27, Xcode 27, an Apple Development identity
whose provisioning profile grants App Attest with the `CDhash` opt-in. The offline checks run
anywhere with Python 3, `cryptography` and OpenSSL 3.

Offline, from this directory:

```
python3 vzattest/verify.py vzattest/captures/vz27-enroll vzattest/captures/vz27-assert 1791496800
python3 macos-guest-appattest/vmtag/verify_vm.py 1791871200
```

The last argument is the Unix time the certificate chain is checked at. The App Attest leaf
is valid for three days around enrollment, so recorded captures are checked inside that
window (2026-10-08 22:00 UTC and 2026-10-13 06:00 UTC).

On the Mac (`vzattest/`): put `vmlinux-arm64` beside `build.sh` (from the Kata 3.17.0 arm64
static release, tarball sha256 in `kata.sha256`, kernel sha256 `67bac9f4…6af6ea0`), then

```
KEYCHAIN=… KEYCHAIN_PW=… PROFILE=… ENTITLEMENTS=… SIGN_IDENTITY="Apple Development: …" ./build.sh
./run.sh enroll vz27-enroll && ./run.sh assert vz27-assert
```

## Recorded result

2026-10-08, Mac mini M4 Pro, macOS 27.0 (26A428), Xcode 27.0, Swift 6.4, SIP on.

| Capture | Build | Attestation flags | CDHash extension |
|---|---|---|---|
| `vz-enroll` / `vz-assert` | min OS / SDK 26.0, + virtualization | `0x40` | absent |
| `novz-enroll` | same binary re-signed without virtualization | `0x40` | absent |
| `control-0916-honest` | earlier probe, min OS / SDK 27.0 | `0xc0` | present |
| `vz27-enroll` / `vz27-assert` | min OS / SDK 27.0, + virtualization | `0xc0` | present, `f25f718f…8a02` |

Rerun of the offline check on 2026-10-15 (Linux laptop, Python 3.10, OpenSSL 3.0.2):

- `vz27` pair at 1791496800: passes. Attestation and assertion CDHash
  `f25f718f9f8b793da5474d6e99d1fd86c8862c7d959ea0c23aedb4e122bc8a02`, validation category 3,
  assertion counter 1, both clientData carry `compose_sha256=0bfcc6a1…1f25c9`
  (`vzattest/verification-vz27.json`).
- `vz` pair (macOS 26 build) at the same time: `Reject: unsupported_cdhash_type`.
- `vz27` pair at the current time: `Reject: certificate_chain_failed` (leaf expired 2026-10-10).
- `verify_vm.py` at 1791871200: output identical to the recorded `vmtag/verification.json`.

Guest output from the attested process (`vzattest/captures/vz27-assert/vm_stdout.txt`):

```
Linux vzspike-1791495907 6.12.28 #1 SMP Tue May 20 15:19:05 UTC 2025 aarch64 Linux
3.16.9
compose_sha256=0bfcc6a1a6eba96a8ce6ae71afc57c2e383179d2f18ec3fb74f248e1331f25c9
```

## Files

- `vzattest/app/Sources/vzattest/main.swift` — the spike: App Attest enroll/assert and the Containerization boot.
- `vzattest/app/Package.swift`, `Package.resolved` — SwiftPM manifest pinning Containerization 0.33.4, macOS 27.
- `vzattest/build.sh` — bundle and sign as `dev.dsmack.provider` with the VZ entitlement added.
- `vzattest/run.sh` — launch through LaunchServices with a fresh challenge into `captures/<name>/`.
- `vzattest/compose.yaml`, `kata.sha256` — the hashed compose and the kernel tarball digest.
- `vzattest/verify.py` — offline check of an enroll/assert pair using `../../verifier/core.py` and `../../verifier/macos_policy.py`.
- `vzattest/captures/` — clientData, challenge, key ID, attestation/assertion CBOR, `codesign -d` output, signed entitlements, guest stdout and exit for each run. `adhoc-boot-vm-only/` is the unsigned VM-only control.
- `vzattest/RESULTS.md` — the original lab log, including the blocked first attempt.
- `vzattest/verification-vz27.json` — output of the offline check above.
- `macos-guest-appattest/probe/` — `Probe.swift` (serial hash, DeviceCheck, App Attest) and its build script, with host results.
- `macos-guest-appattest/vmtag/` — `TagProbe.swift`, build script, host and guest runs, `verify_vm.py`, `verification.json`, guest keystore log.
- `macos-guest-appattest/guest*.txt` — guest probe outputs, AMFI diagnostics, guest security policy (ECID and UDIDs redacted at capture).
- `macos-guest-appattest/RESULTS.md` — the original results table.

## Provenance

- `vzattest/`: an untracked spike directory from 8 October 2026. `src/` was
  restored to the SwiftPM layout `build.sh` expects (`app/`). The 53 MB `vzattest` binaries
  were left out; sha256 `c40d98ce…3e7758` (vz27) and `a9b24aa0…b7b8f6` (vz). `verify.py` was
  changed to read the CDHash from `codesign.txt`'s `CandidateCDHashFull` instead of
  recomputing it from the binary, to take the chain-check time as an argument, and to find
  the repository root one level higher.
- `macos-guest-appattest/`: private research evidence from 12 October 2026.
  `verify_vm.py` now finds the repository root itself and takes the chain-check time.
  `vmtag/build/vm/codesign.txt` moved to `vmtag/codesign-vm.txt` because `build/` is ignored.
- All build scripts: the signing identity became `$SIGN_IDENTITY`. Home paths in captured
  `codesign` output became `<home>` / `<guest-home>`, and the developer name in `Authority=`
  became `<developer>`. The team ID `DC9JH5DRMY` stays because the verifier policy needs it.
- The `vzattest/RESULTS.md` intro and "To finish" section were shortened to drop the
  keychain-unlock instructions; the tables are unchanged.
- The runner is referenced, not copied: `../../runner/`.

## Limits

- Code identity only. Nothing here shows confidentiality from the Mac's owner; guest and
  proxy memory are host memory, and the SIP-off behaviour of App Attest is untested.
- The spike's kernel is an unpinned file and its initfs is fetched by tag. The runner pins
  both; the spike does not.
- The spike was run once per build on one machine. Whether min OS or SDK triggers the missing
  CDHash extension is not separated.
- The offline checks verify recorded captures at a historical time. They do not show
  freshness or admission.
- The "Not tried" row cites private research notes that are not in this repository.
