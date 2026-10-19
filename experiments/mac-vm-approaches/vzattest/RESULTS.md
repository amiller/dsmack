# VZ + App Attest spike, 2026-10-08

The first part of this log was written while the signed build was blocked on a locked
keychain. The signed runs completed the same day; see "Signed runs, 2026-10-08 (completed)"
at the end. Capture directories are under `captures/`.

Question: can one App Attest-enrolled, hardened-runtime app also hold
`com.apple.security.virtualization` and boot a Linux VM through Apple's Containerization
package, while its attestation and assertions still carry its CDHash and its assertion
clientDataHash commits to a compose hash?

Status at the time of writing: the Containerization half worked (ad-hoc signed, VM booted,
guest output captured). The signed half had not run yet because the signing keychain was locked.

## Test conditions

- Mac mini M4 Pro, macOS 27.0 (26A428), Xcode 27.0 (27A266a), Swift 6.4. SIP enabled. No
  platform security setting changed.
- Spike dir on the mini: `~/vz-attest-spike-20261008` (nothing else on the mini modified).
- Containerization package pinned at `0.33.4`, the version `examples/ctr-example` at HEAD
  (c0a6f76, cloned into the spike dir for reference) pins. Init filesystem:
  `ghcr.io/apple/containerization/vminit:0.26.5`, also the example's choice.
- Kernel: the project's documented default (`make fetch-default-kernel`), the Kata 3.17.0
  arm64 static release. Tarball 290,581,648 bytes, sha256
  `647c7612e6edf789d5e14698c48c99d8bac15ad139ffaa1c8bb7d229f748d181` (deleted after extraction).
  Kept only `vmlinux-arm64` = `vmlinux-6.12.28-153`, 14,750,208 bytes, sha256
  `67bac9f416af4cdc9b151e4ba4962d6515e0ad7acc53816761cf964aa6af6ea0`.
- Image store `store/` after one run: 226 MB (vminit initfs, alpine:3.16, 512 MiB sparse rootfs).
- Test compose file `compose.yaml`, sha256
  `0bfcc6a1a6eba96a8ce6ae71afc57c2e383179d2f18ec3fb74f248e1331f25c9`.

## The app (`src/main.swift`, 60 lines)

`vzattest enroll|assert|boot <out> <base> <challenge> <keyIdFile>`

- Reads `<base>/compose.yaml`, builds
  `clientData = {"challenge":"<hex>","compose_sha256":"<hex>"}` and passes
  `sha256(clientData)` as clientDataHash.
- `enroll`: `generateKey` + `attestKey`. `assert`: `generateAssertion`, then boots the VM.
  `boot`: VM only, no App Attest (for the ad-hoc control).
- VM: `ContainerManager` (initfs by reference, store under the spike dir, no network),
  alpine:3.16, runs `uname -a; cat /etc/alpine-release; echo compose_sha256=<hash>`, saves
  guest stdout and exit status.

Signed build (`src/build.sh`): same bundle shape as the 0916 rig and `node/mac/build.sh`
(bundle id `dev.dsmack.provider`, Apple Development identity, hardened runtime,
`embedded.provisionprofile`), with entitlements = `probe-entitlements.plist` plus
`com.apple.security.virtualization = true`. `src/run.sh` launches through `open -n -W`
like `run_step.sh` did, with a fresh 32-byte challenge per capture.

Offline check (`verify.py`): reuses `verifier/core.py` and `verifier/macos_policy.py`
(pinned Apple root, Mac ACL, category 3, production AAGUID, CDHash allowlist = the
captured binary's CodeDirectory, cross-checked against `codesign`'s
`CandidateCDHashFull`). It then verifies the assertion under the enrolled key and checks
that clientData commits to the challenge and to `sha256(compose.yaml)`.

## Steps

| Step | Result | Evidence |
|---|---|---|
| Provisioning profile lists `com.apple.security.virtualization` | No. Profile entitlements: aps-environment, app-attest-opt-in [CDhash], application-identifier, keychain-access-groups, team-identifier, applesignin | `security cms -D -i $SIGNING_DIR/embedded.provisionprofile` |
| Does AMFI accept the unlisted VZ entitlement on a profile-signed app? | NOT RUN (needs signed build) | |
| Build Swift package against Containerization 0.33.4 + DeviceCheck | PASS (release build, 82 s cold) | `src/Package.resolved` |
| Ad-hoc sign (hardened runtime + VZ entitlement only), `boot` mode | PASS. VM booted, container ran, exit 0, about 6.4 s wall time including image pulls | `adhoc-boot-vm-only/` |
| Ad-hoc binary: `DCAppAttestService.isSupported` | false (first run aborted with `appattest_unsupported`, so `boot` mode skips the check) | this file |
| Signed build (`build.sh`) | BLOCKED: `security show-keychain-info` gives `User interaction is not allowed.` (keychain locked) | |
| Enroll from the VZ-entitled signed app | NOT RUN | |
| Assert + VM boot in the same process | NOT RUN | |
| Offline verify (CDHash in attestation and assertion, compose hash in clientData) | NOT RUN (`verify.py` written, needs captures) | |

Ad-hoc guest output (`adhoc-boot-vm-only/vm_stdout.txt`):

```
Linux vzspike-1791494368 6.12.28 #1 SMP Tue May 20 15:19:05 UTC 2025 aarch64 Linux
3.16.9
compose_sha256=0bfcc6a1a6eba96a8ce6ae71afc57c2e383179d2f18ec3fb74f248e1331f25c9
```

## CDHash values

- Ad-hoc VM-only control: `5741ee1dfad670591b29d79bbe9c90adeb06861b9b14131fe35c935887bc2016`
  (flags `0x10002(adhoc,runtime)`, `adhoc-boot-vm-only/codesign-adhoc.txt`). This build is
  not App Attest-capable, so no attestation exists for it.
- Signed VZ build: not produced yet.

## To finish

The original instructions here (build and run on the Mac, copy captures back, run
`verify.py`) were carried out; the result is the last section. If a launch fails,
`captures/<name>/stderr.txt` and the unified log
(`log show --last 5m --predicate 'sender == "AppleMobileFileIntegrity"'`) show whether
AMFI rejected the VZ entitlement as unprovisioned.

## Open

- Whether AMFI launches a profile-signed app holding an entitlement the profile does not
  list. `com.apple.security.virtualization` is not a restricted (`com.apple.developer.*`)
  entitlement and ad-hoc signing accepts it, so I expect it to pass, but nothing has tested
  that yet.
- CDHash in attestation and assertion from the VZ-entitled build, and the compose-hash
  binding, both wait on the signed run.
- `run.sh` generates the challenge on the mini, unlike the 0916 rig's verifier-issued
  challenges. That is fine for a spike, not for admission.
- The compose hash binds the config the app read, not what the guest ran. The guest echoes
  the hash only for display, and the VM boot is not attested.

## Signed runs, 2026-10-08 (completed)

| Capture | Build | Entitlements | Attestation flags | CDHash ext |
|---|---|---|---|---|
| vz-enroll / vz-assert | SwiftPM, minos 26.0 / sdk 26.0 | + virtualization | 0x40 | absent (`unsupported_cdhash_type`) |
| novz-enroll | same binary re-signed | no virtualization | 0x40 | absent |
| control-0916-honest | 0916 probe, swiftc minos/sdk 27.0, fresh enroll today | probe set | 0xc0 | present |
| vz27-enroll / vz27-assert | SwiftPM, minos 27.0 / sdk 27.0 | + virtualization | 0xc0 / 0xc0 | present, `f25f718f…8a02`, verify.py accepts |

Finding: App Attest omits the CDHash extensions when the binary is linked against the macOS 26 SDK / deployment target, even with the `CDhash` opt-in entitlement. The virtualization entitlement does not affect it. With `platforms: [.macOS("27.0")]` one process holds the CDhash opt-in and `com.apple.security.virtualization`, gets CDHash-bearing attestation and assertion, and boots the Linux VM (vz27-assert/vm_stdout.txt). clientData carries `compose_sha256` and verifies offline.

Not separated: minos vs sdk (both moved together). The verifier already fails closed on a missing extension when a CDHash policy is set.
