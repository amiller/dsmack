# dsmack

dsmack runs a Linux workload in a VM on an Apple silicon Mac and produces Apple
App Attest evidence of what ran and what it output. A verifier on another machine
checks that evidence against the expected image, workload and inputs. An
application on top decides what a result means, for example whether a bounty
task passed and should pay out.

```text
Mac: DsmackRunner.app (Swift + libkrun/HVF)                runner-vm/
  └─ Linux ARM64 VM: measured kernel, initrd, verity rootfs   base-vm/browser-sandbox-v1/
       └─ guest supervisor + compose runner
            └─ digest-pinned OCI workload → result disk
Mac: App Attest assertions over launch and result
Linux: run-result verifier                                 applications/pilot-client/verifier-browser/
Apps: task board, acceptance, settlement                   applications/
Chain: App Attest enrollment and assertion verification    app-attest/, contracts/
```

The signed app carries no image identity. It admits a base image against a
policy, boots it with the workload disk, and signs two assertions: one over the
launch and one over the finalized result. A new task, container or base image
needs no new app build. With SIP and the hardened runtime, no process on the Mac,
root included, can read the runner's memory, which holds the VM's memory.
[docs/architecture.md](docs/architecture.md) covers the disks, what is bound into
the evidence, and the trust model.

## Repository map

| Path | Role |
|---|---|
| [`runner-vm/`](runner-vm/README.md) | DsmackRunner.app: Swift app, libkrun/HVF backend, packaging and signing |
| [`base-vm/browser-sandbox-v1/`](base-vm/browser-sandbox-v1/README.md) | Linux guest image source: supervisor, compose runner, I/O transport, sandbox preset |
| [`applications/pilot-client/`](applications/pilot-client/README.md) | Mac-side install, coordinator and launch; Linux run-result verifier |
| [`applications/arcade-pilot/`](applications/arcade-pilot/runner/README.md) | Testnet bounty pilot: service, worker runner, checker, escrow |
| [`applications/bounty-demo/`](applications/bounty-demo/README.md) | Task board, claims and submission API |
| `applications/bounty-{develop,judges,recipes,runtime,settlement}/` | Agent development workload, judges, shared request protocol, stage adapters, acceptance and settlement |
| [`app-attest/`](app-attest/README.md) | On-chain App Attest verification, in Solidity and as a Noir circuit |
| [`contracts/`](contracts/DEPLOY.md) | Build and App Attest key registries |
| `verifier/` | Python App Attest verification |
| [`trust/`](trust/README.md) | Apple App Attestation root certificate |
| `tools/release/` | Runner executable inspection |

## Build

The native archive needs Rust with the `aarch64-apple-darwin` target; the app
needs an Apple silicon Mac with Xcode:

```sh
runner-vm/native/build.sh
runner-vm/packaging/build.sh runner-vm/native/source-tree/apple-static/target/aarch64-apple-darwin/release
```

The guest image, on a Linux builder:

```sh
python3 base-vm/browser-sandbox-v1/derive.py --base-bundle BASE --templates TEMPLATES --out OUT
```

Signing and release steps are in [docs/release/runner-release.md](docs/release/runner-release.md).

## Run

The [Arcade pilot runner](applications/arcade-pilot/runner/README.md) sets up a
Mac, enrolls it and runs a task end to end. [docs/running.md](docs/running.md)
gives the underlying install, enroll, run, verify and cleanup commands.

## Test

Set up the tools as in [CONTRIBUTING.md](CONTRIBUTING.md), then:

```sh
./test.sh
```

This runs the Python verifier tests, both Foundry projects and the leaf circuit.
Each component README lists its own tests.
