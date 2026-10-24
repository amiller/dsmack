# Dsmack

Dsmack provides a protocol and reference verifiers for Apple App Attest evidence
across developer accounts. An application chooses which code to accept. Operators
can sign copies under their own Apple developer accounts, and recipients can
check the app identity, approved code and signed messages. See the
[protocol discussion draft](https://amiller.github.io/dsmack/protocol.html) and
[App Attest implementation](app-attest/README.md).

The signed messages can serve different applications: a peer can authenticate a
network request, while a batch worker can identify the environment and result of
a completed job. DsmackRunner is the included batch-execution runtime: a signed
macOS app that runs a Linux workload in a VM and signs launch and result records.
The bounty application uses that runtime to check code changes before payment.

```text
App Attest policy + approved code + signed messages       app-attest/, contracts/
  └─ VM execution runtime                                runner-vm/
       └─ Linux base + task container                    base-vm/
            └─ bounty checks and reward decisions        applications/bounties/
```

The app admits a base image against an external policy. A different task,
container or compatible base image does not require rebuilding the app.
[docs/architecture.md](docs/architecture.md) explains the VM, disks and execution
records; [docs/running.md](docs/running.md) gives installation and run commands.

## Repository map

| Path | Role |
|---|---|
| [`app-attest/`](app-attest/README.md) | App Attest verification in Solidity and a Noir proof circuit |
| [`contracts/`](contracts/DEPLOY.md) | Approved-code and App Attest key registries; bounty escrow in `work-escrow/` |
| [`runner-vm/`](runner-vm/README.md) | Signed macOS app and its libkrun/Apple Hypervisor backend |
| [`base-vm/browser-sandbox-v1/`](base-vm/browser-sandbox-v1/README.md) | Linux guest, container runtime and input/output transport |
| [`applications/pilot-client/`](applications/pilot-client/README.md) | Shared Mac installation, launch, workload preparation and Linux verification tools |
| [`applications/bounties/`](applications/bounties/README.md) | Bounty service, worker tools and settlement; Arcade tasks under `examples/arcade/` |
| [`applications/bounty-dashboard/`](applications/bounty-dashboard/README.md) | Read-only view of contracts, tasks, attempts and payments |
| `verifier/` | Python App Attest verification |
| [`trust/`](trust/README.md) | Apple's App Attestation root certificate |
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

The [bounty worker tools](applications/bounties/runner/README.md) set up a
Mac, enroll it and run a task end to end. [docs/running.md](docs/running.md)
gives the underlying install, enroll, run, verify and cleanup commands.

## Test

Set up the tools as in [CONTRIBUTING.md](CONTRIBUTING.md), then:

```sh
./test.sh
```

This runs the Python verifier tests, both Foundry projects and the leaf circuit.
Each component README lists its own tests.
