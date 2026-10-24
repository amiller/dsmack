# Architecture

## App Attest messages and applications

The core protocol authenticates app identities, approved code and signed messages.
It does not require a VM or a file-based result. A peer-to-peer application can
use those messages for peer authentication and service requests. The runtime
described below implements a bounded VM job and signs launch and result records.
A persistent worker service could use it to execute individual jobs; discovery,
scheduling and live service authentication belong to that service.


## What runs where

```text
Mac: signed Swift app + native libkrun/HVF backend
  └─ Linux ARM64 VM: measured kernel, initramfs and verity-protected base
       └─ guest supervisor + Docker/compose runner
            └─ OCI workload + declared inputs → bounded outputs
Mac: launch and result App Attest assertions over the retained evidence
Linux: run-result verifier checks the evidence
Application: task acceptance, delivery and settlement
```

HVF is Apple's Hypervisor.framework. macOS is the host and the guest is Linux;
there is no macOS VM per task.

The base image ([`base-vm/browser-sandbox-v1`](../base-vm/browser-sandbox-v1/README.md))
is a dstack-derived Debian ARM64 system. It supplies the guest supervisor,
Docker/compose execution, input/output transport and the credential broker.
Claude Code, browser tests or any other program go in OCI images selected by the
workload. Many workloads share one base and one signed app.

## Disks

The runner attaches up to five disks:

| Device | Contents |
| --- | --- |
| `vda` | system (verity-protected base rootfs) |
| `vdb` | scratch for Docker state |
| `vdc` | workload: OCI payload, compose manifest, public inputs |
| `vdd` | result |
| `vde` | private input (optional) |

The guest validates the workload disk before running anything. Credential-free
browser profiles run with networking disabled. Coding profiles add the private
input disk and the broker route. The coordinator's current profiles use 4 GiB
RAM, one vCPU and a 600-second limit.

## What changes need what

| Layer | Can change by selection | Bound into the evidence |
| --- | --- | --- |
| Signed Mac app | workload, without rebuilding the app | app/native executable, signing identity, entitlements, enrollment |
| Linux base | kernel, rootfs, guest services | image identity, kernel/initramfs, verity root, admission policy |
| OCI workload | application, harness, entrypoint, declared files | OCI digest, compose manifest digest, security/network/resource profile |
| Attempt | public request, outputs, private-input projection | signed workload admission, disk hash, checker context, device key, fresh challenge |

A new task or base image does not require re-signing the app. Changing app or
native code, or the entitlements, changes the app identity and requires a new
App Attest enrollment.

## Trust

App Attest binds each assertion to a key that only the enrolled, signed app can
use. With SIP and the hardened runtime, no process on the Mac, root included,
can read the runner process, which holds the VM's memory. Physical memory probing
and kernel exploits are outside this model. Private inputs are staged
as plaintext disk files on the host.

The guest writes a compose receipt onto the result disk; the outer app produces
the two Apple assertions, one over the launch and one over the finalized result
envelope. An authentic run can report a failed workload; the verifier reports
evidence validity and task success separately.

## Reading the source along the path of one run

1. [`alpha_coordinator.py`](../applications/pilot-client/alpha_coordinator.py):
   release and workload signature checks, public disk validation, native policy.
2. [`V3Launch.swift`](../runner-vm/app-src/Sources/mar/V3Launch.swift): staging,
   VM lifecycle, evidence retention and the two assertions.
3. Guest [`supervisor`](../base-vm/browser-sandbox-v1/source/guest/supervisor-dstack-trixie.sh),
   [`compose runner`](../base-vm/browser-sandbox-v1/source/runner-content/dsmack_compose_runner/runner.py),
   [`receipting`](../base-vm/browser-sandbox-v1/source/runner-content/dsmack_compose_runner/receipting.py)
   and [`security contract`](../base-vm/browser-sandbox-v1/source/runner-content/lib/dsmack_compose_contract/security.py).
4. The [run-result verifier](../applications/pilot-client/verifier/README.md),
   which checks the retained evidence against an expected context.
