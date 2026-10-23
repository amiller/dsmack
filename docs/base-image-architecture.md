# Base image, workload and execution proof

For one task and its proof, start with the [Mac handoff](pilot/operator-assisted-mac.md#one-task-and-its-proof).
This guide describes the selected VM-runner source in this checkout. Binary
availability and host qualification are separate release facts. The older
[`runner/`](../runner/README.md) Containerization/Virtualization implementation is
a separate design. Its kernel, proxy and memory-isolation claims do not describe
the current [`runner-vm/`](../runner-vm/README.md) implementation.

## What runs where

```text
Mac: signed Swift app + native libkrun/HVF backend
  └─ Linux ARM64 VM: measured kernel, initramfs and verity-protected base
       └─ guest supervisor + Docker/compose runner
            └─ selected OCI workload + declared inputs → bounded outputs
Mac: retained original launch/result evidence → independent Linux verifier
Application: task acceptance, delivery and optional settlement
```

HVF is Apple's Hypervisor.framework. macOS is the host; the selected guest is
Linux, not a separate macOS VM for each task.

The current B44 reference is a separately measured, dstack-derived Debian ARM64
base. It supplies the guest supervisor, Docker/compose execution, input/output
transport and broker infrastructure. B44 is the broker-timeout derivative of an
earlier base, not a Claude model or a Mac app identity. Its [source recipe](../base-vm/broker-timeout-v1/README.md)
and [parent base](../base-vm/browser-sandbox-v1/README.md) describe that lineage.
The Claude CLI, browser tests or another application belong in separately selected
OCI container images and harnesses. Several workloads can use the same base and
signed app.

The current device contract separates the system disk (`vda`), ephemeral working
disk (`vdb`), public workload disk (`vdc`) and result disk (`vdd`); an explicitly
admitted private-input route is separate. The workload disk carries the selected
OCI payload, compose manifest and public context. The guest validates its admitted
contents before execution. Credential-free browser profiles consume declared public
files with network disabled. Selected coding profiles use a separate private input
and broker route. These are different admitted policies, not ambient host settings.

## Flexible selections, exact bindings

| Layer | What may change through a supported selection | What must remain bound |
| --- | --- | --- |
| Signed Mac app | A workload can change without rebuilding the app | App/native executable, signing identity, entitlements and accepted enrollment |
| Linux base | A new kernel, rootfs or guest service revision | Measured image identity, kernel/initramfs, verity root and admission policy |
| OCI workload | Application, harness, entrypoint and declared files | OCI digest, compose-manifest digest and permitted security/network/resource profile |
| Attempt | Public request, outputs and permitted private-input projection | Signed workload admission, disk hash, closure/checker context, device key and fresh challenge |

The packaged alpha accepts closed signed profiles; it is not an arbitrary compose
or resource override interface. For example, its current coordinator selects
4 GiB RAM, one vCPU and a 600-second VM limit. A different supported selection needs
its corresponding review, measurements and admissions. Changing app/native code or
signing changes the app identity and requires its own qualification. Choosing a
different admitted task or Linux base does **not** inherently require re-signing
the Mac app. See [the runtime contract](pilot/alpha-runtime.md).

The roughly 611 MB per-attempt browser workload copies used in rehearsals are a
current packer/staging choice, not an architectural requirement to clone an entire
VM for every task. Artifact reuse or delta transfer must still preserve immutable
inputs, exact destination hashes and the declared disk/resource contract. Existing
commands and disk-space checks remain authoritative until an alternative is
implemented and qualified.

## Audit the path to a proof

1. Start at [`runner-vm/README.md`](../runner-vm/README.md) and its explicit source
   derivation check. Source hashes, binary correspondence, Apple distribution and
   fresh-host qualification are separate checks.
2. Read [`alpha_coordinator.py`](../applications/pilot-client/alpha_coordinator.py)
   for release/workload signature checks, full public-disk validation, input paths
   and derived native policy. Follow [`V3Launch.swift`](../runner-vm/app-src/Sources/mar/V3Launch.swift)
   into the native backend for actual staging, VM lifecycle and retention.
3. Inspect the guest [`supervisor`](../base-vm/browser-sandbox-v1/source/guest/supervisor-dstack-trixie.sh),
   [`compose runner`](../base-vm/browser-sandbox-v1/source/runner-content/dsmack_compose_runner/runner.py)
   and [`security contract`](../base-vm/browser-sandbox-v1/source/runner-content/lib/dsmack_compose_contract/security.py),
   then the selected OCI recipe and application checker. The guest receipt is
   not itself an Apple attestation. The outer app produces distinct launch and
   result assertions; the result assertion binds the finalized result envelope.
4. Preserve the original evidence and use the independently selected
   [full verifier](../applications/pilot-client/verifier/README.md) with held
   context and enrollment/replay authority. A model message, guest JSON or
   controller exit alone is not an execution proof.

An authenticated execution can report a failed workload. Matching an expected
outcome is distinct from application acceptance; neither establishes payout.
The current host is trusted for plaintext private inputs: App Attest does not
promise secrecy from its owner/root. Cleanup follows evidence preservation and
confirmed VM/helper quiescence, as described in the [participant guide](pilot/newcomer.md#disk-space-and-cleanup-after-each-run).
