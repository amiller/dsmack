# Development

How the repository is divided, how work is tracked, and how each part is released.

## Streams

| Stream | What it is | Paths | Released as |
|---|---|---|---|
| **Platform** | What a third party checks: the Mac app, the Linux image it boots, the guest API, App Attest verification and the evidence formats | see below | `vX.Y.Z` ([versioning](versioning.md)) |
| **Network** | Macs serving guests to browsers: pool, broker, payments, Mac ownership, egress, directory | `applications/{compute-node,relay-broker,payments,mac-ownership,egress-policy,egress-relay,libp2p-attest,browser-p2p}`, `contracts/payments`, `contracts/src/UsageEscrow.sol` | with the app that deploys it |
| **Apps** | Products built on the platform and network | `applications/{private-agent-web,private-agent-artifacts,agent-turns,bounties,coordinator}`, `contracts/work-escrow` | own tags, e.g. `private-agent-v0.4.0` |
| **Ops** | Monitoring, dashboards, deploy tooling | `applications/{network-dashboard,operator-fleet,bounty-dashboard,pilot-client}`, `tools/` | not versioned |

Apps pin the platform release they run on. Workloads (OCI containers) belong to
the app that uses them and are named by digest.

### Platform areas

Each area has its own identity, and changing one does not force a new version of the
others.

| Area | What it is | Paths | Identity | Breaking when |
|---|---|---|---|---|
| **Runner** | DsmackRunner: Swift app and its libkrun/Apple Hypervisor backend | `runner-vm/`, `tools/release/` | code signature (Team ID, bundle ID, cdhash) | it is re-signed: every Mac re-enrolls |
| **Base image** | Linux kernel, initramfs, verity root, container runtime, task start and result export | `base-vm/` | image hash in the signed release inventory | an admitted image is dropped from the inventory, or the task interface changes. Adding an image is not breaking |
| **Guest API** | dstack's guest API v1 on `/var/run/dstack.sock`, so one compose file runs on dstack and on a Mac | `dstack-compat/` | API version | a call or response changes |
| **Attestation** | App Attest verification in Solidity and Noir, the approved-code and key registries, Apple's root | `app-attest/`, `contracts/src/AppleAttestRegistryV1.sol`, `contracts/src/CDRegistry.sol`, `trust/` | contract address, circuit | an address or interface changes |
| **Evidence** | Statement, receipt, envelope and signed report, and the Python verifier that reads them | `verifier/` | format name and number, e.g. `dsmack-general-launcher/v3-run-statement/1` | the verifier rejects evidence an older release wrote |

## Issues

Issues go in this repository.

Labels exist to route a decision, not to describe an issue:

| Label | Meaning |
|---|---|
| `platform:runner`, `platform:base-image`, `platform:guest-api`, `platform:attestation`, `platform:evidence` | Which platform area, and so which release |
| `network`, `app:private-agent`, `app:bounties`, `ops` | Which stream |
| `trust-boundary` | Touches the attestation chain, a verifier, a contract or guest evidence. Needs a careful review |
| `breaking` | Collects on the next minor platform release. The issue answers the questions in [versioning](versioning.md#proposing-a-breaking-change) |
| `blocked` | The comment that applies it says what it waits on and gives a re-check date |
| `feedback` | Filed from user feedback or a trace |
| `research` | An investigation, not yet a committed change |
| `epic` | Groups other issues |

`bug`, `enhancement`, `documentation`, `good first issue` and `help wanted` keep their
GitHub meanings.

Milestones are releases or sprints, for example `Platform v0.2.0`.

## Decisions

Design decisions are recorded in [decisions/](decisions/README.md), one short file
each. A decision that changes an earlier one names it in `builds-on` and marks the
old one superseded.

## Releases

A release starts as an issue from a checklist template:

- **Platform:** [release-platform](../.github/ISSUE_TEMPLATE/release-platform.md),
  following [releasing](release/releasing.md).
- **App:** [release-app](../.github/ISSUE_TEMPLATE/release-app.md): staging deploy,
  browser journeys, tag, live testnet deploy, Mac pool restart, health checks.

The closed release issue is the record of the release.
