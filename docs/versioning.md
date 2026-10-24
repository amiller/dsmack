# Versions and compatibility

A Dsmack run is built from layers that change at different speeds. Each layer has
its own identity, and changing one should not force a new version of the others. A
new container image for the bounties application does not need a new base image, and
a new base image does not need a new Mac app.

## The layers

| Layer | What it is | Identity | Who decides a change |
| --- | --- | --- | --- |
| Mac app | DsmackRunner: Swift app plus the Rust/libkrun VM backend linked into it | code signature (Team ID, bundle ID, cdhash) | a Dsmack release |
| Base image | Linux kernel, initramfs and verity root the app boots | image hash, admitted by the signed release inventory | a Dsmack release |
| Workload | the OCI container a task runs, e.g. the bounties browser checker | image digest, named in the task | the application |
| Application | services on the pod (bounties, dashboard) and their HTTP APIs | git commit of the deployed tree | the application |
| Contract | on-chain escrow and registries | address | a new deployment |
| Evidence | statement, receipt, envelope, signed report: what the verifier reads | format version in each document | a Dsmack release |

A layer's identity is a hash or address, not a version number. Version numbers are
for people: they name a set of identities that were released together.

## Releases

One tag for the repository: `vX.Y.Z`. A release ships the Mac app, the base images it
admits, and the verifier that reads its evidence. Workloads, applications and
contracts are not released with Dsmack; they pin the Dsmack release they need.

Before 1.0, a minor bump (`v0.2.0`) may break things and a patch bump (`v0.2.1`)
does not. After 1.0, only a major bump breaks.

Re-signing the app changes its identity, so every Mac re-enrolls. That is the most
expensive change and the main reason to batch breaking changes into one release.

## What counts as breaking

A change is breaking when something already out there stops working or reads
something different:

- the verifier rejects evidence an older release produced;
- an enrolled Mac has to re-enroll;
- a deployed application, or a published task, no longer runs on the new release;
- a contract's interface or address changes.

Adding an optional field, a new task, a new workload or a new base image to the
inventory is not breaking.

## Evidence formats

Each kind of document carries one format name and number, for example
`dsmack.statement/1`. Bump the number only for a breaking change to that document.
A release states which format numbers it writes and which it reads.

The verifier reads the formats of the current release and the one before. To check
older evidence, use the verifier from the release that produced it. The signed
workload admission in every run records the release inventory hash, each release
publishes its inventory, and tags never move, so the release is always findable.
That keeps the verifier from accumulating compatibility code.

## Proposing a breaking change

Open an issue labelled `breaking` that answers:

1. What changes, and which layer.
2. What stops working: published evidence, enrolled Macs, deployed apps, contracts.
3. The migration: what each affected party does, and when.
4. Whether the old path is kept for one release, or dropped.

Breaking changes collect on the next minor release. Decide them together when that
release is cut, so Macs re-enroll once.

## Next release: v0.2.0

Collected so far:

- Run evidence no longer carries the `honesty` block. The v0.2 verifier stops
  accepting it.
- The base image's receipt note and `image_admission.py` docstring drop the stale
  host-root wording. This changes the base image hash.
- `verify.py` takes no `--source-manifest-sha256` or `--environment-sha256` flags.
- The ~80 format names, mostly at versions 1 to 4 with their history in the
  number, restart at `/1` under v0.2, and are merged where two names describe the
  same document.
- Tags: drop the per-component series (`runner-v…`, `native-v…`, `arcade-browser-v…`,
  `node-v…`) in favour of `vX.Y.Z`. The browser checker image is a workload and is
  published by digest only.
- Add the release-inventory writer to the repo; today only the checker is here.
