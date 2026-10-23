# dsmack

dsmack runs a selected Linux workload on a Mac and retains independently checkable
App Attest evidence about its launch and result. **Start with one operator-admitted,
credential-free task:** [the Mac handoff guide](docs/pilot/operator-assisted-mac.md#one-task-and-its-proof)
names the existing prepare/check/execute commands, proof files and Linux offline
check. A coding-agent subscription and a bounty payout are separate concerns.

This checkout supplies source, not a ready-to-run invitation. An operator must
provide the authenticated release, fresh device enrollment and admitted task.
A friend-ready download and a normally secured fresh-Mac first-open remain
qualification gates. Do not import a subscription merely to inspect this repo.

Inspect the selected app source without building or launching anything:

```sh
python3 runner-vm/source_check.py \
  --source-derivation-sha256 55f235c383e7312f96b862bfdd0709cb7f5f16001691eb29699ec2f1d5106178
```

The [illustrated architecture guide](docs/base-image-explainer.html) and
[source audit guide](docs/base-image-architecture.md) explain the
Mac app, Linux base and OCI workload boundaries and gives an agent a source audit
route. [The participant guide](docs/pilot/newcomer.md) covers the optional bounty
claim/reconnect/delivery flow. The website does not connect to or launch your Mac.

## Selected-source export scope

A minimal source archive is an explicit subset of this development repository.
Its file manifest is authoritative: it contains runner source, selected base and
workload recipes, participant inspection/claim tools and their declared local
dependencies. The broader repository map below also describes components that
may be omitted: root `verifier/`, `app-attest/`, `runner/`, `experiments/`, `trust/`
and contract projects. Only `contracts/cd_args.py` is needed by the included
runner inspection tool. Omitted project build/test commands are not runnable
from the selected archive. Private operator services, release keys, enrollment
authority, task inputs, model credentials and binary dependencies must never be
inferred from source inclusion.

## What is implemented

[`runner-vm/`](runner-vm/README.md) contains the selected generic app3 Swift and
libkrun/HVF native implementation. It consumes a pinned VM image and workload
inputs, retains launch and result assertions and records the evidence needed by
a full application verifier. VM image releases and workload/harness configuration
are separate from the signed application. The source import has passed a native
cross-build and a fresh unsigned Mac build; those outputs have their own
identities. Separately assembled app identities have completed actual signed
execution and Developer ID distribution checks. See the dated status below;
qualification of one binary does not transfer to a rebuilt binary.

[`applications/bounty-demo/`](applications/bounty-demo/README.md) provides the
prototype task board, durable claims and evidence-submission API.
[`applications/pilot-client/`](applications/pilot-client/README.md) delegates to a
separately selected protected coordinator and journals local launch attempts.
A successful controller exit is not task acceptance; acceptance is not a received
payment. The browser cannot assign either verdict itself.

A historically qualified, separately assembled signed Mac runner completed an
actual Claude coding task and full evidence verification. That result does not
qualify a newly rebuilt binary, a different VM profile, an arbitrary Mac or a new
application's acceptance conditions. Source checks and synthetic application or
local-chain tests are useful evidence with narrower scope.

## Trust and distribution boundaries

App Attest evidence binds an admitted app identity and protocol data. It does
not prove a workload is correct, a credential is safe to disclose, an output is
available indefinitely or a payment was received. A full run check also needs
the independently selected image/workload, original retained bytes, native and
guest evidence, enrollment/replay state and the application's immutable checker.
`verifier/` supplies Apple verification components; it is not, by
itself, the portable full VM-result verifier or a deployed settlement service.
The [full Linux VM-result verifier package](applications/pilot-client/verifier/README.md)
relocates the v3-aware consumer with source/dependency pins and a namespace
extraction boundary. Its local doctor/import controls and preparation of the
historical retained output passed; fresh production verification and deployment
authority remain separate qualification steps.

**Do not assume confidentiality from the Mac's owner.** The current pilot uses a
trusted host for private-input staging and plaintext VM disk files. Credential
exposure and networking differ by explicitly selected harness/profile. App Attest
alone is not a general encrypted-VM boundary or proof that host root cannot see
private inputs. Native helpers and external tools remain part of the selected
execution and verification configuration.

## Release status — 22 October 2026

The [public explainer](https://amiller.github.io/dsmack/) describes the architecture
and inspection journey. This checkout contains the selected VM-runner source;
its signed starter download and qualification records are separate release assets.
Until a runner alpha prerelease is available, the older `node-v0.3.0` download is
not a substitute for this application. See the [operator-assisted handoff](docs/pilot/operator-assisted-mac.md).

A selected Developer ID Application build has passed independent signature,
code-page, stapled-ticket and macOS distribution checks. Its provisioning profile
permits all devices; ordinary participants do **not** need to register each Mac.
The final exported app also completed fresh production App Attest enrollment
with certificate category 6. Certificate category and App Attest environment are
separate fields. The [participant guide](docs/pilot/newcomer.md) records its exact
identity and remaining limits.

The final notarized identity has executed authenticated workloads on the existing
Apple silicon Mini, including private subscription import and retained full
verification. One operator-assisted bounty journey has also completed acceptance
and a received Base Sepolia testnet reward, alongside a refund journey. The
second earned payout and a fresh friend's installation remain incomplete.
These are separate gates from signature and VM execution checks. The
qualification Mac had global Gatekeeper assessments disabled; direct distribution
assessment passed, but a quarantined first-open journey remains unqualified.
The reviewed [alpha staging source](docs/pilot/alpha-install.md) authenticates and
stages a selected release; it does not grant launch readiness by itself.

Before an actual trial, obtain the reviewed release inventory and trust root,
source/build correspondence, selected base/container identities, supported host
requirements and resource/egress plan. The [release runbook](docs/release/runner-release.md)
keeps these gates separate. Never bypass Gatekeeper or copy a maintainer's
private keys to try the app.

## Repository map

| Path | Role |
|---|---|
| [`runner-vm/`](runner-vm/README.md) | Selected generic Swift app and libkrun/HVF source; build adapters and source provenance |
| [`base-vm/`](base-vm/browser-sandbox-v1/README.md) | Independently configured Linux base source and guest/runtime profiles |
| [`applications/pilot-client/`](applications/pilot-client/README.md) | Invited-participant local CLI and launch journal |
| [`applications/bounty-demo/`](applications/bounty-demo/README.md) | Task board, invitation/claim and submission prototype |
| `verifier/` | Apple App Attest verification components |
| `app-attest/` and [`contracts/`](contracts/) | Attestation and build-registry contracts; not proof that the pilot is live on-chain |
| `runner/` | Earlier Containerization/Virtualization runner and proxy experiments; a different implementation |
| `experiments/` | Recorded probes and bounded experiments |
| `trust/` | Apple trust material |

The earlier `runner/` design's kernel pins, proxy behavior and memory-isolation
arguments must not be inferred to apply to `runner-vm/`. Read the selected code
and profile before trusting a claim. Contribution instructions are in
[CONTRIBUTING.md](CONTRIBUTING.md).
