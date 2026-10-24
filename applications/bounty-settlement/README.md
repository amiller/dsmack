# Bounty settlement

Joins the ten original stage proofs of a bounty attempt into an acceptance
decision and projects it onto the WorkEscrow contract.

- `acceptance-adapter.mjs` verifies each original signed verifier report against
  configured report keys and stage contexts, authenticates receipts and output
  bytes, checks source delivery and the base-to-candidate relation, and runs the
  ten-stage join. [ADAPTER-CONTRACT.md](ADAPTER-CONTRACT.md) defines its API.
- `acceptance-service.mjs` / `serve-acceptance.mjs` serve that adapter on the
  `bounty-demo` HTTP application.
- `projection.mjs` maps an accepted certificate to an unsigned escrow submission
  and EIP-712 v2 proposal (`packageHash`, `policyHash`, `candidate`, `evidence`,
  `delivery`).
- `chain-observation.mjs` / `chain-service.mjs` read task funding, assignment,
  resolution and withdrawals for the WorkEscrow runtime on Base Sepolia.
- `construct-admission.mjs` builds the per-attempt admission (below).

## Acceptance service

```sh
node applications/bounty-settlement/serve-acceptance.mjs /absolute/config.json BYTES SHA256
```

The config (`dsmack-bounty-acceptance-service/1`) has keys `schema, state_path,
operator_token, verifier_keys, report_keys, admissions, evidence, repositories,
port`. `verifier_keys` maps certificate key IDs to public PEMs; `report_keys`
maps report key IDs to base64 raw 32-byte public keys. `evidence` maps attempt
IDs to `{path,bytes,sha256}` descriptors of a `dsmack-bounty-original-evidence-files/1`
document (`request`, `results`, and ten `originals` stages with `report`,
`receipt`, `manifest`, `public_inputs`, `outputs`). The server binds 127.0.0.1.

## Admission construction

`construct-admission.mjs` builds one `{pin,stage}` selection per execution from
public prework, then assembles the ten-stage admission. It reads only
root-selected descriptors from protected paths, never a returned report or
receipt. The config SHA is required:

```sh
node applications/bounty-settlement/construct-admission.mjs capture /absolute/capture-config.json CONFIG_SHA /absolute/fresh-stage-output
node applications/bounty-settlement/construct-admission.mjs assemble /absolute/assembly-config.json CONFIG_SHA /absolute/fresh-admission-output
```

Run it under Node 24 with no preloaded Node modules. Output namespaces are
exclusive; keep a refused namespace instead of retrying into it.

A `dsmack-held-stage-construction/1` capture config has exactly `schema`,
`stage_id`, `prelaunch`, `request`, `manifest`, `projection`, `checker`,
`image_manifest`, `launcher_policy`, `base_admission`, `qualified_base`,
`profile`, `inventory`, `enrollment`, `logical_artifacts`, `suite_selection`.
File inputs are `{path,bytes,sha256}` descriptors. The constructor derives the
input slots and driver command, recomputes public commitments and checks source
delivery. `qualified_base` is the selected base record; the boot tuple is derived
from its image, command line and base-admission bytes. The admitted policy image
picks the D9 or B44 receipt-producer mode. Baseline outcomes are failed/1; every
other role is completed/0.

`suite_selection` is null for generation and primary review. For base/candidate
it holds descriptors `generation_selection`, `generation_request` and
`authority`. `authority` is a root-selected `dsmack-root-selected-generated-suite/1`
record with exactly `schema`, `stage_id`, `run_id`, `request_sha256`,
`suite_sha256`, `generation_selection_sha256`, `evidence_audit_sha256`, created
after the GEN proof and strict-suite audit pass. The constructor binds it to the
GEN request, judge, planned run, task, nonce, policy, plan, selection digest and
suite bytes, and re-runs the strict suite grammar. The acceptance operator still
authenticates every GEN proof.

Order: freeze generation selections, authenticate the generated suites, then
freeze base/candidate selections before those jobs run. Primary can freeze at any
point. A completed GEN can be reconstructed from its prelaunch bytes; provenance
records the actual construction time.

A `dsmack-ten-stage-admission-construction/1` assembly config has exactly
`schema`, `operator`, `code_root`, `template`, `selections`, `report_keys`,
`operator_config`. `operator` pins the acceptance operator; `template` pins the
public task/attempt/harness/recipe/delivery template; `selections` lists ten
descriptors ordered base1..3, candidate1..3, generate1..3, primary-review. The
assembler calls the operator's `combineAdmission` and then the `AcceptanceAdapter`
constructor on the result. Missing stages, duplicate runs/challenges, wrong base
outcomes, wrong image policy or an invalid harness closure refuse. The operator
reads the Store task and attempt at evaluation time and compares the subject.

`operator_config` has exactly `schema`, `state_path`, `attempt_id`, `request`,
`originals`, `certificate_key_id`, `certificate_public_key`,
`certificate_private_key_path`, with all ten original evidence descriptors; the
constructor opens neither private keys nor the Store. Output is canonical
`admission.json`, `operator-config.json` and a provenance record of every input
descriptor.

## Local rehearsals

```sh
# Anvil escrow rehearsal: settlement, duplicate resolution, withdrawal, timeout refund.
forge build --root contracts/work-escrow --offline
node applications/bounty-settlement/rehearse-local.mjs contracts/work-escrow/out/WorkEscrow.sol/WorkEscrow.json /new/output-directory
# HTTP walkthrough of the acceptance service with synthetic stage proofs.
node applications/bounty-settlement/walkthrough-local.mjs
```

`rehearse-local.mjs` needs `cast` and `anvil` on PATH (or `DSMACK_CAST`,
`DSMACK_ANVIL`).

## Tests

```sh
node --test --test-isolation=none applications/bounty-settlement/*.test.mjs
python3 -m pytest applications/bounty-settlement
```
