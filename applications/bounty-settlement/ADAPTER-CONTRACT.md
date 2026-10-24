# Acceptance adapter

`AcceptanceAdapter` (`acceptance-adapter.mjs`) turns the original signed
verifier reports of a ten-stage bounty attempt into an acceptance report. It
reads the original run-result report, receipt and exported file formats and
feeds them to the closed `bounty-judges/closure.py` join. It has no signing,
enrollment, replay or settlement authority of its own.

## Original report format

The reference source is `pilot-client/verifier-browser/runresult_ref/protocol.py`
and `schemas.py`. The schema is called `dsmack.runresult-report/3`, but the JSON
carries `runresult_report_version: 2` rather than a schema string. `report_sig`
is exactly `{alg,key_id,sig_b64}`; Ed25519 covers canonical JSON of the whole
report minus `report_sig`
(`contract-lib/dsmack_compose_contract/attestation.py:report_body`). The report
binds the manifest SHA, receipt SHA, native evidence/image, challenge, counters
and enrolled key. It has no application request, model, candidate or payee
fields; the adapter takes those from the admission.

Receipt `outputs.artifacts` entries are `{name,bytes,sha256}`; stdout/stderr are
separate commitments. `tools/prepare_app_evidence.py` lays retained evidence out
as `report.json`, `receipt.json`, `manifest`, `outputs/artifacts/NAME`,
`outputs/streams/stdout|stderr`. Checker stdout and
`AUTHENTICATED-BROWSER-DIAGNOSTIC.json` are not signed reports.

[fixtures/genuine-diagnostic/](fixtures/genuine-diagnostic/) holds the public
report, receipt and result envelope of the six-check diagnostic run. Its Ed25519
signature, expected subjects, raw receipt SHA (including the final LF),
receipt-evidence digest and native envelope digest all verify. Both receipt
environments are `vm`, Apple.environment is `production` and evidence_class is
`apple-hardware-assertion`. Its input commitment is null with signed
`commitment_status: absent`, so full acceptance refuses it, alone or next to nine
synthetic stages. The signing root is `0rs+/3i5MhAVbhkDtpngWfazI5CCVUXqGWlpKFZr8Q4=`
with ID `dsmack-root-demo-c01615dc-20261022`.

## Admission

The constructor takes a Store, a map of report key IDs to Ed25519 public keys,
and one immutable admission per attempt. Admissions are never created over HTTP
and must be identical across restarts. The coordinator fixes the policy, plan and
derivation recipe before the first model run, and each stage's request, run,
challenge, native base/launch closure, manifest, driver, image, source, profile
and input commitment before that stage runs. CI suite digests come out of
generation, so CI admissions are selected after the matching generation verifies.
The adapter checks the admission against the Store's task terms, policy,
attempt, nonce, candidate and payee.

An admission contains:

- `expected`: the `closure.join` expected object, including all ten `PINS` rows,
  requested model, plan, terms, attempt and base/candidate identity.
- `task`: Store fields `task_id`, `terms_sha256`, `checker_sha256`,
  `image_sha256`, `harness_sha256`, `attempt_id`, `nonce`, `payee`,
  `candidate_sha256`, `bundle_sha256`.
- `stages`: ten sorted rows `{stage_id, context, input_commitment, files,
  receipt_status, exit_code, input_slots, driver_sha256, driver_execution,
  native, output_bundle}`.
  - `context` pins verifier ID/version/key ID, the full verifier_context
    (including enrollment digest) and the expected manifest, selector,
    challenge, enrolled key and receipt environment.
  - `native` is the expected `{base_vm,base_vm_launch}` closure; both are
    nonempty objects and every nested field must match the receipt. A configured
    signer can attest other bases under the same manifest, so the base is pinned
    here rather than inferred from the manifest.
  - `driver_execution` pins the full split entrypoint/command arrays.
  - `input_commitment` is the scoped commitment from the public input audit. Its
    file-only digest is recomputed from the measured file bytes on every
    evaluation. It commits the public request/plan, stage profile, source, suite
    input and trusted driver.
  - `files` maps application output names (including `checks.json` and
    generation `suite.json`) to original artifact names. Membership is complete;
    streams cannot grade.
- `delivery`: primary-review artifact names of the source bundle and candidate
  manifest.

## Evaluation

`evaluate(attemptId, input)` takes the canonical public request and stage-results
bytes plus ten sorted stage records `{stage_id, reportBytes, receiptBytes,
manifestBytes, publicInputsBytes, outputs}`, where `outputs` maps
`artifact:NAME`/`stream:NAME` to Buffers. It checks the report signature and
production evidence class, each context, manifest and receipt digests, run ID,
driver, scoped input commitment, workload status/exit, the signed commitment
status and every delivered length and digest. Status `absent` refuses;
`recorded-unchecked` and `bound-to-validated-envelope` are accepted only after
the adapter recomputes the file-only commitment and matches it against both the
admission and the receipt. The report SHA is the stage's evidence digest in the
closed result. The fixture evidence class always refuses.

Verified outputs become application manifests that go to the Python join over a
private stdin protocol. The join executes the selected `closure.py` source bytes
directly, so a stale bytecode cache cannot change join logic. Only the join's
successful output produces the acceptance report and delivery bytes.

### Public input projection

`publicInputsBytes` is the canonical public file projection retained before the
stage runs: `{runtime_input_version:4,manifest_sha256,files,commitments}`, with
file rows `{slot,content_base64}` and commitments in `dsmack.task-commitment/3`.
The adapter rebuilds the payload `[alg,manifest_sha256,scope,{files:sorted_rows}]`
and checks canonical base64, slot membership, manifest declarations, read-only
workload audience, unique targets, read-only service mounts and that the single
stage service runs the measured driver. The projection has no env, stdin,
user-config or secret fields. The private VDE envelope is validated inside the
guest; the receipt's task3 commitment ties the workload files to this public
projection.

Generation may declare broker-only env names in `manifest.allowed_envs` and
`required_envs`; values never appear in the projection. Workload env inputs, broker
env on browser stages and broker file slots refuse. Every workload file must be
required and covered by the projection.

`driver_execution` must equal the manifest service's split arrays. Supported
entrypoints: `[/usr/bin/node]`, `[/usr/local/bin/node]`, `[/usr/bin/python3]`,
`[/usr/bin/python3,-I]`, `[/usr/bin/python3,-I,-B]`. The command starts with the
measured driver file target and the remaining arguments match exactly. Shell,
eval and cat forms refuse.

`input_slots` maps the purposes `request`, `task_terms`, `acceptance_profile`,
`plan`, `stage_profile`, `driver`, `source_manifest`, `source_bundle`, `suite` to
distinct generic slots. Suite is null for generation and primary; for base and
candidate its SHA must match the closed results and the generation output. The
other purposes are required. Terms, profile, plan, stage profile and driver bytes
match the admission; the source manifest and archive reconstruct the expected
base or candidate tree. Extra public files refuse, including candidate or
other-judge files in generation.

The primary request is `dsmack-bounty-public-request/1`. A generation stage
profile includes `specification:{text,sha256}` with nonempty bounded text whose
UTF-8 SHA-256 matches. The native wrapper audits the child request and builds the
two-file generator or four-file browser projection; primary S0 uses its full
public-input audit. Child stages use `dsmack-bounty-child-request/1`, whose exact
fields are in `measured-inputs.mjs`: task/policy/plan, attempt/nonce/payee/model,
stage role/index/run/profile/image/source and input suite. Its domain digest
matches the per-run request digest. Generation requests carry the base source only.

The native runner must validate and consume optional file-only task commitments
for these projections; base8eea rejects commitments on its public-files path.

### Stage outcomes

A base stage needs a signed receipt of failed / exit 1 plus CI output showing the
browser started and completed, no infrastructure failure, and nonempty terminal
tests with at least one assertion failure. A signed completed/exit 0 base refuses
whatever its checks say. Every other stage needs completed/exit 0.

### Source delivery

The delivered bundle is raw uncompressed USTAR: regular files only, ASCII sorted
paths, mode 0644/0755, no PAX/GNU extensions, links, directories or special
files, exact source-manifest membership/bytes/modes and two trailing zero blocks.
Report, certificate and delivery sidecars cannot appear outside the source
manifest.

After all stages authenticate, the adapter recomputes the base-to-candidate
relation (transform/2) from the base-1 and primary-review source manifests. The
primary stage profile carries `admission_transform:{record,sha256}` whose digest
matches the pinned primary request. Version 2 allows only content replacements
of existing files in the three fixed board paths, with identical membership and
modes and a complete nonempty changed-file list. The coordinator runs the same
comparison before admitting stages.

### Output bundles

Each stage admission has `output_bundle`; direct mappings use `null`. The full
browser profile selects:

```
{"schema":"dsmack-flat-result-ustar/1","artifact":"result-files","manifest":"output-manifest.json","duplicates":{"stage-checks":"checks.json","public-input-audit":"public-input-audit.json"}}
```

The report, receipt, native manifest and all native output bytes are
authenticated before the archive is decoded. Native artifacts are exactly
`result-files`, `stage-checks`, `public-input-audit`, plus the stdout/stderr
streams. The archive holds sorted flat regular files and the canonical
`output-manifest.json`, which excludes itself and the archive. Both duplicate
exports must equal their archived copies.

The decoder requires exact USTAR headers, mode 0644, zero ownership, time and
extension metadata, valid checksums, ASCII names, zero padding and two
terminating zero blocks; it never extracts to the filesystem. Links, directories,
extended headers, alias paths, duplicates, unlisted or missing files refuse.
Bounds: 16 MiB per native archive (headers, manifest and padding included), 256
members, 64 MiB across all logical stage results, 64 logical files per stage. Over
a bound is a refusal.

For bundled stages, `stage.files` maps each logical name to the same archive
member name, excluding `output-manifest.json`. The manifest bytes are rebuilt from
the authenticated logical file sizes and hashes. Acceptance and source delivery
read these expanded bytes; `original.outputs` and the receipt are never modified.
The primary request's `required_artifacts` names the three native exports; its
delivery selectors name the logical source bundle and candidate manifest members.

## Admission schema v2

The operator selects `dsmack-bounty-acceptance-admission/2` before execution. It
keeps every signature, context, challenge, base/boot, task3, source, request and
ten-stage uniqueness check. Admissions without a schema keep their receipt-ID,
binary-harness and task-OCI semantics.

In v2 the paid task image is the base VM OS image, and each stage OCI is its own
pin, matched against its measured request and compose image. Projection takes the
image mapping from the admission.

For the pinned d9 producer, receipt IDs are
`guest-<authenticated manifest selector>-<canonical positive Linux PID>`, PID at
most 4194304. The ID names the producer record; stage assignment comes from the
planned run ID in the authenticated task3 public request.

The paid harness commitment hashes canonical raw HARNESS-CLOSURE bytes, which
commit the recipe inventory, platform, role OCI, CLI, settings and drivers. All
ten stages use the measured driver `applications/bounty-runtime/driver.py`,
present in both inventories. The native harness binary is checked against the
manifest. Model identity is the requested ID; the provider does not sign it.

## Certificate and HTTP

`evaluate` returns canonical acceptance-report and delivery bytes and closure
digests. An application signer produces the certificate over the report hash.
`admit(attemptId, input, certificate)` re-evaluates the evidence and checks that
hash and the configured signer before the Store verdict gate. The Store's first
`verdict_received_at` stays fixed across retries, expiry and restarts, so a stale
certificate cannot gain first admission.

`createAcceptanceApplication` routes the operator-only `/verdict` endpoint through
the adapter. A local `loadInput(attemptId)` supplies the retained bytes; HTTP
bodies cannot name paths, trust roots, expectations or child evidence.
