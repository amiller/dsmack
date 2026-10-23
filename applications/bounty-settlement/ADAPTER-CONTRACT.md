# Retained genuine-report acceptance adapter (review candidate)

This is a new application adapter API for review, not a production wire-format
claim or qualification of the current diagnostic. It reuses the original
run-result report, receipt and exported file formats and the existing closed
`bounty-judges/closure.py` join. It does not run operator verify, open replay or
signing authority, enroll a key, sign reports, or change settlement semantics.

## Observed source interface and actual-artifact qualification

The selected source in `pilot-client/verifier-browser/runresult_ref/protocol.py`
and `schemas.py` calls its report `dsmack.runresult-report/3`, but the actual JSON
has **`runresult_report_version: 2`**, not a schema string. `report_sig` is exactly
`{alg,key_id,sig_b64}`; Ed25519 covers canonical JSON of the whole report except
`report_sig` (`contract-lib/dsmack_compose_contract/attestation.py:report_body`).
The report binds the original manifest SHA, receipt SHA, native evidence/image,
challenge, counters and enrolled key. It does not contain application request,
model, candidate or payee fields. Those must never be guessed from report names.
The original receipt's `outputs.artifacts` entries are `{name,bytes,sha256}`;
stdout/stderr are separate commitments. The retained layout produced by
`tools/prepare_app_evidence.py` is `report.json`, `receipt.json`, `manifest`,
`outputs/artifacts/NAME`, `outputs/streams/stdout|stderr`. Checker stdout and
`AUTHENTICATED-BROWSER-DIAGNOSTIC.json` are not signed verifier reports.

The parent supplied the original public bytes after sandbox SSH failed. The
unchanged public report/receipt/result-envelope are retained as
[acceptance-negative fixtures](fixtures/genuine-diagnostic/README.md). Their real
Ed25519 signature, independent expected subjects, raw receipt SHA (including the
original final LF), receipt-evidence digest and native envelope digest pass
read-only controls. **Both receipt environments are `vm`; Apple.environment is
`production` and evidence_class is `apple-hardware-assertion`.** Nothing is
relabelled as `mac-attested`. The original diagnostic has null input commitment
and signed `commitment_status: absent`; full acceptance refuses it, even alongside
nine synthetic child stages. Media/output bytes were not supplied in this public
reference, so this does not repeat their verification or full Apple/image checks.
The selected public root is `0rs+/3i5MhAVbhkDtpngWfazI5CCVUXqGWlpKFZr8Q4=` with
ID `dsmack-root-demo-c01615dc-20261022`. It is not a default operational authority.
No private state or keys were read and operator verification was not rerun.

## Trusted admission and closed evidence input

`AcceptanceAdapter` is constructed with a Store, a configured map of original
report Ed25519 public keys, and per-attempt immutable admissions. There is no
HTTP operation to create or replace an admission. The trusted coordinator must
admit the complete immutable policy/plan and derivation recipe **before the first
model run**. It selects each stage's distinct request/run/challenge, exact native
base/launch closure, manifest, driver, image, source, profile and input commitment
**before that stage executes**. CI suite bytes/digests are outputs unknown before
generation: select CI admissions only after genuinely verifying the corresponding
generation, using the frozen recipe. Never retrofit a changed plan or suite into
an already selected/executed CI request. The constructor receives the final
complete ten-stage admission snapshot for acceptance; it is not an orchestrator
or independent proof of when those upstream selections were made. Stage requests
and manifest hashes are not derived from evidence supplied by the worker. The adapter checks its
admission against the Store's task terms, policy, attempt, nonce, candidate and
payee. Admission must be retained identically across restarts.

The local constructor admission contains:

- `expected`: the existing `closure.join` expected object, including all ten
  `PINS` rows, requested model, plan, terms, attempt and base/candidate identity.
- `task`: exact Store fields `task_id`, `terms_sha256`, `checker_sha256`,
  `image_sha256`, `harness_sha256`, `attempt_id`, `nonce`, `payee`,
  `candidate_sha256`, `bundle_sha256`.
- `stages`: ten sorted rows `{stage_id, context, input_commitment, files,
  receipt_status, exit_code, input_slots, driver_sha256, driver_execution, native}`.
  `context` pins verifier ID/version/key ID, complete
  verifier_context (including enrollment digest), and expected subject's manifest,
  selector, challenge, enrolled key and receipt environment. `native` is the exact
  independently selected `{base_vm,base_vm_launch}` expected closure. Both must
  be nonempty objects and every nested field must match the authenticated receipt.
  A legitimate configured signer can attest other bases under the same manifest;
  the manifest alone is not application base admission. Apple production/hardware
  evidence is a separate predicate from selected base/category policy.
  `driver_execution` independently pins complete split entrypoint/command arrays.
  `input_commitment` is the exact original scoped commitment admitted by the independent public
  input audit; its file-only digest is independently recomputed from actual
  measured declared file bytes on every evaluation. A hash/audit JSON is not
  source proof.
  It must commit the complete public request/plan, stage profile, source, suite
  input and trusted driver. This adapter does not invent a native input layout
  or authorize an audit result supplied by the worker. `files` maps canonical
  application output names (including `checks.json` and generation `suite.json`)
  to original artifact names. Full membership is required; streams cannot grade.
- `delivery`: original artifact names in primary-review for the source bundle
  and candidate manifest. The adapter also checks actual source file bytes from
  that bundle using the bounded uncompressed USTAR subset documented below.

This constructor object is a **local trusted API**, not an external accepted
production packet. No `approved:true`, `verified:true`, authenticated handle,
callback claiming success or controller exit can substitute for a signed report.
A caller capable of replacing trusted admission or configured trust roots is an
application authority. Review the actual coordinator admission implementation
and input audit before deploying this adapter. This patch supplies no policy
approval, native stage driver, model suite qualification or funding authority.

`evaluate(attemptId, input)` takes original canonical public request and closed
stage-results bytes, plus ten sorted original-stage records. Each record has
`stage_id`, original `reportBytes`, `receiptBytes`, `manifestBytes`,
`publicInputsBytes`, and an exact
map `outputs` of `artifact:NAME`/`stream:NAME` to Buffer bytes. It verifies the
configured report signature and production evidence class, each independent
context, manifest and receipt digests, run ID, driver and scoped input commitment,
workload status/exit, the original signed commitment status,
and all delivered byte lengths/digests. `absent` refuses. `recorded-unchecked`
or `bound-to-validated-envelope` is not treated as proof of public input contents:
the adapter independently validates/recomputes the file-only commitment and
compares it to both the admitted commitment and authenticated receipt. Report SHA is the
stage's original evidence digest in the closed result; retries retain those
original report bytes. A report for the six-check diagnostic cannot supply the
required ten stages or primary checks. Fixture evidence class is always refused.

## Measured public files and native gate

`publicInputsBytes` is a canonical **PUBLIC FILE PROJECTION** retained before
that stage executes, using the existing contract's
`{runtime_input_version:4,manifest_sha256,files,commitments}` shape. File rows are `{slot,content_base64}`; commitments use the existing
`dsmack.task-commitment/3` algorithm. The adapter reconstructs its payload
`[alg,manifest_sha256,scope,{files:sorted_rows}]` and checks actual canonical
base64 bytes, exact slot membership, manifest declarations, required read-only
workload audience, unique targets, read-only service mounts and direct selection
of the measured trusted driver in the single admitted stage service. The exact
projection object is `{runtime_input_version,manifest_sha256,files,commitments}`
with no env/stdin/user-config/secret fields. It is **never** the private VDE raw
envelope, and this adapter neither reads nor exports that private original. The
genuine guest/full checker separately validates the actual private envelope; the
authenticated guest receipt's task3 commitment binds the actual workload files to
the independently recomputed public projection. Original signed
`recorded-unchecked` status is preserved, never relabelled as private validation.

Generation may separately declare broker-only env names in `manifest.allowed_envs`
(and corresponding `required_envs`); no values appear in the projection. Workload
env inputs and broker env on browser stages refuse. Every workload file must be
required and covered by the semantic projection. Broker file slots are explicitly
unsupported and refuse because this adapter cannot validate that variant without
private input. This restriction does not reject the supported generator broker-env
route. Manifest/credential policy still needs the original selected full verifier.

`driver_execution` must equal the manifest service's complete split arrays. The
only supported entrypoints are `[/usr/bin/node]`, `[/usr/local/bin/node]`,
`[/usr/bin/python3]`, `[/usr/bin/python3,-I]`, or
`[/usr/bin/python3,-I,-B]`. Command is the independently frozen argument array,
starting with the exact measured driver file target; remaining arguments match
exactly. Shell/eval/cat forms, ignored driver arguments and mismatched splits
refuse. Merely mentioning a driver path anywhere does not establish execution.

`input_slots` maps these application purposes to distinct generic slots:
`request`, `task_terms`, `acceptance_profile`, `plan`, `stage_profile`, `driver`,
`source_manifest`, `source_bundle`, `suite`. Suite is null for generation/primary;
for base/candidate it contains the exact suite bytes whose SHA must match the
closed results and original generation output. Every other purpose is required.
Terms/profile/plan/stage-profile/driver bytes match independent selections;
source manifests and source archive bytes reconstruct the independently expected
base/candidate tree. Extra public files refuse, including candidate/other-judge
files in generation. A caller-supplied digest, `audit_passed` JSON, or output-only
source claim cannot replace the actual measured source input bytes.

Primary request bytes are the existing exact `dsmack-bounty-public-request/1`.
The cross-lane choice retains these nine semantic slots (suite null for
generation/primary) and the custom child request; there is no single tar-packet
fallback. For generation the authorized canonical stage profile must include
`specification:{text,sha256}` with nonempty bounded text and SHA-256 of its exact
UTF-8 bytes. Its complete profile bytes match the admitted stage-profile digest.
The selected native wrapper must audit the child request/packet itself, then
construct the admitted two-file generator or four-file browser projection for the
other lane's driver. Primary S0 uses its existing full public-input audit. Those
wrapper/audit paths are separate native qualification work, not an adapter bypass.

Children use a **new proposed application** `dsmack-bounty-child-request/1` with
exact fields enforced in `measured-inputs.mjs`: immutable task/policy/plan,
attempt/nonce/payee/model, stage role/index/run/profile/image/source and input
suite. Their schema-domain digest must match the independently selected per-run
request digest. Generation requests/sources contain base only. This application
packet is for independent review; it does not claim compatibility with an
existing qualified full-S0 driver or add bounty semantics to the native runner.

**Current native gate:** base8eea's public-files path rejects commitments and the
old diagnostic records none. Its native owner is separately implementing generic
validated optional file-only task commitments. This worker changes no native
code. An admitted version must actually validate/consume these declared files,
and the admitted application driver must read/validate the packet/source/suite
and classify outcomes honestly. Measurement/mount declarations cannot establish
that unqualified driver behavior. Do not deploy this adapter against an old or
unreviewed generic producer, forge a commitment to get through, or treat an
unconsumed audit file as native source proof. Genuine complete-plan qualification
still requires that native change, a reviewed application packet/driver and all
ten original runs plus their authenticated output bytes.

Base classification requires the original signed receipt to report **failed /
exit 1**, plus authenticated CI classifier output: browser started, completed,
no infrastructure failure, nonempty terminal tests with at least one assertion
failure. A signed completed/exit0 base refuses, even if its checks claim failure.
Other stages require completed/exit0 before the unchanged closed join. The
adapter never assigns assertion failure solely from the role.

Application manifests are constructed from these verified outputs, then passed
to the existing Python join through a private stdin subprocess protocol. That
protocol is an internal implementation detail, never a public authentication API.
Only the join's exact successful output can create the acceptance report and
delivery bytes. Original report signatures are checked on every evaluation;
there is no synthetic fallback or injectable verifier-success callback.

The delivered bundle is raw uncompressed USTAR: regular files only, ASCII safe
sorted paths, mode 0644/0755, no PAX/GNU extensions, links, directories or special
files; exact source-manifest membership/bytes/modes and two trailing zero blocks.
This is a NEW bounded delivery restriction, not compatibility with an existing
production source archive. An incompatible genuine archive must refuse and get
an independently reviewed decoder; never relabel synthetic bytes as delivery.
Report/certificate/delivery sidecars cannot appear outside the source manifest.

## Certificate and HTTP integration

`evaluate` returns canonical existing acceptance-report and delivery bytes and
closure digests; it has no signing capability. An independently authorized
application signer must produce the existing certificate over that report hash.
`admit(attemptId, input, certificate)` reevaluates the original evidence and
checks that exact hash and configured application signer before calling the
unchanged Store verdict gate. The Store's first `verdict_received_at` remains
stable on retries after expiry/restart. A stale certificate cannot gain first
admission. No signature or payment action is performed here.

`createAcceptanceApplication` wires the existing operator-only `/verdict` route
through this adapter. A trusted local `loadInput(attemptId)` supplies retained
original bytes; HTTP bodies cannot specify paths, trust roots, expectations or
child evidence. No alternate verdict route bypasses the adapter in this factory.
The original demo's certificate-only factory remains a prototype for its existing
controls; it does not become a genuine acceptance deployment by this patch.

Review focus: coordinator admission authenticity/public input coverage; selected
original report authority/source/environment; complete driver output semantics;
archive delivery restriction; every HTTP verdict entering this adapter; unchanged
atomic certificate admission and restart recovery; the passing real original-byte
authentication/negative diagnostic controls, native optional commitment support,
and eventual genuine complete-plan positive qualification.

## Cross-stage source relation (transform/2)

After authenticating all original stages and their complete source bundles, the
adapter recomputes the limited base-to-candidate relation from the authenticated
base-1 and primary-review source manifests. The primary's admitted stage profile
contains admission_transform:{record,sha256}; its digest must match the pinned
primary request. Version2 permits only existing-file content replacements in the
fixed three board application paths, with identical membership and modes and a
complete nonempty changed-file list. No upstream Git provenance is asserted.
The coordinator must perform this same full-source comparison before admitting
stages; the adapter repeats it before issuing an acceptance report. A signed
worker declaration or a selected profile alone cannot replace the comparison.

The Python closed-join adapter executes selected closure.py source bytes directly;
a timestamp-valid preexisting bytecode cache cannot select different join logic.

## Native artifact cap and logical output bundle

Every stage admission now explicitly contains `output_bundle`. Historical direct
mappings use `null`. The full browser profile selects this exact application
format (the generic native runner remains unchanged):

```
{"schema":"dsmack-flat-result-ustar/1","artifact":"result-files","manifest":"output-manifest.json","duplicates":{"stage-checks":"checks.json","public-input-audit":"public-input-audit.json"}}
```

Authenticate the original signed report, receipt, native manifest and *all*
native output bytes before decoding the archive. Native artifact membership is
exactly `result-files`, `stage-checks`, `public-input-audit`, plus the separately
committed stdout/stderr streams. The archive contains sorted flat regular files
and the original canonical `output-manifest.json`; the manifest excludes itself
and the archive. Both native duplicate exports must equal the corresponding
archived checks/audit bytes. There is no preferred copy on disagreement.

The independent consumer requires exact USTAR headers, mode0644, zero ownership,
time and extension metadata, verified checksum, ASCII names, zero member padding
and exactly two terminating zero blocks. Links, directories, extended headers,
alias paths, duplicates, unlisted or missing files refuse without filesystem
extraction. Bounds remain16MiB for the complete native archive (including headers,
manifest and padding),256 total members, and the existing64MiB aggregate across
all logical stage results. The existing admission mapping still caps each stage
at64 logical files. Exceeding a bound is a refusal, never a truncated success.

For bundled stages, `stage.files` maps every canonical logical name to the
identical archive member name, excluding `output-manifest.json`. The original
manifest bytes are independently reconstructed from all authenticated logical
file sizes and hashes. Downstream closed acceptance and source delivery read
only these expanded authenticated bytes; the implementation never overwrites or
synthesizes `original.outputs` or the signed receipt. Primary request
`required_artifacts` names the three native exports; primary delivery selectors
name the corresponding logical source bundle and candidate manifest members.
Synthetic bundled ten-stage controls do not qualify a genuine native run.
