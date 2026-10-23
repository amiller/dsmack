# Full public-source application adapter (candidate)

This unprivileged application layer consumes the bridge's nine semantic slots:
`request`, `task_terms`, `acceptance_profile`, `plan`, `stage_profile`, `driver`,
`source_manifest`, `source_bundle`, `suite`. Generation and primary omit `suite`.
All present public files must be required, read-only workload slots covered by the
whole `dsmack.task-commitment/3` object. Provider credentials remain in the private
broker input; the canonical public projection never includes them.

Before work, `audit_stage.audit` requires four independent pins: domain-separated
request SHA, raw stage-profile SHA, raw trusted-driver SHA, and raw plan SHA. A
child request uses `dsmack-bounty-child-request/1`; primary uses the reviewed S0
request. Actual terms/profile/source bytes are recomputed. Source bundles are
bounded regular-only USTAR with exact manifest membership and two terminators.
The manifest binds every full source file, mode, length and content hash.

Generation stage profile carries `specification: {text, sha256}`. The generator
gets exactly `base.json` (three board assets projected from the authenticated
FULL base tree) and `spec.txt`. Base/candidate independent browser stages get the
same three board assets plus their independently selected generated suite.
Primary gets a faithful FULL candidate projection, including every app/fixture;
its delivered archive and manifest are the original committed bytes.

Primary profile carries `admission_transform: {record, sha256}` using
`dsmack-bounty-admission-transform/2`. This asserts only existing-file replacement
within the three fixed board paths; it makes no upstream Git provenance claim.
The external coordinator/verifier MUST decode both independently retained base
and candidate trees and recompute `admission_relation` before stage admission.
The primary stage only possesses the candidate tree and does not independently
prove that relation. Neither job-authored audit JSON nor this local helper is
an authorization or payment decision.

`entrypoint.py` invokes the independently selected generator/browser/primary
harness from fixed image-owned paths. A measured thin launcher must execute at
`/workspace/inputs/driver` with Python `-I -B`; implementation imports remain in
the pinned image. Primary projects the full candidate under
`/workspace/state/candidate-projection`, with a separate initially empty
`/workspace/state/primary-run` for the primary harness. Only the built-in state
and artifacts writable mounts are needed. After child
quiescence, original delivery and the public-input observation join ordinary
exported artifacts. Source recipes and invocation are qualification candidates:
no provider call, ARM64 runtime or funded acceptance qualification is claimed. Immutable
application OCI/source closure, selected request/argv and measured generic file
consumption remain mandatory independent gates. The generic base contains no
bounty verifier hooks.

Source-only controls (no installs, browser or credentials):

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s applications/bounty-runtime -p 'test_*.py'
```
