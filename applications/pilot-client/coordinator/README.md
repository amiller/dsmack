# Selected protected coordinator baseline

This page records the historical engineering-policy route. Current signed
alpha profiles use [the alpha runtime adapter](../../../docs/pilot/alpha-runtime.md).
The original-import description below is historical: selected later source
derivations include the explicit baseline-outcome adapter. Consult the exact
source manifest rather than treating this page as an unchanged-source claim.

This is a source-only import of the historically reviewed coordinator repair3.
`SOURCE-IMPORT.json` records all original and selected bytes. Three standard-library modules and the original test file remain unchanged.
The initial packaging removed only unused `original_source` metadata; the
subsequent explicit execution-profile extension also changes the coordinator and
session parser as recorded in the import manifest. No original build-machine
source path is needed at runtime. All module length/hash checks remain enforced before any
selected module executes. This source packaging requires its own independent
review; it does not inherit an approval for new app/image/policy bytes.

Run with an explicitly selected trusted Python and `-I`. A selected protected
operator policy must bind the original raw app/helper/final review records,
signing/build records, exact public inputs, independent context, challenge and
key identifier. It checks private-input file metadata without reading or hashing
that file. Do not place private policies, credentials, keys or enrollment/replay
state in this source directory or commit them.

Without an execution-profile field, the final handoff still selects only the
historical Claude selector, 600 seconds, 4096 MiB/one vCPU, one-GiB scratch and
256-MiB result template. Explicit browser/Codex selection is described below;
changing the operator policy alone cannot authorize another workload or envelope.

Stage the selected runtime closure and policy under an owned 0700 directory with
no symlink or group/world-writable ancestors. A group-writable checkout is not
suitable. Its check-only operation still verifies original app/tool/input bytes
and requires fresh output/helper paths; it launches no VM:

```sh
/absolute/trusted/python3 -I /absolute/private/runtime/coordinator.py \
  --policy /absolute/private/selected-policy.json --mode run --check-only
```

The paths above require an independently prepared policy and runtime; they are
not shipped fixtures. Actual execution additionally requires explicit `--execute`
and fresh run authority. A successful check does not establish challenge
freshness, credential validity, task success, evidence acceptance or payment.
The local client delegates this operation instead of implementing a second VM
supervisor.

For synthetic controls, copy this directory byte-for-byte under a private home
parent, then run `python3 -m unittest -v test_coordinator` from that copy. The
unchanged tests place temporary fixtures beside source and intentionally reject
a group-writable ancestor. Fixtures mock signing tools and use test-only review
records: they do not enroll, use a subscription or boot a VM.

## Explicit execution-profile selection

A newly independently reviewed raw final handoff may contain exactly one
`execution_profile` object with schema `dsmack-protected-execution-profile/1`.
Its exact keys are:

- `profile_id` and `workload_id`: both `bounty-board-search-browser-review-v1`
  (4-GiB scratch), or both `codex-private-sample` (one-GiB scratch).
- `resource_profile`: `mini-4096`; `memory_mib`: 4096; `vcpus`: 1;
  `runtime_seconds`: 600; `result_template_bytes`: 268435456.
- `scratch_template_bytes`: 4294967296 for the browser profile or 1073741824 for
  the Codex private sample. Both selected template byte lengths and SHA-256s
  remain independently pinned in `runtime_public_inputs`.
- `compose_manifest_sha256`: the exact independently selected workload manifest
  digest. Its `name` must match the selected workload. The original image/app,
  source, helper, challenge, closure and checker joins remain mandatory.
- `model_profile` and `security_preset`: nonempty bounded identifiers of the
  independently reviewed workload/model/network configuration. They are labels,
  never environment variables, model flags, shell commands or arbitrary settings.
  The final reviewer must establish their meaning from the actual pinned workload
  bytes; the coordinator does not implement model or network policy from labels.

The final independent review must bind the raw handoff digest including this
object and the exact selected coordinator path/hash. A browser selection needs
its new matching signed app/native capacity qualification; the old App3 cannot
inherit a 4-GiB capability from this metadata. No final handoff or run approval is
provided by this source package. Missing/unknown fields, arbitrary profiles,
resource expansion, null extension, changed manifest and boolean numbers refuse.

The parser mirror defaults to its historical one-GiB scratch cap. Only this
verified profile path passes the explicit role-specific scratch cap; the result
parser limit remains one GiB and the selected result template stays 256 MiB.
The native signed app remains the actual admission authority. Pure-Python tests
are synthetic descriptor/guard controls, not a Mac runtime qualification.

The first browser diagnostic may explicitly select `model_profile: "none"` and
`security_preset: "browser-sandbox-v1"`. This credential-free browser profile
requires an empty private-input path; a supplied private file is refused. All
other selections retain the owned private-file requirement. No dummy credential
file should be invented to satisfy a credential-free diagnostic. The lowerer,
seccomp and actual container/network configuration still require independent
qualification from their pinned bytes.

Read-only admission may use an original `approved_for_check_only: true` final
review bound to the exact raw handoff. This is accepted only for the default
read-only/`--check-only` operation. `--execute` and the execution helper separately
require the existing original `approved_for_signing_and_live_qualification: true`
review before creating logs, starting helpers or invoking LaunchServices. A
successful read-only admission never upgrades itself into execution authority.
