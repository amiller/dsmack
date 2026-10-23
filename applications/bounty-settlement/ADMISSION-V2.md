# Explicit pilot identity mappings

The operator selects `dsmack-bounty-acceptance-admission/2` before execution.
It retains all original signature, context, challenge, base/boot, task3, source,
request and ten-stage uniqueness checks. Legacy admissions without a schema
retain their exact receipt-ID, binary-harness and task-OCI semantics.

In version 2 the paid task image is the base VM OS image; each stage OCI is a
separate independently held pin, matched against its measured request and
actual compose image. Projection receives the derived image mapping from the
held admission, not a worker-selected interpretation of the task.

For the pinned d9 producer only, receipt IDs follow
`guest-<authenticated manifest selector>-<canonical positive Linux PID>`.
The PID is bounded by 4194304. It identifies the producer record, not the
application stage. The stage's planned run ID remains independently selected
and checked in the authenticated task3 public request; selectors never infer
stage assignment. Original receipt/report bytes remain unchanged.

The paid semantic harness commitment hashes canonical raw HARNESS-CLOSURE
bytes. Those bytes commit canonical recipe inventory bytes, platform, role OCI,
CLI, settings and drivers. All ten acceptance stages use the explicitly closed
`applications/bounty-runtime/driver.py` measured driver, present in both
inventories. The actual native harness binary remains independently checked
against the manifest. This mapping does not claim provider-signed model
identity, or that listing a source file proves it executed.

Synthetic complete graphs exercise these mappings and fail-closed legacy
behavior. The retained b46 stage probe independently authenticates one genuine
hardware stage and its 51 logical outputs; it does not establish a complete
acceptance plan or payment eligibility.
