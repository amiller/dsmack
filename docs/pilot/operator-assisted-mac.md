# Operator-assisted alpha on another Mac

This is a participant/operator handoff procedure, not a self-service enrollment
service. The configured Mini has executed the final Developer ID app with retained
proofs. Another Apple silicon Mac on **macOS 27.0 or later** is a supported target
for this procedure, but its acquisition, enrollment and execution have not been
qualified by that Mini result. Do not disable Gatekeeper, strip quarantine or
re-sign the app. The participant needs no developer signing key.

Use [authenticated installation](alpha-install.md) and
[the alpha runtime](alpha-runtime.md). The selected source archive is not the
binary release. Before inviting someone, the operator must provide exact download
locations, inventory/archive/signature, independently communicated root public-key
fingerprint and minimum sequence, and the selected Node24 ARM64/Python runtime.
A public key fetched only from the untrusted release is insufficient.

## One task and its proof

For a friend's first run, ask the operator for one admitted credential-free
workload. No model subscription is needed for that workload. The operator must
first supply the release, complete local runtime, enrollment ceremony and fresh
task/context described below. This is an operator-assisted procedure, not a
currently qualified self-service download. The bounty board, robot claims and
payment are separate application features.

Once authenticated installation and those prerequisites are complete, these are
the existing alpha commands. Every variable denotes an actual operator-selected
local path or profile ID; none is a downloadable default:

```sh
"$PYTHON3" -I "$INSTALL/alpha_coordinator.py" --prepare \
  --bootstrap "$BOOTSTRAP" --inventory "$INVENTORY" --signature "$SIGNATURE" \
  --root "$INSTALL" --profile "$PROFILE_ID" --task "$TASK_JSON" \
  --out-parent "$RUN_PARENT"
"$PYTHON3" -I "$INSTALL/alpha_coordinator.py" --check-only --plan "$PLAN"
"$PYTHON3" -I "$INSTALL/alpha_coordinator.py" --execute --plan "$PLAN"
"$PYTHON3" -I "$INSTALL/alpha_coordinator.py" --resume --plan "$PLAN"
```

`PLAN` is the generated `attempt-NATIVE_RUN_ID.control/plan.json` under
`RUN_PARENT`. Execute once; resume observes that same run. Retain its original
output directory, including `statement.json`, `envelope.json`,
`launch-assertion.cbor`, `result-assertion.cbor`, `launch-client-data.bin`,
`result-client-data.bin`, `console-v3.log` and `result.img`. These names identify
part of the required evidence, not permission to discard the other original
files. The operator's reviewed transport retains the complete declared set.

After the operator's original full verification, request the signed report,
independently admitted checker context, public assertion values and complete
retained evidence. On the separately qualified **Linux x86-64 verifier environment**,
the existing offline relying-party check is:

```sh
/usr/bin/python3 -I "$VERIFIER/verify.py" \
  --source-manifest-sha256 "$VERIFIER_SOURCE_SHA256" \
  --environment-sha256 "$VERIFIER_ENV_SHA256" \
  operator check --context "$CHECKER_CONTEXT" --report "$SIGNED_REPORT" \
  --evidence "$RETAINED_EVIDENCE" \
  --launch-assertion-b64 "$LAUNCH_ASSERTION_B64" \
  --result-assertion-b64 "$RESULT_ASSERTION_B64"
```

The assertion arguments are public base64 encodings of the original CBOR
assertions. Obtain the verifier pins and expected context independently; do not
accept expectations supplied only by the workload. This check uses retained
evidence, not another VM run or a reset replay store. Its JSON distinguishes
`evidence_valid`, `verification_level` and `task_success`: exit 0 means the pinned
expected outcome matched, exit 3 means valid evidence but task failure, and
exit 2 is refusal. Require `verification_level: full` for a full VM-result proof.
Even exit 0 is not bounty acceptance or payment. Keep credentials, saved claim
capabilities and private-input/scratch disks out of the shared proof. See the
[verifier package](../../applications/pilot-client/verifier/README.md) for its
Linux dependencies and the separate nonce-consuming original verification.

## Files exchanged before execution

Agree on a short, owned `0700` local directory. All paths below are local paths
on the participant's Mac. The operator must construct descriptors from those
actual paths and bytes; replacing strings in a signed document is not permitted.
Use an authenticated private exchange for invitation and capability files.

| Direction | Files or information | Purpose |
| --- | --- | --- |
| Operator to participant | Inspected bootstrap source; root public key/key ID/channel/minimum sequence; signed release inventory/signature/archive | Authenticate the selected app, base, helpers and host source. |
| Participant to operator | OS/architecture; selected public install paths and file descriptors; intended run parent; public app identity check results | Bind this host's paths and actual signed app, not the Mini namespace. No credential or private-input descriptor hash is sent. |
| Operator to participant | Fresh 32-byte enrollment challenge and protected `enrollment-policy.json` plus exact coordinator source closure | Bind the enrollment ceremony to the selected app and this host. This engineering-policy object is operator-prepared; the alpha installer does not generate it. |
| Participant to operator | Original `keyId.txt`, `clientData.bin`, `attestation.cbor` from enrollment | Verify Apple enrollment and record the new device key. These are public attestation records, not exported private keys. |
| Operator to participant | Invitation or operator-assisted claim; funded task/immutable terms; saved attempt record when operator claims on the participant's behalf | Preserve one Store claim and reconnect capability. Never distribute the service-wide operator token as a public download. |
| Operator to participant | Public workload disk, signed workload admission, signature; closure/checker context, fresh execution challenge, local task descriptor, selected public preparation | Bind the exact native execution, device key, task inputs and expected outcome before launch. Store claim ID and native execution ID are distinct. |
| Participant to operator | Original closed execution outputs, including public receipt/evidence and admitted artifacts | Full verification happens once against held authority/replay state. Private input and scratch are excluded. |

The operator retains enrollment/replay state, release authority, challenge issuer,
full-verifier environment and acceptance/settlement keys. No such authority is
supplied to the participant. Existing Mini enrollments, challenges and task
admissions are examples of completed runs, not reusable enrollment fixtures.

## Install, enroll and inspect

Run the exact bootstrap/install commands from [alpha-install](alpha-install.md).
First use `--plan` for signed download/expanded/free-space sizing. Existing alpha
profiles use 4 GiB guest memory, one vCPU and a 600-second guest budget. Reserve
space for the exact installed closure, public disk, outputs and two materialized
4-GiB working files; use the selected plan rather than treating these estimates as
a universal storage check. Host helper memory and observation deadlines are
separate from guest limits.

After the operator has supplied the policy and pinned runtime, inspect and then
explicitly perform the enrollment ceremony:

```sh
"$PYTHON3" -I "$ENROLL_RUNTIME/coordinator.py" \
  --policy "$ENROLL_POLICY" --mode enroll --check-only
"$PYTHON3" -I "$ENROLL_RUNTIME/coordinator.py" \
  --policy "$ENROLL_POLICY" --mode enroll --execute
```

These commands contact Apple and create a persistent local App Attest key. Send
the three original public enrollment outputs to the operator. Wait for actual
authority verification before accepting an execution context. Run a separately
admitted credential-free diagnostic before any subscription import. Neither
`doctor`, installation nor check-only grants launch or payment authority.

## Local subscription import

The selected capsule must include the unchanged
[credential exporter](../../applications/bounty-develop/export_subscription.py),
its adjacent `reference/claude_subscription_document.py`, the selected
`stage_private.py` and its complete pinned guest/transport/portable dependencies.
The operator supplies exact public preparation and all source/hash bindings.
Do not run this from an arbitrary checkout or use the Linux default on macOS.

For the development selector, with the selected protected paths already present:

```sh
"$PYTHON3" -I -B "$CAPSULE/export_subscription.py" \
  --source "$LOCAL_CREDENTIAL_DOCUMENT" --emit-credential-stdout | \
"$PYTHON3" -I -B "$CAPSULE/stage_private.py" \
  --preparation "$PUBLIC_PREPARATION" \
  --expected-manifest-sha256 "$MANIFEST_SHA256" \
  --expected-projection-sha256 "$PROJECTION_SHA256" \
  --guest-source "$PINNED_GUEST_SOURCE" --transport-module "$PINNED_TRANSPORT" \
  --private-parent "$PRIVATE_PARENT" --out-name develop-private \
  --transport-backend darwin-owned-tempfile-v1 \
  --portable-module "$PINNED_PORTABLE_MODULE" --temporary-parent "$PROTECTED_TEMP_PARENT"
```

Both processes run locally on the participant's Mac. Never insert `tee`, redirect
credential stdout to a file, log it, or forward it to the operator. The exporter
requires explicit source/emit flags, isolated Python, a pipe destination, and an
owned regular single-link `0600` credential document. It projects known OAuth
fields only; it does not copy settings, hooks, MCP, SSH keys or history. A valid
subscription with at least 1200 seconds remaining is required. Account login and
credential renewal are separate operations, not automatic setup steps here.
Generation and diagnostics use their separately selected importer, not an
arbitrary workload override.

The private image remains plaintext to the trusted Mac user/root. Darwin temporary
files are not Linux kernel write seals. Do not hash or export private inputs for
public evidence. Review [the importer contract](../../applications/bounty-develop/JIT-PREPARATION.md)
and its retained-residue limits before importing.

## Execute once, reconnect and finish

Use the exact prepare → check-only → execute commands in
[alpha-runtime](alpha-runtime.md), with this host's signed release/task and fresh
context. `--resume` observes an existing attempt; it does not rerun it. After an
uncertain launch, preserve journals/output and ask the operator to reconcile the
same attempt before selecting any retry.

Keep the saved claim file protected. The website's **Open saved attempt** restores
the same claim after reload; it does not checkpoint a VM. Progress is advisory.
In the current service, candidate submission ends progress updates, so the
operator waits until browser proofs close before submitting the retained candidate.
Full execution proof, workload success, ten-stage acceptance, escrow credit and
received withdrawal are separate outcomes. The operator returns their public
records and chain receipts; neither a screenshot nor check-only establishes pay.

After retained proof verification and confirmed quiescence, the separately
reviewed scratch-retirement helper may remove only selected working files.
Preserve original proofs and the saved claim. Follow its open-file/host-trust
limits; this is not secure erasure.

## Operator preparation still required

There is no supplied portable enrollment-policy generator or service-facing task
admission endpoint. The exchange table is the exact handoff contract, not a claim
that those authority operations are automated. The operator must prepare and
select each policy, task, context and public source capsule before invitation.
A runnable invitation is incomplete until all command variables above resolve to
actual selected local files. Release URLs, license/source-offer obligations and
fresh-device results must be recorded honestly; Mini qualification alone does
not establish those distribution facts.
