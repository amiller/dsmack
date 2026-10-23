# Signed alpha runtime: candidate adapter

This adapter consumes an externally authenticated release inventory rather than
participant-authored engineering review JSON. The final Developer ID app has
executed workloads with retained full verification on the existing Mini. An
actual downloadable release and fresh quarantined installation on another Mac
remain pending. Authenticate the complete release closure before invoking its
Python entrypoint.

Profiles are closed, signed selections, not arbitrary workload permissions.
Profile/2 with task/2 covers separately admitted credential-free browser review;
profile/3 with task/3 adds explicitly selected private-input routes, including
Claude development and independent generation. An archive contains only its
selected profiles. All use the admitted resource limits; a model label alone
does not authorize credentials or execution. See the selected profile and private-input policy before import. Browser diagnostics, full14/80 checks,
generation, acceptance and payment remain distinct evidence.

After authenticated installation, the selected release's alpha entry supports:

```sh
python3 -I /PRIVATE/INSTALL/alpha_coordinator.py --prepare \
  --bootstrap /PRIVATE/BOOTSTRAP/bootstrap.json \
  --inventory /PRIVATE/release.json --signature /PRIVATE/release.sig \
  --root /PRIVATE/INSTALL --profile bounty-board-search-browser-review-v1 \
  --task /PRIVATE/task.json --out-parent /PRIVATE/runs
python3 -I /PRIVATE/INSTALL/alpha_coordinator.py --check-only --plan /PRIVATE/runs/attempt-ATTEMPT.control/plan.json
python3 -I /PRIVATE/INSTALL/alpha_coordinator.py --execute --plan /PRIVATE/runs/attempt-ATTEMPT.control/plan.json
python3 -I /PRIVATE/INSTALL/alpha_coordinator.py --resume --plan /PRIVATE/runs/attempt-ATTEMPT.control/plan.json
```

Paths above are illustrative, not a current release or ready policy. The private
`dsmack-alpha-local-task/2` file has exactly schema,profile_id,closure_context,
checker_context,challenge,key_id,workload_disk,workload_admission,workload_signature.
All input fields after profile_id are selected path/size/SHA256 descriptors; the
key_id file contains the freshly enrolled App Attest key.
Independent authority must issue the challenge against that enrollment. There is
no arbitrary app, resource, credential or approval override in this file.

Preparation authenticates signed bindings and every staged file, validates the
external rollback state and expiry, derives local image/admission files from
signed roles, and checks actual codesign, certificate, exact entitlements,
stapled notarization and explicit OS distribution assessment. A descriptive
notary record is never a substitute for these checks. The final app currently
requires macOS27.0 and ARM64. Fresh quarantined download on another Mac remains a
separate qualification. OS loader/interpreters and the host remain trusted;
App Attest does not establish secrecy from a malicious root host.

Check-only performs no VM launch. Execute repeats release/source/OS/input checks
before side effects, writes and fsyncs an exclusive launch-request journal, then
uses the reviewed coordinator runtime. A saved requested attempt refuses implicit
relaunch, including after an uncertain outcome. Resume is read-only. Journal
protection is local to the selected directory; it is not global exactly-once
execution. Controller return, guest stop, evidence verification, task acceptance
and payment remain separate states. Existing helper memory-hardcap limitations
and the outer controller's bounded lifecycle still apply; uncertain residuals
must be inspected rather than silently deleted.

The engineering coordinator continues to require its original independent
engineering gates. The alpha route does not manufacture equivalent approved
objects: signature-authenticated release closure and actual OS checks supply its
separate authority. Full Linux evidence verification, replay authority and reward
settlement remain downstream, independently selected operations.


### Credential-free per-attempt public workload (profile/2 and task/2)

This credential-free route requires `dsmack-alpha-profile/2` and
`dsmack-alpha-local-task/2`; profile/1 and task/1 are explicitly refused by this
route. The reusable signed release contains the app, base, helpers, toolchain,
compose manifest and resource limits. It does not contain a fixed task disk.
The selected profile has an exact `public_task` source role instead.

A task adds `workload_disk`, `workload_admission`, and `workload_signature`
path/bytes/SHA256 descriptors to the existing closure/checker/challenge/key inputs.
An independently selected release authority signs canonical
`dsmack-alpha-workload-admission/1` bytes with that schema followed by a NUL as
the signature domain. The closed admission binds the release inventory digest,
profile, compose-manifest digest, attempt ID, canonical closure digest, disk size
and digest, key ID, issue time and expiry. This authority authorizes task inputs;
it cannot override the signed base, app, resources, security preset or private
input policy. Admission expiry may not exceed release expiry.

`public_task.py` prepares a fresh public USTAR disk from a qualified seed and
canonical closure, rebuilding the complete checksum table. It does not sign or
launch anything. Preparation preserves all other regular-file hashes. Local
Mac preflight streams the entire selected disk with a 4GiB cap, verifies raw
canonical USTAR structure, complete checksum membership, actual embedded compose
manifest and exact closure bytes against task and independent checker context.
It permits only the packer's exact zero-only 10KiB tar-record rounding followed
by 1MiB device rounding. It does not extract files or invoke debugfs. The source
is authenticated from the release before exact-byte compilation, avoiding
ambient Python bytecode caches. Signature, expiry, context and actual disk bytes
are checked again immediately before the exclusive launch journal is written.

Historical R5 demonstrated that a VM can run while its full evidence correctly
refuses an old embedded attempt context. Its expected context is not rewritten
and its authority is not retried. Subsequent Mini runs used reviewed releases and fresh per-attempt admissions;
the historical refusal remains retained. Every new run still needs independently
selected inputs, a fresh issued challenge and explicit launch selection.

## Current Mini checkpoint and operator boundaries (22 October 2026)

The unchanged notarized app CDHash `6b9baf8b20a1212adb6e9d08a36b8dd66c471dffb9d870ef1ac75413bfebd64d`
is distinct from the selected Linux base. D9 is historical; B44 is its separately
measured broker-timeout derivative. App signing does not authenticate a different
base, container, public request or private input by implication.

The all-device Developer ID profile permits distribution without registering each
Mac. Actual qualification is on the existing Apple silicon Mini/macOS27 only.
Fresh device enrollment, normal Gatekeeper/quarantined first-open, public release
artifacts and source/build provenance are separate pending gates. Maintainer
inventory signatures are not Sigstore source-build attestations.

A saved browser claim reconnects to the same Store attempt; it does not checkpoint
or resume the VM. Progress events report advisory phases, not verified model turns.
Receive original evidence and perform nonce-consuming verification once; subsequent
views use retained authenticated results. Never overwrite expected inputs after a
failure or treat controller exit as acceptance or payment.
