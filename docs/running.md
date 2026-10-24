# Running a task on a Mac

The Arcade pilot automates every step below: see
[`applications/bounties/runner`](../applications/bounties/runner/README.md).
This page lists the underlying commands. The Mac needs Apple silicon, macOS 27
or later, Python 3 and Node 24. Never disable Gatekeeper, strip quarantine or
re-sign the app.

## Roles

The operator holds the release signing key, the enrollment and replay state,
the challenge issuer and the verifier. The participant runs the Mac. Files
exchanged:

| Direction | Files |
| --- | --- |
| operator → participant | bootstrap source; release root public key, key ID, channel, minimum sequence; signed release inventory, signature, archive |
| operator → participant | enrollment challenge and `enrollment-policy.json` |
| participant → operator | `keyId.txt`, `clientData.bin`, `attestation.cbor` from enrollment |
| operator → participant | public workload disk, signed workload admission and signature, checker context, fresh execution challenge, local task descriptor |
| participant → operator | the complete output directory of the run (excluding private input and scratch) |

## Install

```sh
mkdir -m700 "$HOME/.dsmack-alpha"
env -i HOME="$HOME" PATH=/usr/bin:/bin "$NODE" applications/pilot-client/alpha-bootstrap.mjs \
  --trust-key maintainer-public.pem --key-id "$RELEASE_KEY_ID" --channel alpha \
  --min-sequence "$MIN_SEQUENCE" --out "$HOME/.dsmack-alpha/bootstrap"
python3 -I "$HOME/.dsmack-alpha/bootstrap/alpha_stage.py" \
  --bootstrap "$HOME/.dsmack-alpha/bootstrap/bootstrap.json" \
  --inventory release.json --signature release.sig \
  --target "$HOME/.dsmack-alpha/version1" --plan
python3 -I "$HOME/.dsmack-alpha/bootstrap/alpha_stage.py" \
  --bootstrap "$HOME/.dsmack-alpha/bootstrap/bootstrap.json" \
  --inventory release.json --signature release.sig --archive release.tar.gz \
  --target "$HOME/.dsmack-alpha/version1"
```

Get the trust key from the operator separately, not from the release archive.
`--plan` reports download size, expanded size and free space needed. The
installer accepts only a `dsmack-alpha-release/2` inventory, checks every file
against it, and refuses an older sequence or a different inventory at the same
sequence. Staging never launches anything.

## Enroll

```sh
python3 -I "$ENROLL_RUNTIME/coordinator.py" --policy "$ENROLL_POLICY" --mode enroll --check-only
python3 -I "$ENROLL_RUNTIME/coordinator.py" --policy "$ENROLL_POLICY" --mode enroll --execute
```

This contacts Apple and creates a persistent App Attest key. Send the three
enrollment outputs to the operator.

## Run

```sh
python3 -I "$INSTALL/alpha_coordinator.py" --prepare \
  --bootstrap "$BOOTSTRAP" --inventory "$INVENTORY" --signature "$SIGNATURE" \
  --root "$INSTALL" --profile "$PROFILE_ID" --task "$TASK_JSON" \
  --out-parent "$RUN_PARENT"
python3 -I "$INSTALL/alpha_coordinator.py" --check-only --plan "$PLAN"
python3 -I "$INSTALL/alpha_coordinator.py" --execute --plan "$PLAN"
python3 -I "$INSTALL/alpha_coordinator.py" --resume --plan "$PLAN"
```

`PLAN` is `$RUN_PARENT/attempt-ID.control/plan.json`. The task file
(`dsmack-alpha-local-task/2`) has the fields `schema`, `profile_id`,
`closure_context`, `checker_context`, `challenge`, `key_id`, `workload_disk`,
`workload_admission` and `workload_signature`; each input is a
`{path, bytes, sha256}` descriptor. Profiles are fixed in the signed release:
profile/2 is credential-free browser review, profile/3 adds private inputs.

Prepare checks the release, the app's code signature, entitlements, stapled
notarization and the OS distribution assessment. Check-only does not launch.
Execute writes a launch journal first and runs once; a second execute on the
same plan is refused. Resume only observes.

For a credential-free run, the operator can instead send a single
`invitation.json` and its SHA-256:

```sh
python3 -I applications/pilot-client/friend.py inspect invitation.json --sha256 "$DIGEST"
python3 -I applications/pilot-client/friend.py prepare invitation.json --sha256 "$DIGEST"
python3 -I applications/pilot-client/friend.py check invitation.json --sha256 "$DIGEST"
python3 -I applications/pilot-client/friend.py run invitation.json --sha256 "$DIGEST"
```

`friend.py resume` observes the same run.

## Private inputs

Coding tasks need a subscription credential. Both processes run on the
participant's Mac; the credential travels only through the pipe. The helper
folder is `applications/pilot-client/workload`:

```sh
CAPSULE="$PWD/applications/pilot-client/workload"
```

```sh
python3 -I -B "$CAPSULE/export_subscription.py" \
  --source "$LOCAL_CREDENTIAL_DOCUMENT" --emit-credential-stdout | \
python3 -I -B "$CAPSULE/stage_private.py" \
  --preparation "$PUBLIC_PREPARATION" \
  --expected-manifest-sha256 "$MANIFEST_SHA256" \
  --expected-projection-sha256 "$PROJECTION_SHA256" \
  --guest-source "$PINNED_GUEST_SOURCE" --transport-module "$PINNED_TRANSPORT" \
  --private-parent "$PRIVATE_PARENT" --out-name develop-private \
  --transport-backend darwin-owned-tempfile-v1 \
  --portable-module "$PINNED_PORTABLE_MODULE" --temporary-parent "$PROTECTED_TEMP_PARENT"
```

The exporter copies only the OAuth fields, not settings, hooks, MCP config or
history. See the [workload helpers](../applications/pilot-client/workload/README.md).

## Verify

The output directory includes `statement.json`, `envelope.json`,
`launch-assertion.cbor`, `result-assertion.cbor`, `launch-client-data.bin`,
`result-client-data.bin`, `console-v3.log` and `result.img`. The operator runs
the full verification once, against its replay state, and returns a signed
report. Anyone can then check that report on Linux:

```sh
python3 applications/pilot-client/verifier-browser/verify.py \
  operator check --context "$CHECKER_CONTEXT" --report "$SIGNED_REPORT" \
  --evidence "$RETAINED_EVIDENCE" \
  --launch-assertion-b64 "$LAUNCH_ASSERTION_B64" \
  --result-assertion-b64 "$RESULT_ASSERTION_B64"
```

Exit 0: valid evidence, task succeeded. Exit 3: valid evidence, task failed.
Exit 2: refused. The JSON output has `evidence_valid`, `verification_level`
(`full` for a complete VM-result check) and `task_success`. The check also
verifies the App Attest chain against `trust/apple-app-attestation-root.pem` and
both assertions directly, so it does not rely on the report key for the Apple
step (`apple_assertions_valid`). See the
[verifier README](../applications/pilot-client/verifier/README.md).

## Clean up

After the verifier report, delete the two scratch files of the attempt:

```sh
node applications/pilot-client/retire-scratch.mjs /abs/selection.json SELECTION_SHA256
```

It checks the report and that the VM helpers have exited before deleting.
Keep the original evidence.
