# Invited participant CLI

A small application adapter outside the signed runner. Node24+, standard library
only. It reuses the reviewed bounty-demo protected claim reader. The selected
release source and claimant workflow must both be present in the checkout.

```sh
node applications/pilot-client/pilot.mjs help
node --test applications/pilot-client/pilot.test.mjs
```

`doctor` is read-only host inventory, with no candidate execution, network,
credential, VM, signing, enrollment or package installation. Its `launch_ready`
is always false. Use it to identify cheap prerequisites before a separately
qualified credential-free VM diagnostic.

**Historical journal interface:** `plan`, `check`, `run` and `resume` below
are retained for inspection and regression tests. Their shared Store/native ID
assumption is not the current alpha profile/3 execution route. Follow
[the current alpha runtime](../../docs/pilot/alpha-runtime.md) for independently
selected native execution IDs. `doctor` and the saved-record claim CLI remain
read-only inspection/claim interfaces with their stated scopes.

`plan` joins an existing claimed record to the operator-selected protected
coordinator policy's exact closure attempt and single selector. It pins public
coordinator/policy/context/manifest bytes and an explicitly trusted local Python
interpreter; it never copies or hashes the capability or private input bytes.
The independently supplied coordinator digest and protected policy are trust
inputs, not values the candidate can approve for itself. This is not a release
signature verifier, online assignment check or independent task-terms verifier.

`check` and `run` delegate to the exact selected protected coordinator with Python
isolated mode and a minimal environment. They do not implement another app,
helper supervisor, enrollment ceremony or evidence verifier. Only `run --execute`
can request execution. It writes an exclusive0600/fsynced launch-request journal
before invoking the coordinator, then private stdout/stderr files. A stable
journal filename derives from the public server origin and assignment ID in the
chosen private state directory. Existing journals refuse another launch,
including uncertain/failed outcomes. `resume` is read-only and never retries.

This is local recovery, not a server-wide lease or hostile-host exactly-once
guarantee. Keep one state directory for an assignment. Copying records or
choosing another state directory can bypass this local guard; the protected
coordinator's original output/attempt controls and service admission remain
necessary. Concurrent writers and malicious same-UID/root namespace replacement
are outside this adapter's guarantee. Do not delete journals to retry an
uncertain run. Inspect the original coordinator session/output first.

A controller exit, including zero, never sets execution_verified, task_accepted
or payment_received. Retained logs may contain private paths or runtime
information; inspect locally rather than uploading them indiscriminately.
The coordinator owns the separately reviewed VM/time/helper lifecycle. Closing
this CLI is not a cancellation API or proof that a VM stopped. A launch-request
journal after interruption means the outcome is uncertain.

See [the newcomer runbook](../../docs/pilot/newcomer.md) for the full sequence and
release gaps. Actual authenticated staging, final signed app execution, enrollment and
private import have passed on the configured Mini. Fresh normally secured Mac
installation and a public downloadable release remain unqualified; selected
image/helper/coordinator/operator inputs still require explicit binding. This client does not make the old private demo recipe a
self-serve release or spend funds.

The [selected coordinator source](coordinator/README.md) includes the original
protected checks plus explicit final-handoff-bound browser/Codex profiles. The
[full Linux evidence verifier](verifier/README.md) is a separate operator-side
source package with pinned dependencies and extraction tools. Its doctor, CLI
imports and historical public-output preparation passed; source packaging does
not supply fresh authority or qualify an actual new Mac run. Its prepared-bundle
transfer entrypoint is not a raw Mac AppOUT upload service.
