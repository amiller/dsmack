# Optional post-proof scratch retirement (candidate)

This host helper is a source candidate, not an enabled release action. It removes only `scratch.img` and `scratch-template.img.staged` from an independently selected `attempt-<native-execution-id>` directory after authenticating the original full-checker report and checking native process quiescence and open file references. It leaves evidence, result disks, console logs, public workload disks and the installed release intact.

The operator supplies a protected canonical selection record and its independently held SHA-256. The record pins the prelaunch closure/context, original signed report, independently trusted public report key, public quiescence record and original public scratch template descriptor. Quiescence observations must identify every native process used by the selected launch; a process exit observation alone is insufficient while a helper still holds the scratch file. Missing or ambiguous process/open-file checks refuse cleanup.

An exclusive lock prevents concurrent retirement. Each unlink follows an fsynced intent containing file identities, with durable progress records and a directory sync. A normal second invocation verifies that both targets remain absent and reports `already-retired`. Interrupted work resumes only against the same independently selected record and unchanged file identities. An abandoned lock requires explicit operator investigation of the original process before removal; the helper never guesses that a lock is stale. Preserve journals as evidence.

Mutable scratch contents are never read, hashed or exported. The selected public template digest is an external selection binding; this helper does not rehash the staged scratch template or mutable scratch. Unlinking does not establish secure erasure, removal from snapshots or a physical free-space gain.

Allow roughly **9.6 GB of logical storage per run** for two 4 GiB scratch files, the public workload disk and bounded result/retained files, in addition to the installed release and other historical evidence. Actual peak use varies with filesystem sharing and retained outputs. Retire the previous run's scratch after full proof and quiescence and before preparing the next stage; check actual free space separately. Do not delete original outputs to make a failed cleanup appear successful.

Candidate invocation:

```sh
node applications/pilot-client/retire-scratch.mjs /absolute/protected/selection.json <independently-selected-sha256>
```

No runtime image, provider policy, acceptance rule or VM implementation changes are involved. Production Darwin qualification and independent review remain required before release adoption.

### Host trust and visibility limits

Use a trusted system Node launcher and the intended user's home environment; a
caller-controlled HOME is not a new filesystem authority. Ancestor directories
are checked against symlinks and group/world writes, not against every possible
privileged owner. A non-root lsof process may lack visibility into foreign-UID
processes; the quiescence and open-reference checks cover the selected owned
native processes and are not a system-wide proof that no privileged process can
access the disk. Missing probes or reported incomplete visibility refuse.

The operator must prevent concurrent same-UID mutation of the attempt directory.
The identity check immediately before unlink narrows, but does not eliminate,
the same-UID check/unlink race. The journal and lock do not protect against a
malicious host owner or root. Recovery may find a file already absent after the
durable intent; reported two-file counts and retired logical bytes describe the
closed retirement set, including such absent targets, rather than new unlinks or
a measured physical-space gain in that invocation.
