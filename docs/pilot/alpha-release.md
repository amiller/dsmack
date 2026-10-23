# Historical alpha inventory/1 prototype

This page records the earlier inventory/1 prototype. Current installation uses
[authenticated inventory/2 staging](alpha-install.md) and the
[signed runtime profiles](alpha-runtime.md). The existing Mini has passed actual
installation, OS checks, private import and execution under the final notarized
identity; another Mac and public downloadable artifacts remain unqualified.

This earlier module authenticates a canonical `dsmack-alpha-release/1` inventory using an
Ed25519 public trust root selected outside the download. It checks the explicit
channel, minimum sequence and validity window, Developer ID/category-6 metadata,
exact file closure and profile descriptor digests. The detached signature covers
`dsmack-alpha-release/1` followed by a NUL byte and the exact canonical JSON bytes.
A signature is not Apple code-signature validation or notarization evidence.

The caller supplies its trusted clock and persistent minimum accepted sequence.
This prototype does not fetch revocation information or persist rollback state.
The caller must not take a replacement trust root or minimum sequence from the
same release archive. Synthetic test keys do not establish a production root.

`verifyStagedFiles` checks an already privately staged tree, refusing missing or
extra files, symlinks, nonregular files, hardlinks, unsafe modes and changed
bytes. It does not extract an archive or install dependencies. The whole tree
must remain under the trusted operator's control during and after checking;
this is not protection against a hostile root or same-user process replacing
files between validation and execution.

All return values retain `launch_ready: false`. No legacy approval booleans are
manufactured. At this historical checkpoint the path still needed independently reviewed safe
extraction/atomic installation, actual Apple signature/timestamp/stapled-notary
checks, explicit Developer ID coordinator policy, fresh category-6 enrollment,
and the actual VM/checker qualification. Current engineering coordinator admission
continues to require Apple Development and its separately reviewed handoffs.

Run source controls from the repository root:

```sh
node --test applications/pilot-client/alpha-release.test.mjs
```

This is a bounded source prototype, not an alpha download or runnable installer.
