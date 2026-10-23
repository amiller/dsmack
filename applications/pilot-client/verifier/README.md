# Selected full VM evidence verifier (Linux operator)

This source package relocates the actual reviewed v3-aware production consumer.
It includes original statement/result-assertion authentication, full native/guest
and output-closure checks, replay/enrollment handling, signed report verification
and the independently pinned Apple core/contract library. It does not replace
these with the older standalone Apple verifier or a browser-supplied verdict.
`SOURCE-IMPORT.json` records original and selected bytes. Only `frozen.py` changes
original implementation bytes, to replace build-host paths with package-relative
locations while preserving every dependency digest and exact membership guard.
The launcher and explicit tools package are separate packaging additions.

The current deployment target is the qualified Linux x86-64 verifier environment,
not macOS. `QUALIFIED-LINUX-ENVIRONMENT.json` records exact Python, OpenSSL,
unshare/debugfs/true tool bytes, cryptography/backend module bytes, versions and
origins. It is a selected reference environment, not a dependency installer,
security update policy or hermetic OS image. No dependency is downloaded by these
commands. A changed environment needs its own reviewed lock/qualification; do not
edit a hash to force an unexplained mismatch through. The selected source and
environment manifests themselves require independent approval.

Stage the whole package under an owned 0700 directory with no symlink or
group/world-writable ancestors. Inspect/select the launcher
and complete source first. With the selected `/usr/bin/python3`, use `-I`:

```sh
/usr/bin/python3 -I /absolute/private/verifier/verify.py \
  --source-manifest-sha256 INDEPENDENT_RAW_SOURCE_MANIFEST_SHA256 \
  --environment-sha256 INDEPENDENT_RAW_ENVIRONMENT_MANIFEST_SHA256 doctor
```

The capitalized digests are required independent selections, not published
release values. The launcher verifies complete source membership and all bytes,
then the environment, before importing the selected implementation. Unlisted
files, bytecode caches, extension-loader alternatives and writable/symlinked
source descendants refuse. Imports use a fresh owned empty cache prefix and
suppress bytecode writes so installed dependency caches cannot bypass source
pins; `-B` alone would not provide that protection. It clears
inherited environment variables and fixes PATH for the original OpenSSL call.
Doctor runs the original credential-free Linux namespace probe; it never opens
operator authority, enrollment/replay stores or credentials. Readiness means this
local parser/extraction runtime is available, not that any task is verified.

The same prefix delegates the original entrypoints without changing arguments:

```text
... operator --help
... prepare --help
... transfer --help
```

For an operator-selected original retained output directory, the actual prepare
interface is:

```text
... prepare prepare --app-out /absolute/original-retained-output \
  --enrollment /absolute/public-enrollment-package.json \
  --context /absolute/independent-checker-context.json \
  --bundle /absolute/fresh-bundle
```

Preparing a bundle is not verification and does not consume replay authority.
The original `operator verify` and full `operator check` interfaces are separate
and require protected external authority and independent context. Root/operator
must select those exact inputs and preserve replay floors. No demo enrollment
store, replay DB, private key, report key or operator secret is shipped here.
Do not reset replay or issue a replacement challenge to hide a failed check.
The checker exposes execution validity and workload/task success separately.
Application acceptance and settlement require additional task-specific policy.

## Mac evidence delivery and remaining qualification

The Mac participant uses the protected coordinator, not this Linux extraction
runtime. Transfer the exact original 21 retained AppOUT evidence files through an
independently reviewed finite, no-follow transport. Preserve additional original
VM residues on the Mac without reading/hashing/copying scratch or private state.
This package's `transfer` entrypoint handles the original prepared-bundle format;
it is not a new raw-AppOUT upload API and must not be substituted for the reviewed
Mac-to-verifier transport. No unrestricted tar extraction fallback is allowed.

A deployment must still independently bind the original selected final handoff,
source inventory, extraction tool, signed app and VM/guest configuration, context,
complete retained evidence and authenticated delivery digest. This package does
not provide a general network service, discovery, private-state backup or payment
certificate. A fresh friend-Mac run and fresh production verification using this
relocated package remain runtime gates until explicitly demonstrated. Source
packaging cannot inherit a historical run's replay authorization.
