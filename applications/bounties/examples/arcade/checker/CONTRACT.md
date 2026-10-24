# Board-search bonus checker

The checker runs seven fixed Playwright checks against a board-search submission
for the deterministic browser-only testnet bonus. The publisher freezes this
directory, the base manifest, the OCI image and runtime, and the task terms before
accepting attempts. Submitters cannot supply tests, server code, package scripts,
dependencies or controller modules.

Invocation (absolute directories; empty owned output directory):

```
python3 -I /checker/check.py --base-dir /base --candidate-dir /candidate --out /out
```

Node is fixed at `/usr/bin/node`, and its only external module is
`/opt/checker/node_modules/playwright/index.mjs` in the pinned runtime image. The
command, module path and environment are not caller-selectable.

## Inputs

The runtime supplies read-only projected source snapshots. Policy
`frozen-base39+candidate-board3/v1` resolves the full submitted commit from the
fixed repository, starts from the frozen 39-file base and overlays that commit's
three board files. Everything else in the commit (package, tests, bounty files)
is left out of the projection. The request binds both the full Git commit and
the projected tree digest.

The base is `5c76d40e77db1f4864dabd4b9398d02589cff330`; the reference checker
input is `82323836a672b799ac8f9f74265498f97438cd02`. Only `apps/board/index.html`,
`apps/board/logic.js` and `apps/board/ui.js` may differ. The unchanged base is a
valid input and fails the functional search check.

## Checks

Search is case-insensitive, trimmed substring matching across columns: Apple,
Grape and apricot all match `AP`. A blank query restores all cards and plain
counts; an active query shows matching/total counts. Filtering leaves the saved
board and export unchanged. Moving a filtered card moves that card, and reloading
after the data-saved transaction signal restores the full board with an empty
search. The seven checks cover baseline add/save, the search control, substring /
case / trim, blank/counts, export immutability, filtered move and reload reset.

Python serves the three board resources from validated in-memory bytes and has
no upload, write or execute endpoint. Chromium may only request that loopback
origin, service workers are disabled, and CSP blocks external code, connections
and frames. Submitted JavaScript runs only in Chromium. Run the container with
no network and read-only source mounts.

## Result

`checker-result.json` is closed typed output (see result.schema.json). `passed`
is true only when the outcome is `passed`, all seven checks pass and the
controller exits zero. Exit 3 is a functional assertion failure, 2 an invalid
submission scope or input, 4 an infrastructure failure or timeout. Skipped,
timed-out and malformed runs fail. The result becomes settlement evidence once
the native attestation and original-evidence verification bind this checker and
its input commitments. Screenshots, trace and video are supplementary.

One native execution runs the base and the submission in sequence into separate
output directories. Its outer driver requires the base to exit 3
(functional_failure) and the submission to exit 0 (passed, all seven tests)
before the workload completes. The same result proof authenticates both results
and their media.

## Running

Offline tests need only the Python standard library:

```
python3 -m unittest discover -s applications/bounties/examples/arcade/checker -p test_checker.py
```

On Zed, use the AMD64 image
`sha256:be0a78bf3cc2732833d65eb48b235d43917ac29df0ac455c328feab7169ebaec`
with `docker run --rm --network none --read-only --tmpfs /tmp:rw,nosuid,size=512m
--shm-size=256m`, read-only checker/base/candidate bind mounts and an empty
writable `/out` mount. Use `/usr/bin/python3` as entrypoint with the invocation
above; no npm install or browser download is needed. The Mac runtime uses the
ARM64 flat OCI manifest
`222c279f5a94a6ad7fdbcf781faf4536cd0d6edd40c18e711b714183dbd58ed3`
(config `61c8f50f8b46b3badde245be0635dcaa1b530a3e87a8641d3a9ccc648c49ed76`).
ARM64 under emulation on AMD64 fails at startup, so run ARM64 natively.

## Reference submission

[`../fixtures/candidate/`](../fixtures/candidate/) holds three board files
written from the frozen base source and the published search requirements.
Overlay them onto the 39-file base. The patch adds an exported pure filter, a
transient search control, filtered counts and rendering. Card controls keep
their underlying-board indices, filtering never writes persistence, and reload
starts with an empty query. The overlay tree digest is
`432fc561e2a7d34cdda8c6e29c0cc7cb99c84f644a217900c80f1474f8e4510f` under the
checker's path-to-file-SHA256 commitment. On the Zed AMD64 browser image it
passes all seven checks, and the unchanged base fails a search assertion.
