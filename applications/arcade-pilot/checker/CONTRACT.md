# Frozen board-search bonus checker

This is a new deterministic browser-only testnet bonus, not the historical
three-judge bounty. Publisher freezes this directory, base manifest, OCI/runtime
and task terms before accepting attempts. Candidate authors cannot supply tests,
server code, package scripts, dependencies or trusted-controller modules.

Invocation (absolute directories; empty owned output directory):

```
python3 -I /checker/check.py --base-dir /base --candidate-dir /candidate --out /out
```

The trusted Node executable is fixed at `/usr/bin/node`; its only external module
is `/opt/checker/node_modules/playwright/index.mjs` in the pinned runtime image.
There is no caller-selectable command, module path or environment injection.

The runtime supplies read-only projected source snapshots, not arbitrary Git
working directories. Policy `frozen-base39+candidate-board3/v1` resolves the
public full candidate commit from the fixed repository, starts with the frozen
39-file base, and overlays only that commit's three allowed board files. Other
files in the candidate Git commit (including package, tests and bounty files)
are not executed, imported or copied into this projection. The request must bind
both the full candidate Git commit and the resulting projected tree digest.

The base is exactly
`5c76d40e77db1f4864dabd4b9398d02589cff330`; reference checker input is
`82323836a672b799ac8f9f74265498f97438cd02`. Only `apps/board/index.html`,
`apps/board/logic.js`, and `apps/board/ui.js` may differ. An unchanged base is a
valid candidate input but must fail the functional search check. No PR source is
used by the independently written fixture candidate.

Search must use case-insensitive, trimmed substring matching across columns:
Apple, Grape and apricot all match `AP`. Blank query restores all cards and plain
counts; active query shows matching/total counts. Filtering changes no persisted
board or export. Moving a filtered card must move that card, and reloading after
the explicit data-saved transaction signal restores the full board with empty
search. Seven fixed checks cover baseline add/save, search control, substring /
case / trim, blank/counts, export immutability, filtered move and reload reset.

Trusted Python serves only the three allowed browser resources from validated
in-memory bytes. It has no candidate upload/write/execute endpoint. Chromium
requests are restricted to that exact loopback origin, service workers disabled,
and CSP rejects external code/connections/frames. Candidate JavaScript executes
only in Chromium, never imported into the trusted Node/Python controller.
The container must run with no external network and read-only candidate mounts.

`checker-result.json` is closed typed output (see result.schema.json), never a
cryptographic proof. `passed` is true only for outcome `passed`, all seven fixed
checks passed and zero trusted-controller exit. Exit 3 = functional assertion
failure, 2 = invalid candidate scope/input, 4 = infrastructure failure or timeout.
No skipped, timed-out or malformed run is passing. Runtime/native attestation and
independent original-evidence verification must bind this checker and its input
commitments before a service may authorize settlement. Screenshots/trace/video
are supplementary artifacts; the service never trusts a candidate-written pass.

## Reuse and qualification

Offline controls need only Python standard library:

```
python3 -m unittest discover -s applications/arcade-pilot/checker -p test_checker.py
```

Zed engineering controls reuse existing AMD64 image
`sha256:be0a78bf3cc2732833d65eb48b235d43917ac29df0ac455c328feab7169ebaec`.
Use `docker run --rm --network none --read-only --tmpfs /tmp:rw,nosuid,size=512m
--shm-size=256m`, read-only checker/base/candidate bind mounts, and a separate empty
owned writable `/out` mount. Select `/usr/bin/python3` as entrypoint and the
invocation above; no npm install or browser download is needed.
The runtime lane uses the independently qualified ARM64 flat OCI manifest
`222c279f5a94a6ad7fdbcf781faf4536cd0d6edd40c18e711b714183dbd58ed3`
(config `61c8f50f8b46b3badde245be0635dcaa1b530a3e87a8641d3a9ccc648c49ed76`).
ARM64-on-AMD64 emulation failed infrastructure startup in one engineering probe;
that refusal is not a functional verdict or native-Mac qualification.

One native execution may run baseline and candidate sequentially into separate
output directories. Its trusted outer driver must require expected baseline
exit 3 / functional_failure, then candidate exit 0 / passed and all seven tests;
only then may that outer workload complete successfully. Both complete results
and media must be authenticated by the same original result/proof. Never treat
baseline exit 3 as infrastructure success or use a different candidate/checker.
