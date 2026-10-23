# Primary review: complete original logic coverage and browser checks

This source joins all 80 original logic cases as renderer observations with
expected assertions in trusted Node. The four per-application ports passed their
individual browser and mutation controls. Common integration and the selected
image/native VM still require qualification; these source results do not establish
full primary acceptance or a paid bounty. Missing source, case correspondence,
media, or cleanup still fails closed.

[primary-driver.mjs](primary-driver.mjs) supervises a closed 14-test Playwright
run. [primary-contract.mjs](primary-contract.mjs) fixes the exact test identities
and result mapping. [primary-feature.spec.mjs](primary-feature.spec.mjs) implements
the six existing feature checks as independent, freshly seeded tests, including
renderer-only `filterBoard` invocation with trusted host expectations and bounded
JSON download inspection. The four original browser specs retain every original
assertion, keyboard action, delay, reload and upload; their exact source hashes
are pinned. The only rewrite changes their Playwright import to the image-owned
[primary-fixtures.mjs](primary-fixtures.mjs), which blocks external networking,
websockets, service workers, popups and renderer errors. Candidate code is served
as bytes into Chromium, never imported into privileged Node or another Node child.

The original four logic files and three referenced data fixtures are retained
byte for byte in [primary-original/SOURCE.json](primary-original/SOURCE.json), pinned
to base `5c76d40e77db1f4864dabd4b9398d02589cff330`. Runtime staging rechecks all
seven files. [primary-logic-coverage.json](primary-logic-coverage.json) fixes the
expanded original IDs: board 27 (including 15 invalid-board parameterizations),
flight 15, puzzle 26 (including all six solutions), and routes 12: **80 cases**.
Each group pins its reviewed helper source and case correspondence. The
[coverage admission](primary-logic-admission.mjs) refuses missing, changed, or
reduced helper/case closures before the trusted runner starts.

Candidate calls execute only in Chromium. The four image-owned helpers return
observations, including explicit identity and thrown-error observations, and
compare all original expected values in Node. They preserve the seeded RNG and
physics loops, complete puzzle undo histories, fixed GPX bytes and original
numerical tolerances. An application's returned pass count or boolean is never
acceptance authority. Each aggregate returns its exact case-ID list only after
all trusted Node comparisons succeed; the common test checks that list against
the independently selected coverage inventory. The original Node test files
are provenance; they are not executed with candidate imports in privileged Node.

The result ABI is canonical `checks.json`, schema
`dsmack-bounty-primary-checks/1`, with exact boolean arrays
`fixed_browser_baselines` (4), `fixed_logic_baselines` (4), `feature_checks` (6).
Passed flags derive only from the exact trusted runner results after validating
discovery, terminal membership, expected status, no retry/skip, renderer health,
all media and normal cleanup. stdout/exit zero alone cannot pass. Missing tests,
expected failures, timeouts, crashes, absent media, source mismatch or cleanup
failure reset the checks to false. `primary-details.json` records exact IDs and
the normalized outcome, always `accepted:false`, `execution_closure_joined:false`.
The parent must independently authenticate that outcome with original evidence.

Each of the 14 tests requires its screenshot, video and trace, exported as
`browser-board.png/.webm/.zip`, `logic-board.*`, `feature-<name>.*`, etc.
`primary-raw-report.json`, `primary-source-transform.json`, bounded original
stdout/stderr and details are also retained. The sorted canonical
`output-manifest.json` lists all other exported files with bytes/SHA-256 and
excludes itself. Bounds: 16 MiB/file, 60 MiB media and 64 MiB total, at most 64
manifest entries. Playwright uses one worker, zero retries, 25 seconds/test and
480 seconds globally; the supervisor caps the child at 490 seconds and has a
540-second hard watchdog. Outer container/VM lifecycle must remain within the
independently admitted envelope, initially 600 seconds.

The supervisor launches a new process group, bounds both streams, detects
descendants surviving the runner, kills and confirms group emptiness under a
finite deadline. Unconfirmed or abnormal cleanup prevents success. Its global
watchdog attempts group cancellation/quiescence before exit. Process-group checks
do not prove container-wide quiescence for processes escaping that group; the
parent retains container/cgroup cleanup ownership and must qualify actual browser
teardown. The source controls use lightweight Python subprocesses to test group
behavior; the actual selected-container teardown remains an integration qualification.

Consumed readonly ABI:

| Input | Actual consumer |
|---|---|
| `/candidate/` complete immutable extracted source projection | Trusted supervisor snapshots only safe regular files into an HTTP map; recomputes the existing domain-separated full source-tree digest |
| One command argument: independently expected candidate tree SHA-256 | Supervisor compares against its actual source snapshot before executing tests |
| Image-owned four raw browser specs, fixed driver/config/reporter/fixtures and original logic fixture inventory | Supervisor validates fixed source hashes, stages only trusted tests, invokes pinned Playwright 1.64.0 |
| Fresh writable `/workspace/state`, empty `/workspace/artifacts` | Trusted runner/results/media only, under actual UID/GID1000 |

The parent full-S0 readonly audit wrapper creates the candidate projection from
the original committed source archive. **`source-delivery.tar` and
`candidate-manifest.json` must come from that original readonly archive**, never
from the mutable extracted tree or these browser outputs. Audit, immutable task/
plan/driver/child evidence inputs, original delivery export and genuine full
closure joining belong to the parent runtime lane. This entrypoint does not
consume a stage-plan or child-closure file and cannot claim that join occurred.
The generic VM stays application-neutral. Docker USER metadata does not prove
the runtime identity; the supervisor checks UID/GID1000 and real mounts must be
qualified under that identity.

Local source controls:

```sh
node applications/bounty-judges/test_primary.mjs
```

Parent-owned Zed commands after independent review (not run here):

```sh
cd /data/PARENT_CHECKOUT
docker build --network=none --pull=false \
  --build-arg ADMITTED_BROWSER_IMAGE="$ADMITTED_BROWSER_OCI_REFERENCE" \
  -f applications/bounty-judges/Dockerfile.primary -t dsmack-primary:review .
# In the separately owned browser-sandbox container, with network none, actual
# UID1000 and the readonly /candidate projection plus bounded state/output:
/usr/bin/node /opt/bounty-judges/primary-driver.mjs "$CANDIDATE_TREE_SHA256"
```

A derived image has a new digest; the frozen task must independently select the
actual primary browser image, never reuse the generator image identity. Next qualify the integrated 14-test run in its selected image, including real
positive/adversarial browser controls and the immutable audit/delivery/evidence
join. Individually passing logic ports do not establish that integrated result.
The generic generator/browser/closure implementations are separate.
