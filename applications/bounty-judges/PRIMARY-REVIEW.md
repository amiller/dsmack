# Primary review

The primary review runs the original fixed checks against a candidate: the four
original browser specs, all 80 original logic cases, and six feature checks, as
a closed 14-test Playwright run. Missing source, case correspondence, media or
cleanup fails the run.

## Pieces

- [primary-driver.mjs](primary-driver.mjs) supervises the run.
- [primary-contract.mjs](primary-contract.mjs) fixes the test identities and
  result mapping.
- [primary-feature.spec.mjs](primary-feature.spec.mjs) implements the six feature
  checks as independent, freshly seeded tests, including renderer-only
  `filterBoard` invocation with host-side expectations and bounded JSON download
  inspection.
- The four original browser specs keep every assertion, keyboard action, delay,
  reload and upload, with their source hashes pinned. The one rewrite points
  their Playwright import at the image-owned
  [primary-fixtures.mjs](primary-fixtures.mjs), which blocks external
  networking, websockets, service workers, popups and renderer errors.

Candidate code is served as bytes into Chromium and is never imported into
privileged Node or another Node child.

## Logic cases

The four original logic files and three referenced data fixtures are kept byte
for byte in [primary-original/SOURCE.json](primary-original/SOURCE.json), pinned
to base `5c76d40e77db1f4864dabd4b9398d02589cff330`; runtime staging rechecks all
seven. [primary-logic-coverage.json](primary-logic-coverage.json) lists the
expanded case IDs: board 27 (including 15 invalid-board parameterizations),
flight 15, puzzle 26 (including all six solutions) and routes 12, for **80
cases**. Each group pins its helper source and case correspondence, and
[primary-logic-admission.mjs](primary-logic-admission.mjs) rejects missing,
changed or reduced helpers or cases before the runner starts.

Candidate calls run only in Chromium. The four image-owned helpers return
observations, including identity and thrown-error observations, and Node
compares them against the original expected values. They keep the seeded RNG and
physics loops, full puzzle undo histories, fixed GPX bytes and the original
numerical tolerances. A pass count or boolean returned by the app counts for
nothing: each aggregate returns its exact case-ID list after all Node
comparisons succeed, and the common test checks that list against the coverage
inventory. The original Node test files are kept as the reference source and are
not run with candidate imports.

## Result

`checks.json` is canonical, schema `dsmack-bounty-primary-checks/1`, with boolean
arrays `fixed_browser_baselines` (4), `fixed_logic_baselines` (4) and
`feature_checks` (6). Flags come from the trusted runner results after checking
discovery, terminal membership, expected status, no retry/skip, renderer health,
all media and normal cleanup; stdout or exit zero alone never passes. Missing
tests, expected failures, timeouts, crashes, absent media, source mismatch or
cleanup failure set the checks to false. `primary-details.json` records exact
IDs and the outcome, always with `accepted:false` and
`execution_closure_joined:false`; acceptance comes from the parent's join over
the original evidence.

Each of the 14 tests exports a screenshot, video and trace as
`browser-board.png/.webm/.zip`, `logic-board.*`, `feature-<name>.*`, etc. The run
also keeps `primary-raw-report.json`, `primary-source-transform.json`, bounded
stdout/stderr and details. The sorted canonical `output-manifest.json` lists all
other files with size and SHA-256 and excludes itself.

| Limit | Value |
|---|---|
| Per file / media / total | 16 MiB / 60 MiB / 64 MiB |
| Manifest entries | 64 |
| Playwright | 1 worker, 0 retries, 25 s per test, 480 s global |
| Supervisor child cap / hard watchdog | 490 s / 540 s |
| Outer container/VM envelope | 600 s |

The supervisor starts a new process group, bounds both streams, detects
descendants that outlive the runner, and kills the group and confirms it is empty
within a deadline; abnormal or unconfirmed cleanup fails the run. The watchdog
cancels the group before exiting. Process-group cleanup covers that group only;
processes that escape it are the container/cgroup owner's to clean up.

## Inputs

| Input | Consumer |
|---|---|
| `/candidate/`, the immutable extracted source projection | The supervisor snapshots safe regular files into an HTTP map and recomputes the domain-separated source-tree digest |
| One argument: the expected candidate tree SHA-256 | Compared against the snapshot before any test runs |
| Image-owned browser specs, driver/config/reporter/fixtures and logic fixture inventory | Hash-checked, staged and run with pinned Playwright 1.64.0 |
| Fresh writable `/workspace/state`, empty `/workspace/artifacts` | Runner, results and media, under UID/GID 1000 (checked at startup) |

The parent's S0 audit wrapper builds the candidate projection from the original
committed source archive. `source-delivery.tar` and `candidate-manifest.json`
come from that read-only archive, never from the extracted tree or these
outputs. This entrypoint reads no stage plan or child closure; the parent runtime
does the full closure join.

## Running

```sh
node applications/bounty-judges/test_primary.mjs
```

On Zed:

```sh
cd /data/PARENT_CHECKOUT
docker build --network=none --pull=false \
  --build-arg ADMITTED_BROWSER_IMAGE="$ADMITTED_BROWSER_OCI_REFERENCE" \
  -f applications/bounty-judges/Dockerfile.primary -t dsmack-primary:review .
# In the browser-sandbox container, with network none, UID 1000 and the
# read-only /candidate projection plus bounded state/output:
/usr/bin/node /opt/bounty-judges/primary-driver.mjs "$CANDIDATE_TREE_SHA256"
```

The derived image has its own digest, which the task pins as the primary browser
image, separate from the generator image.
