# Test generator and declarative browser driver

Three independent judges each write a declarative browser test suite for the
board app from the base source and the task spec. The driver runs each suite
against both the base tree and the candidate tree. A useful suite fails on base
and passes on the candidate. Generation uses fixed Claude Code **2.1.187** with
the explicitly requested model `claude-opus-4-8`; the generator checks that the
model the CLI reports matches the request.

## Components

| Component | Role | Inputs and result |
|---|---|---|
| [prepare-generation.py](prepare-generation.py) | Trusted preparation | Recomputes the full base tree manifest/digest, checks the pinned spec, exports the three board source files and spec |
| [generate.py](generate.py) | Bounded CLI supervisor | One judge per process/container, pinned binary, fresh context, stream transcript, identity, validated suite and generation checks |
| [suite-contract.mjs](suite-contract.mjs) | Shared validator | Exact bounded JSON grammar, canonical UTF-8 suite bytes, no generated executable code |
| [browser-driver.mjs](browser-driver.mjs) | External Playwright interpreter | Same suite bytes for base/candidate, closed IDs, renderer-only candidate JS, screenshots/videos/traces and CI checks |
| [generation-recipe.json](generation-recipe.json) | Admission recipe | The three generation stages and their resource/context/identity policy; the derived image pin is still unset |
| [closure.py](closure.py) | Acceptance join | Joins genuine verification of all ten stages with the fixed primary checks ([README](README.md)) |

## Images

The source Claude OCI image is
`sha256:dedc08251681f537d3c4fc8d3e9a3bc70f666bf979946e6daadee35178f0c418`; the
fixed ARM64 CLI file SHA-256 is
`b49be8a5e565bf2d45b50d2de62017b25462131acc9425d2fdb98b8f29c9dce2`. The generator
recomputes the CLI digest and requires `2.1.187 (Claude Code)` from `--version`.
A derived image has its own OCI manifest digest, which the stage plan pins
separately from the source image digest (and from any Docker config ID).

Both Dockerfiles download nothing and fail if a prerequisite is missing. The
generator needs Python 3.10+ and Node 20+ at `/usr/local/bin/node` (the
generator parent's measured path, not `/usr/bin/node`); it exports that binary's
SHA-256 for pinning. The browser image uses `/usr/bin/node` and Playwright 1.64.0
at `/opt/checker`. Builds run on Zed, not the laptop.

The generic runner forces runtime UID 1000 regardless of Docker `USER`. Both
images declare 1000:1000 and make trusted source readable by that user.
Entrypoints require and record UID/GID 1000. `/workspace/state` and
`/workspace/artifacts` must be writable by that user; wrong IDs or missing
mounts fail.

## CLI invocation

The generator keeps the ABI of the original subscription wrapper: a fresh
`CLAUDE_CONFIG_DIR`, `TMPDIR` in writable state,
`--print PROMPT --output-format stream-json --verbose`, `--setting-sources user`,
`--strict-mcp-config`, and a sentinel route. It calls the raw CLI directly with
no tools, because the coding wrapper imports a seed/patch and enables editing
tools. Managed settings say `model:"opus"`, so the exact model is passed on the
command line:

`--model EXACT_ID`, `--max-turns 2`, `--tools ''`,
`--strict-mcp-config --mcp-config '{"mcpServers":{}}'`, `--setting-sources user`,
`--settings '{"disableAllHooks":true}'`, `--disable-slash-commands`,
`--no-session-persistence`, `--print PROMPT --verbose --output-format stream-json`,
with stdin closed.

The prompt argument is limited to 96 KiB, below Linux's single-argument limit;
a larger base/spec projection fails. A failed run is kept as-is and never
retried with weaker flags.

The only authentication input is the injected `DSMACK_SENTINEL_ENDPOINT`, an HTTP
bridge URL ending in one run-local capability segment. As in the wrapper, it
becomes `ANTHROPIC_BASE_URL` and `ANTHROPIC_AUTH_TOKEN`; the sentinel holds
provider authentication upstream. The generator opens no provider credential.
The child environment drops ambient API keys, OAuth tokens, provider URLs, MCP
config and caller `PATH`, and errors do not echo the route value.

## Inputs and contexts

Preparation starts from a read-only **base export**. The source-tree digest is
`SHA256(b"dsmack-bounty-source-tree/1\0" + canonical_manifest_bytes)` with a
literal NUL byte. The stage plan pins repository, commit, full tree, task
spec/prompt and driver/recipe digests. `prepare-generation.py` checks the full
manifest against all source files, then projects
`apps/board/{index.html,logic.js,ui.js}` into a canonical text snapshot.

The generator's public mount holds exactly `base.json` and `spec.txt`.
`base.json` is canonical JSON with keys `schema` (`dsmack-bounty-base-snapshot/1`)
and `files`, a sorted unique list of `{path,content}` rows. A canonical
`dsmack-bounty-generator-input/1` snapshot binds `base_tree_sha256` and the two
sorted `{name,size,sha256}` input rows; its raw SHA-256, distinct from the base
tree digest, is pinned in every generation request.

`generate-1`, `generate-2` and `generate-3` run in separate new containers. Each
gets the same base/spec snapshot and a new empty cwd, HOME and
`CLAUDE_CONFIG_DIR` under `/workspace/state`. The prompt contains only the suite
language plus base and spec.

## Bounds

| Limit | Value |
|---|---|
| Generation | 180 s |
| Version probe / suite validation / process-group reaping | 10 s / 5 s / 5 s per subprocess |
| Whole stage (outer cap) | 240 s |
| stdout / stderr | 1 MiB / 64 KiB |
| Turns | 2 |
| Public input | 512 KiB |

On timeout or overflow the supervisor kills and reaps its process group and
keeps the bounded stream prefix. Temporary HOME/cwd are removed after exit and
live in writable state rather than `/tmp`. The container or guest supervisor
enforces memory, CPU, PID and writable-state limits.

## Identity and result checks

Every assistant message must name a nonempty model and contain no tool-use
block. There must be exactly one CLI init model and one final successful result
with `is_error:false` and 1..2 integer turns. The init model and every assistant
model must equal the request; a mismatch is recorded in `observed-identity.json`
and the transcript with `completed:false`. The final result must be exactly one
canonical declarative JSON suite. Nothing is stripped, extracted or executed.
CLI exit zero and model prose do not count as completion.

## Suite language

[suite-language.txt](suite-language.txt) is what the generator sees;
`suite-contract.mjs` is the executable schema. A suite has exactly
`schema:"dsmack-bounty-browser-suite/1"` and `tests`; each test has exactly `id`
and `steps`. IDs match `[a-z][a-z0-9-]{0,63}` and are sorted and unique. A suite
has 1..16 tests, 2..64 steps per test, and at most 512 steps and 256 KiB. Every
test starts with navigation and contains an assertion. The 16-test limit (closure
allows 64) keeps per-test media within the 64-file manifest bound.

Operations: `navigate` (only `/apps/board/`), `reload`, `fill`, `click`,
`assert_count`, `assert_text`, `assert_value`, `assert_attribute`,
`assert_visible`. Assertions compare exact values. Selectors are a small CSS
grammar: tags, IDs, classes, quoted simple attributes, and child or descendant
combinators. Attribute assertions read only `data-*`, `aria-*`, `title` and
`disabled`. Text is limited to 4096 UTF-16 units and selectors to 240. Unknown
fields, duplicate or noncanonical JSON, floats, truthy booleans and extra
operations are rejected before the browser starts.

## Browser driver

Each test gets a fresh browser context and page with its own trace, video and
screenshot. The driver runs every test ID in order on both trees with the same
suite bytes. The first failing assertion ends that test; the remaining tests
still run.

Only a successful browser read followed by a mismatched assertion yields
`assertion_failed`. Assertions poll for up to 1500 ms; browser calls, navigation
and actions each time out after 5 seconds. A missing or ambiguous action target
is an infrastructure failure, so generators assert that a control exists before
acting on it. Script errors, browser startup failure or crash, popups,
disconnected reads, failed actions, the global deadline, missing media, output
overflow and cleanup failure all prevent completion. A 180-second watchdog
writes infrastructure checks and exits 2, leaving browser/container cleanup to
the external owner. Successful checks are written only after normal teardown and
validation of all media.

The production entrypoint reads `suite.json`, `board-index.html`,
`board-logic.js` and `board-ui.js` from `/workspace/inputs` and serves them from
a small local HTTP server. Route interception allows only exact GET requests for
those assets on the admitted origin/port, blocks remote URLs, queries,
websockets and service workers, and sets a strict CSP. Production runs with the
browser sandbox, no network, read-only root and input mounts, a nonroot user,
bounded writable tmpfs and owned cleanup. Candidate JS runs only in the Chromium
renderer, never in the host Node process. This isolation relies on the kernel,
the container runtime and the Chromium sandbox.

## Files each stage reads

| Stage/driver | Files read |
|---|---|
| Generator | `/workspace/inputs/base.json`, `spec.txt`; image-owned `suite-language.txt`, `suite-contract.mjs`, recipe implementation; the CLI and Node binaries |
| Generated-suite browser CI | `/workspace/inputs/suite.json`, `board-index.html`, `board-logic.js`, `board-ui.js`; image-owned interpreter and validator |
| Native six-check probe | The three board assets plus its admitted `browser.mjs` |
| Full-site fixed browser baseline | `/candidate` HTTP source tree; `/fixed-baseline/SOURCE.json` and four original `*.spec.js`; `/checker/baseline.mjs` and `baseline.config.mjs` |
| Fixed logic diagnostic | Four `apps/{board,flight,puzzle,routes}/test/logic.test.js` plus modules, in an isolated candidate Node process |

Model, judge, snapshot and base pins are command arguments, which the stage
manifest and expected request bind. No code path reads an `audit_passed` field.
The full `primary-review` (S0) stage is described in
[PRIMARY-REVIEW.md](PRIMARY-REVIEW.md); its adapter, which reads the original
base and candidate source, task terms, plan and child evidence, lives in the
parent integration.

## Output

All JSON read by closure is canonical UTF-8: sorted keys, no trailing
whitespace, no duplicate keys or nonfinite values. SHA-256 is always over the
original bytes.

Generation writes the generation-checks fields `schema`, `completed`,
`requested_model`, `observed_model`, `suite_sha256`, `base_tree_sha256`. On
success it also exports `suite.json`, `input-snapshot.json`,
`observed-identity.json`, `transcript.jsonl`, `stderr.txt`, `version.txt`,
`prompt.txt` and `generation-outcome.json`. A failure keeps whatever originals
exist plus a negative checks object and infrastructure outcome. Runs are never
overwritten; a retry is a new run.

Browser `checks.json` has exactly `schema:"dsmack-bounty-ci-checks/1"`,
`browser_started`, `completed`, `infrastructure_failed`, `tests`, `suite_sha256`.
On completion each test row is exactly `{id,status}` with status `passed` or
`assertion_failed`, in suite order; closure rejects incomplete runs. Errors go
in `driver-details.json`. Per-test `test-01.png`, `test-01.zip`, `test-01.webm`
etc. are required and nonempty, including for behavioral failures. Limits:
16 MiB per file, 64 MiB total, 64 manifest entries. The outer export limits must
allow this envelope.

Both tools write `output-manifest.json` inside the output mount: canonical
`dsmack-bounty-output-manifest/1` listing every other regular file as sorted
`{name,size,sha256}` rows, excluding itself. The genuine-verifier adapter passes
its authenticated bytes as `VerifiedOutputs.manifest_bytes` and exactly the
listed files as `files` (the manifest itself is not in `files`). Parent
verification recomputes the file set and hashes; transport manifests are a
separate layer.

`generate-i`'s `suite_sha256` becomes the input-suite hash of both `base-i` and
`candidate-i`. The parent allocates all ten run IDs and requests, pins image,
source, driver, profile and input digests, runs the genuine verifier for every
stage, and joins them with `closure.py`. All three bases must fail a behavioral
assertion, all three candidates must pass every test, and `primary-review` must
pass the fixed 4 browser + 4 logic + 6 feature checks.

## Tests

Local, with no browser, model, credentials, install or network:

```sh
python3 -m unittest discover -s applications/bounty-judges -p 'test_*.py' -v
node applications/bounty-judges/test_browser_driver.mjs
git diff --check
```

They cover fresh three-judge fake contexts, model mismatch, fixed binary
refusal, input/spec/source swaps, extra candidate/other-suite slots, malicious
grammar, stream/turn/output/time bounds, closure-compatible bytes, full ID
membership, sentinel ABI with no provider credentials, wrong UID/missing Node,
browser/media/cleanup failures and the watchdog. Host browser lifecycle tests use
a test double with a socket-free server, since the worker sandbox denies
loopback binding. [browser-controls.mjs](browser-controls.mjs) runs real
renderer controls (positive, base-negative, script error, syntax error, network,
host import) in the admitted browser image on Zed and keeps its originals and
summary even when a control fails.

## Running on Zed

From a reviewed checkout under `/data`, with admitted images and inputs. The
variables are absolute paths and OCI identities chosen by the parent.

```sh
cd /data/PARENT_CHECKOUT
python3 applications/bounty-judges/prepare-generation.py \
  --base "$ADMITTED_BASE_EXPORT" --manifest "$BASE_MANIFEST" --spec "$TASK_SPEC" \
  --base-tree-sha256 "$BASE_TREE_SHA256" --spec-sha256 "$SPEC_SHA256" \
  --output "$NEW_EVIDENCE_ROOT/generator-public"

docker build --network=none --pull=false \
  --build-arg QUALIFIED_CLAUDE_REPOSITORY="$QUALIFIED_CLAUDE_REPOSITORY" \
  -f applications/bounty-judges/Dockerfile.generator -t dsmack-judge-generator:review \
  applications/bounty-judges
docker build --network=none --pull=false \
  --build-arg ADMITTED_BROWSER_IMAGE="$ADMITTED_BROWSER_OCI_REFERENCE" \
  -f applications/bounty-judges/Dockerfile.browser -t dsmack-judge-browser:review \
  applications/bounty-judges
```

Keep the derived OCI layouts and manifests and pin their new digests in the
stage plan. Browser controls run in the admitted browser image with its sandbox
profile:

```sh
docker run --rm --network=none --read-only --user 1000:1000 \
  --cap-drop=ALL --cap-add=SYS_CHROOT \
  --security-opt "seccomp=$ADMITTED_BROWSER_SECCOMP" \
  --memory=1g --cpus=2 --pids-limit=256 --shm-size=256m \
  --tmpfs /tmp:rw,nosuid,nodev,size=128m \
  --mount "type=bind,src=$REVIEWED_JUDGES_SOURCE,dst=/opt/bounty-judges,readonly" \
  --mount "type=bind,src=$OWNED_EMPTY_BROWSER_CONTROL_OUTPUT,dst=/evidence" \
  --entrypoint /usr/bin/node "$ADMITTED_BROWSER_OCI_REFERENCE" \
  /opt/bounty-judges/browser-controls.mjs /evidence/controls
```

An outer 240-second controller bounds create, run, export and cleanup. ARM64
runs happen on native ARM64, not QEMU-user.

Each of the three generator containers runs:

```sh
python3 /opt/bounty-judges/generate.py \
  --public /workspace/inputs --output /workspace/artifacts \
  --cli /usr/local/bin/claude --model claude-opus-4-8 --judge 1 \
  --snapshot-sha256 "$SNAPSHOT_SHA256" --base-tree-sha256 "$BASE_TREE_SHA256"
# Separate new containers and output directories for --judge 2 and --judge 3.
```

This makes a real provider call through the sentinel, whose egress and auth
policy the parent sets. Mount only that judge's two input files read-only, its
empty output directory and a fresh bounded `/workspace/state` writable under
UID 1000, drop all capabilities and apply the recipe bounds. Do not mount a
directory holding other judges' outputs or the candidate. `generate.py` relies
on the container for isolation. The browser entrypoint is
`/usr/bin/node /opt/bounty-judges/browser-driver.mjs` with no network and the
four read-only inputs; whether it is a base or candidate run comes from the
pinned request, not a command-line label.
