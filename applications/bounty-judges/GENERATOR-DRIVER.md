# Independent generator and declarative browser driver

This is implementation for the **new Opus 4.8 pilot policy**, using fixed Claude
Code **2.1.187**. It does **not** fulfill the historical three-Claude-5.5 bounty
terms. Nothing here signs an acceptance certificate, verifies a genuine run,
authorizes payment, launches a VM, or contacts a contributor. This document and
the source are the concrete contract for independent Astra/parent review.

The local controls use fake CLI/browser implementations. **No real generation,
browser-image build, native ARM64 execution, or ten-stage acceptance has been
qualified by this change.** The model ID `claude-opus-4-8` in the draft recipe is
an explicit requested ID, not a claim that the provider recognizes or returned
it. The parent must validate the exact requested/observed identity policy before
freezing the actual stage plan; aliases and fallbacks fail closed.

## Components and trust boundary

| Component | Executed authority | Inputs and result |
|---|---|---|
| [prepare-generation.py](prepare-generation.py) | Trusted preparation only | Recomputes existing full base tree manifest/digest, checks pinned spec, exports only three admitted board source files and spec |
| [generate.py](generate.py) | Trusted bounded CLI supervisor | One judge per process/container, pinned binary, fresh context, stream transcript, identity, validated suite and generation checks |
| [suite-contract.mjs](suite-contract.mjs) | Shared trusted validator | Exact bounded JSON grammar, canonical UTF-8 suite bytes, no generated executable code |
| [browser-driver.mjs](browser-driver.mjs) | Trusted external Playwright interpreter | Same suite bytes for base/candidate, closed IDs, renderer-only candidate JS, screenshots/videos/traces and CI checks |
| [generation-recipe.json](generation-recipe.json) | Draft admission recipe | All three generation stages and finite resource/context/identity policy; actual derived image pin still unset |
| [closure.py](closure.py) | Existing unchanged acceptance join | Requires original genuine verification of all ten selected stages and original fixed primary checks |

The source qualified Claude OCI is
`sha256:dedc08251681f537d3c4fc8d3e9a3bc70f666bf979946e6daadee35178f0c418`;
the fixed ARM64 CLI file SHA-256 is
`b49be8a5e565bf2d45b50d2de62017b25462131acc9425d2fdb98b8f29c9dce2`.
These are supplied qualification pins, not newly observed runs. The generator
recomputes the CLI file digest and requires `2.1.187 (Claude Code)` from
`--version`. Any derived image has a **new** OCI manifest digest and must be
selected independently in the frozen plan. Never reuse the source image digest
as the derived image identity or confuse an OCI manifest with a Docker config ID.
Both Dockerfiles are source recipes, perform no dependency downloads, and refuse
missing prerequisites. The qualified generator parent's measured Node path is
`/usr/local/bin/node`, **not** `/usr/bin/node`; no symlink or package install is
introduced. The generator requires Python 3.10+ and that Node 20+ binary; its
observed file SHA-256 is exported and needs pinning during qualification. The
browser parent's `/usr/bin/node` is valid; its image requires Playwright 1.64.0 at
`/opt/checker`. No builds or installs belong on the laptop.

After SSH was unavailable, the parent supplied the original public Dockerfile,
subscription wrapper and managed settings; their supplied hashes were checked.
The wrapper uses a fresh `CLAUDE_CONFIG_DIR`, writable state for `TMPDIR`,
`--print PROMPT --output-format stream-json --verbose`, `--setting-sources user`,
`--strict-mcp-config`, and a sentinel route. The new generator preserves that
ABI, replaces the coding-tool allowlist with no tools, and passes the model and
bounds explicitly. Managed settings currently say `model:"opus"`; that is not
observed Opus 4.8 identity. The raw fixed CLI is invoked directly rather than the
coding wrapper, which would import a seed/patch and enable editing tools. Extra
generation flags, model resolution and absence of ambient instructions/plugins
still require qualification against the actual admitted image. Source inspection
does not establish a real model call or image/network admission.

The generic runner forces runtime **UID1000** regardless of Docker USER metadata.
Both image recipes declare 1000:1000 and make trusted source readable by that
user. Production entrypoints require/record UID/GID1000. Qualification must test
actual state/output/input permissions under that UID, not infer them from USER.
Writable `/workspace/state` and `/workspace/artifacts` must be writable by that
runtime user. Missing writable mounts or wrong IDs fail closed. Image metadata
alone proves no execution boundary.

## Closed inputs and three independent contexts

Preparation starts from a stable, privately staged read-only **base export**, not
an arbitrary working checkout. The existing source-tree domain is preserved:
`SHA256(b"dsmack-bounty-source-tree/1\0" + canonical_manifest_bytes)`, with a
literal NUL byte. The parent independently pins repository, commit, full tree,
task specification/prompt and driver/recipe digests in the immutable stage plan.
The preparation tool checks the full manifest against all source files, then
projects `apps/board/{index.html,logic.js,ui.js}` into a canonical text snapshot.
This is an explicit bounded base projection, not a claim to supply a full repo.

The public generator mount has exactly `base.json` and `spec.txt`. No candidate,
other suite, transcript, operator planning directory or credential file belongs
there. `base.json` is canonical JSON with exact keys `schema` and `files`, schema
`dsmack-bounty-base-snapshot/1`, and sorted unique `{path,content}` rows. A separate
canonical `dsmack-bounty-generator-input/1` snapshot binds `base_tree_sha256` and
the two sorted `{name,size,sha256}` input rows. Its raw SHA-256 is independently
pinned in every generation request. The admitted base tree and snapshot digests
are distinct. A matching caller-supplied hash alone does not admit source bytes.

Run `generate-1`, `generate-2`, `generate-3` in separate new containers. Each gets
the **same** pinned base/spec snapshot and a new empty cwd, HOME and
`CLAUDE_CONFIG_DIR` under writable `/workspace/state`. Only the
trusted language plus base/spec enters the prompt. No candidate or previous
suite is inspected to guide retries. The only authentication input accepted is
the generic injected `DSMACK_SENTINEL_ENDPOINT`, a validated HTTP bridge endpoint
ending in one run-local capability segment. As in the qualified subscription
wrapper, this becomes `ANTHROPIC_BASE_URL` and `ANTHROPIC_AUTH_TOKEN`; the sentinel
owns provider authentication upstream. No provider credential or credential file
is accepted/opened by this code. The child environment drops ambient API keys,
OAuth tokens, provider URLs, MCP config and caller PATH. Only the admitted
sentinel route is set, with value-free errors. No route/auth is provisioned here.

The command explicitly passes `--model EXACT_ID`, `--max-turns 2`, `--tools ''`,
`--strict-mcp-config --mcp-config '{"mcpServers":{}}'`, `--setting-sources user`,
`--settings '{"disableAllHooks":true}'`, `--disable-slash-commands`,
`--no-session-persistence`, `--print PROMPT --verbose --output-format stream-json`,
with stdin closed. Prompt arguments are bounded to 96 KiB, below Linux's single
argument limit; larger base/spec projections fail instead of switching transport.
Compatibility of these flags with the actual pinned binary remains a real-run
qualification gate; failure is retained, never retried with weaker restrictions.

The supervisor bounds generation to 180 seconds, stdout to 1 MiB, stderr to
64 KiB, turns to 2, and public input to 512 KiB. Version probing adds at most
10 seconds, suite validation 5 seconds, and owned process-group reaping 5 seconds
per subprocess; the outer stage must cap the whole workload at 240 seconds.
It kills/reaps its owned process group on timeout or output overflow and retains
the original bounded stream prefix. Temporary HOME/cwd are removed after exit.
The external container/guest supervisor must enforce memory, CPU, PID and writable
state bounds as well. Temporary files use the writable state context, not an
assumed writable `/tmp`. No new compose tmpfs key is required by the generator.
CLI exit zero and a model's prose cannot award completion.

Every assistant message must contain a nonempty observed model and no tool-use
block. There must be exactly one CLI init model and one final successful result,
with a strictly typed `is_error:false` and 1..2 integer turns. Every assistant
model and the init model must equal the explicit request. Mismatch observations
remain in `observed-identity.json` and the transcript, with `completed:false`.
The final result must contain only a canonical valid declarative JSON suite.
No markdown stripping, arbitrary code extraction or execution takes place.

## Browser language and classification

[suite-language.txt](suite-language.txt) is the generator-facing reference;
`suite-contract.mjs` is the authoritative executable schema. The suite has exact
keys `schema:"dsmack-bounty-browser-suite/1"` and `tests`; tests have exactly `id`
and `steps`. IDs match `[a-z][a-z0-9-]{0,63}` and are sorted/unique. There are
1..16 tests, 2..64 steps per test, and at most 512 steps/256 KiB per suite. Every
test starts with navigation and contains an assertion. Closure's 64-test bound
is deliberately narrowed to 16 so per-test media fits its 64-file manifest bound.

Allowed operations are `navigate` (only `/apps/board/`), `reload`, `fill`, `click`,
`assert_count`, `assert_text`, `assert_value`, `assert_attribute`, and
`assert_visible`. Assertions use exact values, not regexes or generated code.
CSS is a small grammar of tags, IDs, classes, quoted simple attributes and child
or descendant combinators: no Playwright selector engines, pseudo selectors,
escaping, URLs, regexes, imports, eval, shell or filesystem access. Attribute
assertions only read `data-*`, `aria-*`, `title` and `disabled`. Text is bounded
to 4096 UTF-16 units (the stricter executable limit); selectors to 240. Unknown
fields, duplicate/noncanonical JSON, floats, truthy booleans and extra operations
refuse before browser startup. There is no suite-controlled resource limit.

For each test, the driver opens a fresh browser context and page, with separate
trace/video/screenshot. It runs every ID in order on **both** trees with the same
exact suite bytes and driver. The first failing assertion terminates that test;
all other test IDs still execute. This ordinary per-test termination is not a
selected subset or retry. There is no conditional/skip/discovery facility.

Only successful browser reads followed by a mismatched declared assertion can
produce `assertion_failed`. Assertions poll at most 1500ms; browser API calls,
navigation and actions each have a 5-second infrastructure timeout. Missing or
ambiguous **action** targets are infrastructure failures. Generators are told to
assert control presence explicitly before acting, so absent base functionality
can fail meaningfully. A syntax/import/runtime script error, browser startup
failure/crash, popup, disconnected read, failed action, global deadline, missing
media, output overflow or cleanup failure always prevents completion. A 180-second
hard driver watchdog writes infrastructure checks and exits 2; the external
owner must then clean up all browser/container processes. No successful checks
are written before normal owned teardown and validation of all required media.

The production entrypoint reads only flat `suite.json`, `board-index.html`,
`board-logic.js`, `board-ui.js` from `/workspace/inputs`. The trusted interpreter
is in the measured image, never selected by candidate source. It snapshots only
these local regular assets into a small HTTP server. Route interception permits
only exact GET requests to the admitted origin/port/board assets, blocks remote
URLs/queries/other fixtures, blocks websockets/service workers, and sets a strict
CSP. Production requires the browser sandbox, an external network-none profile,
read-only root/input mounts, nonroot user, bounded writable tmpfs and owned
cleanup. Candidate JS executes only in the Chromium renderer; candidate packages,
scripts and JS are never imported into the host Node process. These controls
still trust the kernel/container runtime and Chromium sandbox.

## Output envelope and unchanged closure join

### Exactly consumed measured files and the primary-review boundary

| Stage/driver | Files actually read | What is not consumed by that driver |
|---|---|---|
| New generator | `/workspace/inputs/base.json`, `spec.txt`; image-owned `suite-language.txt`, `suite-contract.mjs`, recipe implementation; exact CLI and Node image binaries | No candidate, other suite, full source archive, stage-plan JSON or closure JSON |
| New generated-suite browser CI | `/workspace/inputs/suite.json`, `board-index.html`, `board-logic.js`, `board-ui.js`; image-owned browser interpreter and validator | No full repo tree, task terms, stage-plan JSON, generation transcript or execution closure |
| Existing native six-check probe | Three flat board assets plus its admitted `browser.mjs` | No independent judge suites, full-site browser baselines, plan or child evidence join |
| Existing full-site fixed browser baseline | `/candidate` HTTP source tree; `/fixed-baseline/SOURCE.json` and four original `*.spec.js` files; immutable `/checker/baseline.mjs` and `baseline.config.mjs` | No generated-suite closure or actual genuine child verification |
| Existing fixed logic diagnostic | Four `apps/{board,flight,puzzle,routes}/test/logic.test.js` plus modules in its isolated candidate Node process | Candidate Node self-reports cannot authenticate acceptance or share the privileged browser interpreter |

Generator model/judge/snapshot/base pins are explicit command arguments. The
parent must bind those exact arguments in the measured declared stage manifest
and independently expected request. Neither code path reads an arbitrary JSON
`audit_passed` field. The generic public envelope must actually declare/stage the
files it supports; do not assume an unsupported `commitments` object is consumed.
The pending generic optional file-only commitment extension belongs to its owner
and stays application-neutral. This change does not modify the base VM.

Full `primary-review` (S0) still needs measured declared files for original base
and candidate source/manifests, task terms, immutable plan, selected drivers and
the complete child result/evidence closure. Its trusted application adapter must
read/recompute them and run the original fixed checks plus genuine child join.
A declaration alone does not prove consumption. That S0 assembly/adapter is a
parent integration gate, **not implemented or qualified by this driver**. The
six-check probe cannot be relabeled full S0 by adding an unconsumed JSON audit.

### Result bytes

All JSON consumed by closure uses canonical UTF-8 with sorted keys, no trailing
newline/whitespace, duplicate keys or nonfinite values. SHA-256 always hashes the
original bytes. Generation emits the exact existing generation-checks fields:
`schema`, `completed`, `requested_model`, `observed_model`, `suite_sha256`,
`base_tree_sha256`. Success also exports `suite.json`, `input-snapshot.json`,
`observed-identity.json`, `transcript.jsonl`, `stderr.txt`, `version.txt`, `prompt.txt`
and `generation-outcome.json`. Failures retain available originals, a negative
checks object and infrastructure outcome. A frozen run is never overwritten;
any retry is a separately selected run under parent policy.

Browser `checks.json` has **exactly** `schema:"dsmack-bounty-ci-checks/1"`,
`browser_started`, `completed`, `infrastructure_failed`, `tests`, `suite_sha256`.
Every successful-completion test row is exactly `{id,status}`, with `status`
`passed` or `assertion_failed`, in the full generated order. Incomplete runs may
have missing/infrastructure rows; closure refuses them. Detailed errors go in
`driver-details.json`. Per-test `test-01.png`, `test-01.zip`, `test-01.webm`, etc.
are required and nonempty even for behavioral failures. Each file is limited to
16 MiB, with 64 MiB total browser output and at most 64 manifest entries. The
outer export limits must explicitly support this new envelope; the earlier
single-probe 16 MiB total output allowance is not inherited silently.

Both tools write `output-manifest.json` **inside** the writable output mount.
This canonical `dsmack-bounty-output-manifest/1` envelope lists all other regular
files in sorted order with `{name,size,sha256}`; it excludes itself to avoid a
self-hash cycle. The genuine-verifier adapter passes its authenticated bytes as
`VerifiedOutputs.manifest_bytes` and exactly its listed files as `files`.
The envelope is not also inserted into that files dictionary. Any transport
manifest remains a separate layer. Parent verification must recompute the file
set and original hashes; a worker-written envelope is not authentication.

`generate-i`'s output `suite_sha256` must become **both** `base-i` and
`candidate-i` input-suite hashes. Generation hashes are outputs, never fields
retroactively patched into a funded generation request/profile. The parent
independently allocates all ten unique run IDs/requests, pins actual image/source/
driver/profile/input digests, runs the genuine original verifier for every stage,
and joins them with `closure.py`. All three bases need a meaningful behavioral
failure, all three candidates must pass every test, and `primary-review` must
still pass all original fixed 4 browser + 4 logic + 6 feature checks. No generated
suite or this driver replaces the fixed primary checks. Calibration does not
prove suite completeness, model honesty, or application correctness.

## Validation and Zed handoff commands

Lightweight local controls (no browser, model, credentials, install or network):

```sh
python3 -m unittest discover -s applications/bounty-judges -p 'test_*.py' -v
node applications/bounty-judges/test_browser_driver.mjs
git diff --check
```

Tests cover fresh three-judge fake contexts, model mismatch, fixed binary refusal,
input/spec/source swaps, extra candidate/other-suite slots, malicious grammar,
stream/turn/output/time bounds, strict closure-compatible bytes, full ID
membership, sentinel ABI/no provider credentials, wrong UID/missing Node,
browser/media/cleanup failures and the hard watchdog. Host browser
lifecycle controls use a test double, including a socket-free server because this
worker sandbox denies loopback binding. [browser-controls.mjs](browser-controls.mjs)
adds real renderer positive/base-negative/script-error/syntax-error/network/host-
import controls for the already admitted image on Zed. Its originals and summary
are retained even if a control fails. It is still not native attested evidence.

The following are **parent-owned commands on Zed under `/data`**, after copying
this reviewed source and admitting images/inputs. Variables denote independently
selected absolute paths and OCI identities, not values to infer from a worker.
No pushes, publishing, real provider calls or VM launches are performed by these
documentation examples. Builds require prerequisites already in the source image.

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

Retain derived OCI layouts and actual manifests, pin their **new** digests in the
stage plan, and review settings before real use. Run actual browser controls with
the existing admitted browser image and its existing sandbox profile:

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

An outer 240-second owned-container controller must additionally bound create,
run, export and cleanup. Native ARM64 is required for ARM64 qualification; no
QEMU-user success/failure substitutes for it. These Docker commands are diagnostic
controls, not a genuine-verifier adapter or settlement run.

After final admission and just-in-time auth staging, the entrypoint for each of
the **three separate** generator containers is:

```sh
python3 /opt/bounty-judges/generate.py \
  --public /workspace/inputs --output /workspace/artifacts \
  --cli /usr/local/bin/claude --model claude-opus-4-8 --judge 1 \
  --snapshot-sha256 "$SNAPSHOT_SHA256" --base-tree-sha256 "$BASE_TREE_SHA256"
# Separate new containers and output directories for --judge 2 and --judge 3.
```

This is a future real provider operation: parent owns the explicit admitted
sentinel egress/auth policy and execution decision. Mount only that judge's two
public input files read-only, its empty output writable and fresh bounded
`/workspace/state` writable under actual UID1000. Drop all capabilities and apply
recipe bounds. Never mount the parent directory
holding other judge outputs or the candidate. `generate.py` does not itself
create container/network/VM isolation. Browser child entrypoint is
`/usr/bin/node /opt/bounty-judges/browser-driver.mjs`, with network none and the
four flat read-only inputs. Its role/source identity is pinned by the original
request, not inferred from a `base` or `candidate` command-line label.

Remaining parent gates: independent source review; verify binary/CLI flags/model
identity/settings; build and measure selected images; run real browser controls;
freeze immutable plan and public-input audit; execute/verify all independent
child runs and fixed primary review; adapt authenticated outputs; then perform
native original-evidence closure. No acceptance or payment claim is made here.
