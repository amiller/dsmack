# An invited Mac participant: inspect, run, reconnect, deliver

This is the invited pilot's operator-assisted command sequence. Selected signed
inventories have been installed and executed on the existing Mini, including
private import and retained full verification under the final notarized app.
A published release packet with selected source/build provenance and a fresh-Mac
quarantined first-open remain pending. Private maintainer paths below are
illustrative; they are not downloadable release locations.

The signed app stays generic. A separate client selects the task, saves the
claim, imports only the chosen credential through its reviewed harness recipe,
requests execution from the protected coordinator and submits retained evidence.
The website can browse and reconnect; it cannot discover or launch your Mac yet.

## 1. Inspect the selected release without executing it

Obtain an independently reviewed release tag, full source commit, archive URL
and hash, full CodeDirectory digest, Team/bundle identity and expected
entitlements. None may be approved solely by the downloaded candidate. The tag
and capitalized values below are intentional placeholders until a release is
selected; they are not a claim that a downloadable asset exists today.

Use a fresh private directory. Do not import a subscription to inspect a release.
Download the archive as data with your existing trusted download tool; never
pipe a downloaded script into a shell. From the independently inspected checkout:

```sh
python3 runner-vm/source_check.py \
  --source-derivation-sha256 55f235c383e7312f96b862bfdd0709cb7f5f16001691eb29699ec2f1d5106178
python3 tools/release/verify_provenance.py /absolute/private/DsmackRunner.zip \
  --repository amiller/dsmack --workflow release.yml --tag RELEASE_TAG \
  --commit FULL_APPROVED_SOURCE_COMMIT --expected-sha256 INDEPENDENT_ARCHIVE_SHA256
```

The provenance helper's same-repository workflow profile currently rejects
self-hosted builds. The Mini-built preview needs an explicitly reviewed profile;
removing this check is not a workaround. A real hosted positive verification
has not been demonstrated. See [the release runbook](../release/runner-release.md).

**Published packaging and integrated Mac staging remain release gates.** The
reviewed [alpha installer source](alpha-install.md) is available in this candidate;
its complete released-archive journey is not yet qualified. Use the selected
extractor and manifest once shipped, or have the operator provide the already
verified staged app for a maintainer rehearsal. Do not substitute unrestricted
`unzip` or bypass Gatekeeper. On the extracted Mac bundle, without launching it:

```sh
codesign --verify --deep --strict --verbose=4 /absolute/verified/DsmackRunner.app
codesign --display --verbose=6 /absolute/verified/DsmackRunner.app
codesign --display --entitlements - --xml /absolute/verified/DsmackRunner.app
spctl --assess --type execute --verbose=4 /absolute/verified/DsmackRunner.app
python3 tools/release/inspect_runner.py \
  /absolute/verified/DsmackRunner.app/Contents/MacOS/dsmack-runner \
  --expected-cdhash INDEPENDENT_FULL_SHA256_CD_DIGEST \
  --expected-team INDEPENDENT_TEAM_ID --expected-bundle INDEPENDENT_BUNDLE_ID
```

Source/provenance, Apple signing, Gatekeeper and App Attest answer different
questions. Development signing on the maintainer's provisioned Mac does not
qualify an arbitrary friend's Mac. A new app signature/CDHash requires its own
accepted enrollment/qualification. Do not use the old `runner/sign.sh` to build
this VM runner; [runner-vm](../../runner-vm/README.md) has the selected source.

### Distribution precondition for another Mac

The selected alpha distribution route is Developer ID Application signing with
an all-device provisioning profile and notarization. It does not require each
participant's Mac to be registered. The older Apple Development profile covered
one registered Mac and belongs to the engineering route, not the intended public
alpha onboarding.

As of 22 October 2026, the final exported app independently passed signature,
all-code-page, stapled-ticket and direct macOS distribution checks. Its full
CodeDirectory SHA-256 is
`6b9baf8b20a1212adb6e9d08a36b8dd66c471dffb9d870ef1ac75413bfebd64d`;
its executable SHA-256 is
`7616deeb7a461ada6a4dc9b092177229295a9059c6f9acdf117b4c580c1ebd17`.
The selected Developer ID team is `DC9JH5DRMY`. Fresh App Attest enrollment passed
for that exact final identity with production environment and certificate
category 6. Export/re-signing changed the prior app identity: older enrollment
must not be reused. These dated hashes identify checked evidence; obtain trust
roots and an actual release inventory independently before using a download.

The qualification Mac had global Gatekeeper assessments disabled. Direct
signature, ticket and distribution checks passed; a quarantined first-open on a
fresh Mac remains a separate qualification gate. Execution under this final
identity has passed on the existing Mini; browser-to-Mac self-service launch
is still unwired. Do not substitute the old Node release.

The current native qualification requires Apple silicon and macOS 27. Linux
source tests used Node 24; the selected protected Mac runtime closure has actual Mini qualification.
The bootstrap also requires Python 3. Obtain the selected release's exact runtime
closure, download/expanded/free-disk plan and VM resource limits before staging.
Xcode and a signing account are maintainer build dependencies, not ordinary
participant prerequisites. See [alpha staging](alpha-install.md) and the
[inspection explainer](https://amiller.github.io/dsmack/build.html).

### Disk space and cleanup after each run

Ask for the selected profile's peak disk-space estimate before starting. It must
cover the expanded release, temporary VM disks, retained results and a free-space
reserve; download size alone is not enough. Run stages serially when the machine
cannot hold their temporary disks together.

Cleanup is part of finishing a test, including a failed test. In the current
operator-assisted pilot, the operator first retains the original result and
attestation files, records verification or failure, and confirms the VM and its
helper have stopped. Only then does the operator remove the run's temporary
scratch disks and staged public copies, recording reclaimed space. Keep one
active expanded release and only the older archive needed for the next transfer.
This cleanup remains operator-assisted; it is not a self-service client command.

Do not delete the only copy of result evidence, your saved claim, credentials,
inputs needed by queued work, or a VM whose state is still uncertain. Reclaiming
disk space does not turn a failed run into a passing task, and deleting temporary
files does not establish secure erasure.

Apple documents [Developer ID distribution](https://developer.apple.com/developer-id/).
A production App Attest environment is not a distribution certificate category.
No account changes or signing actions are performed by these inspection commands.

## 2. Run cheap, read-only host checks

Prepare one private state directory and keep it for the assignment:

```sh
umask 077
mkdir -p /absolute/private/pilot-state
chmod 700 /absolute/private/pilot-state
node applications/pilot-client/pilot.mjs doctor --workspace /absolute/private/pilot-state
```

This reports OS family/architecture, Node major version, available disk and
memory. It performs no VM or network probe and always says launch_ready=false.
Apple silicon/macOS family alone does not prove HVF entitlement, required OS
version, free capacity under load, provisioning, enrollment or a valid subscription.

Before claiming or importing credentials, stage the independently selected
runtime closure and protected policy under an owned 0700 home directory, such as
`~/.local/share/dsmack/pilot`. Every ancestor must be root-owned or user-owned,
without symlinks or group/world write permission. A group-writable source
checkout can be inspected but is not a protected runtime staging tree. The
current client does not install or authenticate that closure for you.

The next diagnostic must use the exact reviewed image, network helper and
protected coordinator to launch a bounded credential-free VM, demonstrate actual
network reachability and clean shutdown. That portable diagnostic package and
fresh-Mac run are current qualification gaps. Do not import credentials to debug
missing image/helper/build dependencies. Browser acceptance has a separate
resource/security profile and cannot inherit the old one-GiB scratch envelope.

## 3. Read terms and obtain a durable invitation

The pilot still requires operator authorization to claim; there is no anonymous
signup, wallet ownership proof or automatic earning eligibility. Browse first:

```sh
BOUNTY_URL=https://YOUR_SELECTED_SERVICE \
  node applications/bounty-demo/cli.mjs tasks
BOUNTY_URL=https://YOUR_SELECTED_SERVICE \
  node applications/bounty-demo/cli.mjs show TASK_ID
```

Review the exact issue, full base revision, immutable acceptance profile, allowed
changes, time/resource/disclosure plan, funded state, judge budget, authority and
failure/recovery terms. Displayed proposed amounts do not reserve funds.
A real paid pilot additionally needs accepted exact funding/settlement terms.

With the invitation operator credential in a protected file, claim once:

```sh
BOUNTY_URL=https://YOUR_SELECTED_SERVICE \
BOUNTY_TOKEN_FILE=/absolute/private/operator-token \
  node applications/bounty-demo/cli.mjs claim TASK_ID WORKER_LABEL PAYEE_ADDRESS \
  --out /absolute/private/attempt.json
```

The client saves its capability before HTTP. If the response is lost, retry the
identical command and SAME file. Do not create another assignment. Open this
file with the website's **Open saved attempt** to reconnect after reload: the
file is read locally, and the capability remains in tab memory. Never upload or
commit the file, or paste its capability into chat/URLs.

See [the operator-assisted Mac handoff](operator-assisted-mac.md) for exact exchange files and the local Darwin import command.

## 4. Obtain the admitted enrollment/import/launch recipe

After the cheap checks and credential-free diagnostic pass, the operator must
supply a protected policy bound to this exact assignment, selected manifest,
image/helper/app identities and fresh challenge. Its closure attempt_id must
match the independently selected native execution ID and S0 request.run_id. The
saved Store application attempt_id is a separate identity bound inside the public
request; do not copy it into the native closure. Reusing the historical demo's challenge,
context or private paths will be refused. Enrollment is a genuine ceremony, not
a caller-supplied readiness checkbox; disclose the Apple request and persistent
local key. The actual protected coordinator supports enrollment, but a portable
service-facing enrollment/package workflow is not supplied by this client.

Review the pinned harness-specific credential importer. Import only explicitly
allowed fields into its declared private destination. Do not copy the entire
Claude/Codex home, config, hooks, rules, MCP, skills, SSH keys or history. A local
operator or host root may inspect VM state; this pilot does not promise secrecy
from that operator. The private inputs in the completed demo were uncommitted.
No credential importer command is invented here: the qualified Claude path and
separate reviewed private Codex sample must be packaged with their own recipe.
This CLI never reads a subscription credential or falls back to an API key.

The current qualified route uses the signed release profile/task admission and
reviewed alpha coordinator described in [alpha runtime](alpha-runtime.md). Use
that package's exact prepare → check-only → execute/resume interface, selected
native execution ID, private JIT importer and independent run context. A browser
reconnect restores the saved claim; it is not a VM checkpoint or a second launch.

The following `pilot.mjs` plan/run examples document the **historical journal
prototype**. They are not the supported lowering route for the current profile3
paid recipes, whose Store and native execution IDs differ. Do not use the
prototype to construct a current native admission. Its source and commands are
retained for inspection of the earlier journal design.

Historical plan inspection used the reviewed coordinator and an explicitly
trusted absolute Python interpreter:

```sh
node applications/pilot-client/pilot.mjs plan \
  --attempt-file /absolute/private/attempt.json \
  --policy /absolute/private/EXECUTION-POLICY.json \
  --coordinator /absolute/verified/coordinator.py \
  --expected-coordinator-sha256 INDEPENDENT_COORDINATOR_SHA256 \
  --python /absolute/trusted/python3 \
  --out /absolute/private/launch-plan.json
node applications/pilot-client/pilot.mjs check --plan /absolute/private/launch-plan.json
```

The coordinator must include its pinned modulepack and original independent
app/helper/final reviews. `plan` binds local identities; it does not authenticate
online task terms, the service or a funding transaction. `check` delegates to the
actual reviewed coordinator's check-only path; a successful check does not launch
or prove execution. Preserve its diagnostics privately. Source/policy changes
require a new reviewed selection, not a hash copied from a refused candidate.

## 5. Current launch route and historical journal example

For a current release, follow the signed profile/task admission and alpha
coordinator route linked above. The following commands belong only to the
**historical journal prototype**; they are not current profile3 launch commands.
They document the older once-only journal behavior after its operator selection:

```sh
node applications/pilot-client/pilot.mjs run \
  --plan /absolute/private/launch-plan.json \
  --state-dir /absolute/private/pilot-state --execute
node applications/pilot-client/pilot.mjs resume \
  --plan /absolute/private/launch-plan.json \
  --state-dir /absolute/private/pilot-state
```

A stable local journal is written/fsynced BEFORE execution, keyed by public
server origin and attempt ID. A repeated launch with that journal refuses even
if the first outcome is uncertain or nonzero. Resume reads state; it never retries
or starts another model job. Keep the same state directory. This is not a global
network lease or a defense against malicious same-UID/root copying/replacement.

The original protected coordinator owns app/helper/VM lifecycle and the admitted
runtime bound. This wrapper is not another supervisor or cancellation protocol.
Closing a terminal does not prove the VM stopped or entitle a refund. An
interrupted launch-request journal means inspect the original coordinator
session and retained output before any explicit recovery decision. Controller
exit0 is advisory: execution_verified, task_accepted and payment_received remain
false in this client's output.

## 6. Retain, verify, submit and collect separately

Keep the original AppOUT and coordinator session. Use the independently reviewed
full evidence transport/verifier; do not replace it with a host-authored success
JSON or an unrestricted extraction of result.img. The qualified transport retains
21 declared app evidence files and excludes five named stage/scratch residues;
private scratch/cache and raw model text remain private. The delivery digest
must come from authenticated evidence and the candidate must pass its exact
immutable acceptance procedure. Those verifier/recipe components are separate
release dependencies, not implemented by this journal adapter. The
[selected full Linux verifier package](../../applications/pilot-client/verifier/README.md)
now provides pinned source, environment checks and original CLI interfaces. It
has verified fresh actual production Mini evidence with selected authority; each
new run still requires its independently selected context and verifier authority. Its prepared-bundle
transfer CLI does not replace the separately reviewed raw Mac AppOUT transport.

After reviewing the actual source and retained evidence, submit the frozen
candidate/bundle identities through the saved attempt:

```sh
BOUNTY_URL=https://YOUR_SELECTED_SERVICE \
  node applications/bounty-demo/cli.mjs submit \
  --attempt-file /absolute/private/attempt.json /absolute/private/submission.json
```

Submission is idempotent for identical content and rejects conflicts. The trusted
verification authority supplies its own bound certificate; the worker cannot
set verified=true. A failure, missing evidence and verifier outage need distinct
operator recovery decisions. Verification retries should reuse retained outputs
where possible, without charging another coding run.

A settlement credit is claimable; a successful withdrawal and confirmed receipt
establish payment received. Returned funds after expiry may require close and
withdraw steps. No payment happens merely by running these CLI commands.

## Operator and agent safety ladder

Proceed only with the exact selected release and task at each step:

1. Inspect source, trust root, inventory and resource/private-data plan without
   importing credentials. `doctor` reports prerequisites; it never grants launch.
2. Authenticate installation, OS checks and fresh device enrollment. Inventory
   signatures do not replace source/build provenance or Apple checks. Run the
   separately selected credential-free diagnostic before claiming or importing.
3. Claim once and retain the protected saved attempt. Reconnect/reload that same
   claim; do not create another claim after a lost browser connection.
4. Import only the selected credential projection through the reviewed private
   JIT route. Plain credential files are secret input, not arbitrary config.
   The trusted Mac owner/root can inspect plaintext VM inputs.
5. Prepare and check-only, then execute only the independently selected fresh
   challenge. Advisory progress is phase feedback, not a VM checkpoint or proof.
6. Receive original outputs and run the nonce-consuming verifier once. Preserve
   failures and journals; retained verified evidence supports later inspection.
7. Independently evaluate the full acceptance graph before certification. A
   controller success, model output or passing browser diagnostic earns no payout.
8. Show settlement credit, withdrawal receipt and actual received balance as
   separate facts. A refund is a different requester flow at its real deadline.

The [runtime contract](alpha-runtime.md) distinguishes profile/task versions,
Mini evidence, app versus Linux base identity, and remaining distribution limits.
