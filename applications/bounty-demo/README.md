# Bounty demo application

This page describes the historical full-repository prototype. The minimal
selected-source archive includes its claim/submission CLI, not the web server,
GitHub adapter or operator deployment. The server setup and tests below require
that separate full checkout and are not runnable from the minimal archive.
Current genuine acceptance uses the separately selected ten-proof service; do
not use the historical certificate-only server as its replacement.

A small application above DsmackRunner: a participant-facing bounty board,
durable single-worker claims, advisory progress, immutable submission and a
trusted Ed25519 verifier-certificate gate. Includes a GitHub App adapter and
authenticated/deduplicated webhook receiver. No npm install or build step.

This is an implemented local workflow prototype. The signed Mac runner has
completed a separate real Claude coding task; that result is not bounty-arcade
acceptance. No real bounty has been awarded by this application.

## Run locally

Node.js 24 or later (uses the built-in `node:sqlite` module):

```sh
mkdir -p local-data/bounty-demo
umask 077
node -e "process.stdout.write(require('node:crypto').randomBytes(32).toString('base64url'))" > local-data/bounty-demo/operator-token
BOUNTY_STATE="$PWD/local-data/bounty-demo/state.sqlite" \
BOUNTY_OPERATOR_TOKEN_FILE="$PWD/local-data/bounty-demo/operator-token" \
node applications/bounty-demo/server.mjs
```

Open `http://127.0.0.1:8787`. The empty state is intentional. In the operator
setup section, create a task using independently frozen acceptance/image/harness
identities; tasks display unfunded. The operator enters the local token manually
to create/invite a worker. The returned attempt capability stays in browser
memory. Keep a private copy if you need to reconnect; it is not recoverable from
the public API. Restarting the browser does not reset the durable claim.

The agent-facing client has the same operations:

```sh
node applications/bounty-demo/cli.mjs help
node applications/bounty-demo/cli.mjs tasks
BOUNTY_TOKEN_FILE=local-data/bounty-demo/operator-token \
node applications/bounty-demo/cli.mjs create frozen-task.json
```

Never put tokens in URLs, issue comments, repository files or recordings. This
pilot has a trusted operator, invitation-based assignment and a loopback listener.
It does not yet implement public account signup, wallet signatures, TLS ingress,
multi-tenant isolation, artifact hosting, quotas, cancellation/reassignment,
payment/recovery contracts or a production deployment.

## Observe a running VM

Run the observer where the runner's **public console** exists, using the private
attempt capability file. The service must be reachable from that host (e.g. a
private SSH tunnel to its loopback listener):

```sh
BOUNTY_TOKEN_FILE=attempt-token BOUNTY_URL=http://127.0.0.1:8787 \
node applications/bounty-demo/observe.mjs /path/to/RUN/console-v3.log ATTEMPT_ID
```

This reports actual host-observed lifecycle phases and elapsed heartbeats only.
It never forwards raw logs, prompts, filenames or tool arguments. Its events are
advisory. A guest poweroff marker is not a passing verdict. Detailed live agent
activity still needs a newly qualified guest telemetry path; final transcript
delivery remains the current source of detailed agent activity.

## GitHub and evidence integration

See [GITHUB.md](GITHUB.md) for the installable App manifest, permissions,
JWT/installation-token adapter and explicitly invoked issue/check operations.
The webhook receiver verifies raw-body HMAC and persists delivery deduplication;
it never executes commands from comments or creates tasks from mutable issue text.

See [PROTOCOL.md](PROTOCOL.md) for HTTP operations and exact trust boundaries.
Configure `BOUNTY_VERIFIER_KEYS_FILE` with a JSON map of key IDs to Ed25519 SPKI
public PEMs. Without a configured verifier key, verdicts fail closed. The verifier
certificate gate is implemented; the genuine bounty-specific verification adapter
is not. A worker-supplied JSON report or a successful final transcript cannot
authorize acceptance. No test signing key is shipped as an operational authority.

## Checks

```sh
node --test applications/bounty-demo/*.test.mjs
```

Tests exercise durable claims/restart, private capabilities, advisory events,
immutable submission/retries, substituted and stale signed certificates, missing
verifier configuration, raw webhook forgery/replay, JWT and repository scope,
and observer privacy. Synthetic signatures are local control fixtures, not Apple
attestations or real bounty acceptance.

Next real milestone: finalize one bounty-arcade acceptance profile; qualify the
ARM64 browser/toolchain harness and all three draft judge runs; connect actual
runner launch and genuine verifier adapter; review the candidate/evidence joins;
register/install the GitHub App; then rehearse one complete unfunded claim.
Funding, settlement and any NFT enrollment are separate explicit steps.

### Recoverable worker claims

Prefer the local CLI over a browser-only invitation. Create an owned private directory (mode 0700), then run `node applications/bounty-demo/cli.mjs claim TASK WORKER PAYEE --out /absolute/private-dir/attempt.json` with the pilot operator token in `BOUNTY_TOKEN_FILE`. The CLI saves a fresh capability before contacting the service, and never prints it. If the response is lost, retry the identical command and file; do not create a second record. Keep the private record to reconnect using **Open saved attempt** in the website, or pass it with `progress --attempt-file FILE EVENT_JSON` / `submit --attempt-file FILE SUBMISSION_JSON`. The website must have the same exact origin as BOUNTY_URL; it reads the file locally into memory without uploading it. See [the protocol](PROTOCOL.md#durable-local-claim-record) for filesystem and recovery limits.
