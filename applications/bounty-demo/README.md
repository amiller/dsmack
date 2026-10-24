# Bounty demo application

A bounty board above DsmackRunner: tasks, durable single-worker claims, advisory
progress, immutable submission and an Ed25519 verifier-certificate gate, with a
GitHub webhook receiver. Node.js 24 or later (`node:sqlite`); no npm install.
[PROTOCOL.md](PROTOCOL.md) lists the HTTP operations.

`bounty-settlement/serve-acceptance.mjs` builds the full-evidence acceptance
service on `createApplication` from `server.mjs`.

## Run locally

```sh
mkdir -p local-data/bounty-demo
umask 077
node -e "process.stdout.write(require('node:crypto').randomBytes(32).toString('base64url'))" > local-data/bounty-demo/operator-token
BOUNTY_STATE="$PWD/local-data/bounty-demo/state.sqlite" \
BOUNTY_OPERATOR_TOKEN_FILE="$PWD/local-data/bounty-demo/operator-token" \
node applications/bounty-demo/server.mjs
```

Open `http://127.0.0.1:8787`. Optional environment: `BOUNTY_VERIFIER_KEYS_FILE`
(JSON map of key IDs to Ed25519 SPKI PEMs; without it every verdict is refused),
`BOUNTY_REPOSITORIES`, `GITHUB_WEBHOOK_SECRET`, `PORT`.

The CLI has the same operations:

```sh
node applications/bounty-demo/cli.mjs help
node applications/bounty-demo/cli.mjs tasks
BOUNTY_TOKEN_FILE=local-data/bounty-demo/operator-token \
node applications/bounty-demo/cli.mjs create frozen-task.json
BOUNTY_TOKEN_FILE=local-data/bounty-demo/operator-token \
node applications/bounty-demo/cli.mjs claim TASK WORKER PAYEE --out /absolute/private-dir/attempt.json
```

`claim` saves a fresh capability to the private record before contacting the
service. Retry the same command and file after a lost response. Use the record
with `progress --attempt-file FILE EVENT_JSON`, `submit --attempt-file FILE
SUBMISSION_JSON`, or **Open saved attempt** on the website.

## Observe a running VM

Run where the runner's public console log exists:

```sh
BOUNTY_TOKEN_FILE=attempt-token BOUNTY_URL=http://127.0.0.1:8787 \
node applications/bounty-demo/observe.mjs /path/to/RUN/console-v3.log ATTEMPT_ID
```

It reports lifecycle phases and elapsed heartbeats, never raw log contents.

## Tests

```sh
node --test --test-isolation=none applications/bounty-demo/*.test.mjs
```
