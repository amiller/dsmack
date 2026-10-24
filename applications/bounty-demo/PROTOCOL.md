# Bounty demo protocol

A bounty board on top of the signed runner, first used for amiller/bounty-arcade.
It records one assignment per task, advisory progress, a submission and a
verifier verdict. It runs no host commands and moves no money. GitHub supplies
task discovery and a place to show results.

Node 24+, standard library only. HTTP binds loopback by default. Errors are
`{error: string}`. Mutating APIs need `Authorization: Bearer <operator-token>`,
except attempt operations, which use the attempt capability returned at claim.
The operator token lives in the CLI/environment, never in the page or URL; the
browser uses a token or capability the user types in.

## Endpoints

- `GET /api/tasks` -> `{tasks:[Task]}`; `GET /api/tasks/:id` -> `{task:Task,attempt:Attempt|null,events:[Progress]}`. Responses never include capability hashes or tokens.
- `POST /api/tasks` (operator) creates frozen task terms `{id,repo,issue_number,title,base_commit,checker_sha256,image_sha256,harness_sha256,reward:{amount,asset,chain}}`. IDs `[a-z0-9-]{1,80}`, repo `owner/repo`, SHA256 fields 64 lowercase hex, base_commit 40 lowercase hex. Reward is display-only with `funding_status:'unfunded'`. The SHA256 of the exact terms is stored; metadata is fixed after claim.
- `POST /api/tasks/:id/claim` (operator) body `{worker,payee,request_id?,capability?}` -> `{attempt:Attempt,token:string}`. One active attempt per task, by invitation. `payee` is an Ethereum-style address; `worker` is a bounded label. For durable claims send both optional fields: `request_id` is 32 random bytes as 64 lowercase hex, `capability` is 32 random bytes as unpadded base64url, both generated and saved before the request. The service stores only hashes of the capability and request body. Repeating the same request ID, task, worker, normalized payee and capability returns the same attempt and capability, even after a lost response or restart; changed terms return 409. Request IDs are unique per service. Plain `{worker,payee}` claims also work but cannot be recovered after a lost response. Every claim and retry needs operator authorization.
- `POST /api/attempts/:id/progress` (attempt capability) body `{phase,kind,counters?}` -> `{event:Progress}`. Phases `launch,boot,pull,agent,review,verify,done`; kinds `phase,heartbeat,tool,usage`. Counters are safe nonnegative integers under 1e12 keyed `turns,input_tokens,output_tokens,elapsed_ms`. No prompts, filenames, arguments, stdout, token values or free text. The server assigns sequence and time. Events are advisory. The browser polls the task every two seconds while it is active.
- `POST /api/attempts/:id/submit` (attempt capability) body `{candidate_sha256,bundle_sha256,commit_sha?}` -> `{attempt:Attempt}`. Submissions are immutable; an identical retry is idempotent, a conflicting one is rejected. `commit_sha` is for display on GitHub; `candidate_sha256` identifies the source.
- `POST /api/attempts/:id/verdict` (operator) body `{payload,signature,key_id}`: an Ed25519 certificate from a configured verification adapter, domain `dsmack-bounty-verdict/1`. The payload matches the frozen task/terms/attempt/nonce/payee/candidate/bundle/checker/image/harness and includes `report_sha256`, `accepted`, `checks:{apple,outputs,functional}`, `issued_at`, `expires_at`. The signature is over UTF-8 canonical JSON (recursively sorted keys, compact separators, no unsafe numbers). `accepted` requires all three checks true. With no configured verifier key every verdict is refused. The attempt moves to `verified` or `failed`. An identical retry is idempotent; stale, substituted or conflicting verdicts are refused.
- `POST /github/webhook`: HMAC over the raw body and durable delivery deduplication, then bounded event handling. The repository allowlist comes from operator config. Issue comments never run commands.

Task states: `open,claimed,running,submitted,verified,failed`. Public attempt fields: id, task_id, worker, payee, nonce, state, created_at, candidate_sha256, bundle_sha256, commit_sha, verdict. Progress: seq, phase, kind, counters, received_at, advisory:true.

On the first successful verdict the server records `verdict_received_at`.
Certificate expiry is checked at that moment; exact retries keep the original
certificate and timestamp, so a retained acceptance stays inspectable after
expiry. Settlement projection checks the configured key, bindings and admission
time. Payment additionally needs a current on-chain assignment, deadline and
signing authorization.

## GitHub module

`github.mjs` exports `verifyWebhook(rawBody, signature, secret)`,
`createAppJwt({appId,privateKey,now?})`, `GitHubAppClient` and
`normalizeWebhook(event,payload,{allowedRepositories})`. The client takes an
injected fetch for tests and defaults to api.github.com. It reads issues and
creates/updates check runs with an installation token; webhooks trigger no
writes, and results are published by an explicit operator CLI command. The local
site needs no GitHub credentials. The app manifest requests issues-read,
checks-write and contents-read.

## Evidence digests

The signed payload's `schema` is its domain separator. For a bounty profile,
`candidate_sha256` is a canonical source-tree manifest digest (sorted
repository-relative paths with regular-file SHA256, length and mode; no links,
traversal or duplicates), `bundle_sha256` is the SHA256 of the delivered evidence
archive, and `checker_sha256` is the acceptance-profile manifest digest. The
profile covers the full base revision, check.yml, check.mjs, acceptance and
baseline tests, dependency locks, architecture-specific image digest,
harness/model configuration, generated-check procedure and artifact requirements.

The verifier adapter authenticates the Apple/native/guest/output evidence,
extracts the delivered source, recomputes its candidate identity, runs the
declared acceptance procedure on those bytes, checks the browser and
generated-check artifacts, and signs a certificate bound to the task terms,
attempt, payee and nonce. The service checks that certificate; App Attest is
verified by the adapter, not on chain here.

For bounty-arcade issue 1, acceptance requires the existing tests plus three
independently generated judge suites, each failing the base and passing the
candidate.

The bounty-arcade checker runs `npm test` inside the patched candidate, so the
candidate's package.json controls the test command. A reward profile runs its
own driver and checker configuration outside the candidate tree.

## Observing a VM

`observe.mjs` turns a public VM console log into advisory
boot/pull/harness-start/export/poweroff phase events and host elapsed heartbeats.
It sends no console content. Agent stdout/stderr are captured only at the end of
the run, so there are no live model-turn events.

Mac enrollment uses App Attest in the runner. This site does not pair with a
Mac, mint node NFTs or check wallet ownership.

## Web UI

`web/index.html`, `web/app.js`, `web/style.css`: same-origin API, no build, no
third-party scripts, no preloaded tokens. It shows task terms, funding status,
claim, live advisory progress, evidence state and the original issue, and keeps
"verified result" apart from "reward paid". API data is never inserted with
innerHTML.

A saved CLI attempt record can be opened to reconnect. It must name this server
origin and match the public attempt ID, task, worker and payee. The browser reads
at most 16 KiB, never uploads the record and never stores credentials; the
capability is held in memory and sent only in the Authorization header. A wrong
capability still gets 401.

The readiness card is derived from the assignment and the in-memory capability.
The activity view shows the last worker/observer event time and the last
successful poll time separately. If a refresh fails, the previous view stays up
with an update warning.

## Durable claim record

`node cli.mjs claim TASK WORKER PAYEE --out PRIVATE_RECORD` writes a fresh 0600
JSON record in a private 0700 directory before any HTTP request. Schema
`dsmack-bounty-attempt/1`: `{schema,state,server,task_id,worker,payee,request_id,capability,attempt_id?}`.
It starts in state `claim-requested` without attempt_id; on success it is
atomically replaced with state `claimed` and the attempt_id, fsyncing file and
directory. After a lost response, rerun the identical command with the same file.
The record is a bearer credential: keep it out of commits and uploads. CLI output
omits the capability. Avoid concurrent use of one record.

`node cli.mjs progress --attempt-file PRIVATE_RECORD EVENT_JSON` and
`submit --attempt-file PRIVATE_RECORD SUBMISSION_JSON` read the record directly.
`BOUNTY_URL` must match its server origin. A record still in `claim-requested`
must be completed with `claim` first. Symlinked, nonregular, multi-link,
foreign-owned, oversized or group/other-readable records are refused.

## Tests

The tests drive the HTTP and browser journey through task creation, claim,
progress, submit and verdict, and check that wrong signatures, tasks, nonces or
content, duplicate claims, stale certificates, forged GitHub deliveries and a
missing verifier key are rejected. They use test-only signing keys and webhook
bodies.
