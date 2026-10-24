# Arcade testnet pilot service

A Node 24 stdlib HTTP and SQLite service for the deterministic board-search
bonus. No npm install or build. Run tests:

```sh
node --test applications/arcade-pilot/service/core.test.mjs applications/arcade-pilot/chain/work-escrow.test.mjs
```

The service stores API state and files. App Attest registration, per-attempt task
preparation, verification of the 21 original evidence files and WorkEscrow
authority run on a trusted Zed worker, which reports verdicts through the worker
API. The pod holds no deployer, report or worker-wallet secret. Settlement goes
through a trusted EOA bridge.

## Deployment inputs

The operator supplies Node 24, the reviewed `cast` executable and its SHA256, a
persistent private `/data`, and a mode-0600 JSON `ARCADE_CONFIG` with:

- `dbPath`: `/data/state.sqlite`; `root`: `/data/evidence` (0700).
- `origin`: exact HTTPS origin, e.g. `https://pod.dstack.soc1024.com`.
- `basePath`: `/arcade-pilot`; `port`: 8080.
- `cast`: `{path:"/usr/local/bin/cast",sha256:"<actual64hex>"}`.
- `worker_token_sha256`: SHA256 of a 32-byte base64url worker token generated
  for the worker. Only the worker holds the token.
- `task`: public immutable object with `slug`, `policy_sha256`,
  `app_policy_sha256`, `repository`: `amiller/bounty-arcade`, optional
  `candidates` (display suggestions), `chain_id`: 84532, `contract` (lowercase
  address), `task_id` (receipt-derived decimal string), plus the public terms,
  checker, image, fee, reward and instructions descriptors.

The task is fixed for a given SQLite state; changing it is refused. Put the
funding receipt and task terms in the task object. The sample config has no
financial authority or task ID: the coordinator creates and funds the bonus,
assigns the wallet through its allocator and configures the runtime worker
before deployment.

Build from a source-only context containing the three directories and the
reviewed `cast`, passing `--build-arg NODE_IMAGE=node@sha256:<digest>`. Mount a
persistent named volume at `/data` without publishing it. The proxy needs body
limits of at least 4 MiB for chunks, HTTPS and a persistent process. The pinned
`cast` performs EIP-191 signature recovery directly, without a shell.

## Participant HTTP API

JSON bodies are limited to 512 KiB and original file chunks to 4 MiB. Attempt
writes use `Authorization: Bearer <client-generated 32-byte base64url capability>`.
The capability stays private: it never appears in URLs or public status. Browser
writes must be same-origin; the CLI can omit Origin. Agent discovery: `GET /agent.json`.

1. `GET /api/task`: the published task.
2. `POST /api/authorization-challenges`
   `{request_id,purpose:"attempt"|"registration",payee,candidate_commit}`;
   registration uses `candidate_commit:null`. Returns
   `{authorization_id,message,expires_at}`. Sign that exact message locally with
   EIP-191 `personal_sign`. The message binds origin, task and policy, purpose,
   wallet, commit, request ID, a fresh nonce and expiry.
3. `POST /api/attempts`
   `{request_id,candidate_commit,payee,authorization_id,wallet_authorization:{signature},capability}`.
   Any lowercase 40-hex commit in the published repository can be registered.
   The task factory resolves that commit from the repository or its PR refs,
   builds the base39 projection and accepts changes only to the three board
   files. Callers cannot pass a repository, URL, branch, ref or path. An exact
   retry returns the same attempt; altered retries and replays are refused.
4. `POST /api/registrations/challenge`
   `{request_id,payee,authorization_id,wallet_authorization:{signature},node_capability}`.
   The client generates and keeps a private 32-byte base64url `node_capability`.
   Returns `{schema,registration_id,challenge_b64,expires_at,app_policy_sha256}`.
5. `POST /api/registrations`
   `{registration_id,key_id,attestation_b64,client_data_b64,payee}` queues
   attestation verification. `GET /api/registrations/:id` returns the state and
   public enrollment package. The worker checks the canonical enrollment
   clientData against the original challenge before verifying with Apple.
6. `POST /api/attempts/:id/execution`
   `{request_id,mode:"self"|"best_effort",key_id}`. `self` uses an enrolled key;
   `best_effort` may pass null. Returns `pending_job_id`; once prepared, the
   attempt status contains the server-selected execution packet. Trust root,
   command, policy, file paths and verifier are all fixed by the server.
7. `POST /api/attempts/:id/evidence`
   `{request_id,files:[{name,bytes,sha256}]}` lists exactly the 21 original app
   files and returns `submission_id` and `chunk_bytes`. Upload each with
   sequential `PUT /api/attempts/:id/evidence/:submission_id/:name`, raw body and
   `Content-Range: bytes START-END/TOTAL`; full file hashes are checked. Finish
   with `POST` to the same path plus `/complete` `{request_id}`. A partial write
   with unknown outcome is kept and blocks overwrites. Final verification runs
   once; an error stays an error.
8. `GET /api/attempts/:id` returns public status. `GET /claim` returns current
   claim data and status. Capability-authenticated `POST /claim` `{request_id}`
   queues a fresh, journaled chain observation once the attempt has a full
   passing verdict; exact retries return the same job. The flow is: submit the
   commitments, get signatures once the task is actually Submitted, then
   resolve, withdraw and received. Signatures are issued only after fresh checks
   of chain, task, assignment, payee, commitments and deadline.

The public site connects a browser wallet, signs authorizations and shows
status. Its submit, resolve and withdraw buttons require chain 84532 and the
fixed contract, payee and value. A broadcast hash shows as pending until escrow
records it. The service never funds, sends transactions or runs models.

## Worker API

Uses the separate worker Bearer token, the fixed task and HTTPS:

- `POST /api/worker/lease` `{worker_id,capabilities:[registration|prepareExecution|verifyEvidence|claim]}`.
  Returns 204 if there is no job, else
  `{job_id,lease_id,lease_expires_at,action,input,input_sha256}`, where the
  digest is SHA256 of the canonical wire input. Each job is leased once; an
  expired lease is not redelivered. The worker persists its intent and cached
  result before any nonce, enrollment or signing action, and reconciles any
  uncertain state.
- `POST /api/worker/jobs/:id/result`
  `{lease_id,input_sha256,status:"completed"|"uncertain"|"failed",result}`.
  Exact cached retries are idempotent; a conflicting result is refused.
- `GET /api/worker/jobs/:id/files/:name` fetches evidence files. Wire inputs
  contain no pod paths; the worker checks bytes against the descriptors.
- `POST /api/worker/jobs/:id/artifacts` `{lease_id,files:[{name,bytes,sha256}]}`
  then sequential 4 MiB `PUT /api/worker/jobs/:id/artifacts/:name` uploads the
  five preparation artifacts: checker-context.json, closure-context.json,
  workload-admission.json, workload.sig, workload.img. Complete, rehashed files
  are served at `/api/artifacts/:job/:name`.

An accepted verification publishes the attempt's 21 originals plus the signed
`report.json` and the key's `enrollment.json` at
`/api/artifacts/:submission_id/:name`. The host calls `backfillEvidence()` at
startup to publish attempts accepted earlier.

Registration output has `registered_key_id`, `enrollment_sha256` and the public
package. Execution output binds the market `attempt_id` and `key_id`, plus a
`native_execution_id` and the packet and artifacts defined by the runner.
Verification output binds `attempt_id`, `payee`, `candidate_commit`,
`policy_sha256`, `manifest_sha256`, `report_sha256`, `verification_level:"full"`
and `accepted`. An accepted verdict also requires `apple_verified`,
`outputs_verified` and `functional_pass` true, `expected_exit_code:0` and
`receipt_status:"completed"`. The worker derives these from full verification
and recomputed checker, input and output correspondence.

Mac nodes lease with their private node capability at `POST /api/nodes/lease`
`{key_id,request_id,capability}`, where `capability` is a fresh upload
capability for the attempt. It returns one prepared best-effort packet bound to
that node, or 204. An exact retry returns the same packet; the client keeps its
own run-once journal. The node capability grants no service authority, and the
participant's payee and commit stay fixed whoever owns the node. With no node
available, the attempt stays queued.

## Limits and retention

Defaults: 20 attempts, 100 registrations, 1000 authorizations and jobs, 8 GiB
total submitted evidence, 1.5 GiB per attempt, 1 GiB per result image and 32 MiB
per other original file. Disk and reserved-descriptor quota are checked before
uploads. Protected configuration can lower these limits. Expired authorizations
are kept as replay history and removed only by explicit operator maintenance.
Evidence and uncertain scratch are never deleted automatically. Wallet,
capability and token values stay out of public logs. The operator is
responsible for backing up the private volume and keeping HTTPS up.
