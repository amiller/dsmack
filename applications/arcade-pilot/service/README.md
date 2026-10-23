# Arcade deterministic testnet pilot service

Node24 stdlib HTTP/SQLite service. No npm install/build. Run tests:

```sh
node --test applications/arcade-pilot/service/core.test.mjs applications/arcade-pilot/chain/work-escrow.test.mjs
```

This is a new deterministic browser bonus, not the old three-agent acceptance
protocol. The service does not interpret worker booleans as a verdict. App Attest
registration, per-attempt task preparation, original21 evidence verification and
WorkEscrow authority run on a separately configured trusted Zed worker. The pod
stores durable API state/files; no existing deployer/report/worker-wallet secret
belongs in the pod. Its public bridge is explicitly trusted EOA settlement.

## Deployment inputs (operator selects; never supplied by participants)

Node24, the reviewed `cast` executable and its SHA256, persistent private `/data`,
and a mode0600 JSON `ARCADE_CONFIG`. Fields:

- `dbPath`: `/data/state.sqlite`; `root`: `/data/evidence` (0700).
- `origin`: exact HTTPS origin, e.g. `https://pod.dstack.soc1024.com`.
- `basePath`: `/arcade-pilot`; `port`:8080.
- `cast`: `{path:"/usr/local/bin/cast",sha256:"<actual64hex>"}`.
- `worker_token_sha256`: SHA256 of a separately generated32-byte base64url worker
  token. The worker stores that token privately; no browser/participant receives it.
- `task`: public immutable object with `slug`, `policy_sha256`,
  `app_policy_sha256`, `repository`: `amiller/bounty-arcade`, optional `candidates` (display suggestions only), `chain_id`:84532,
  `contract` (lowercase address), `task_id` (actual receipt-derived decimalstring),
  plus selected public terms/checker/image/fee/reward/instructions descriptors.

Task changes against the same SQLite state refuse. Store actual funding receipt
and immutable task terms in that public task object, not an invented funded flag.
The sample has no selected financial authority or task ID. The coordinator must
create/fund the new bonus, assign the wallet through its selected allocator and
configure the selected runtime worker before deployment is runnable.

Build from a selected source-only context containing the three directories and
reviewed `cast`; pass `--build-arg NODE_IMAGE=node@sha256:<selecteddigest>`.
Mount persistent named volume `/data`; do not publish it. Configure proxy body
limits at least4MiB for chunks, HTTPS and a persistent process. No Mini SSH from
this HTTP container. No shell is used for wallet verification. The pinned cast
performs real EIP191 recovery, not a service callback that accepts client claims.

## Participant HTTP API

JSON body limit512KiB; original file chunks4MiB. All attempt writes use
`Authorization: Bearer <client-generated32-byte-base64url capability>`.
The capability is private, never in URLs/public status. Same-origin browser
writes only; CLI can omit Origin. Agent discovery: `GET /agent.json`.

1. `GET /api/task`: immutable published selection.
2. `POST /api/authorization-challenges` exact
   `{request_id,purpose:"attempt"|"registration",payee,candidate_commit}`;
   registration uses candidate_commit:null. Returns
   `{authorization_id,message,expires_at}`. Sign **that exact** message locally
   with EIP191/personal_sign. Message binds origin, task/policy, purpose, wallet,
   candidate, request ID, fresh nonce and expiry. No private key upload.
3. `POST /api/attempts`
   `{request_id,candidate_commit,payee,authorization_id,wallet_authorization:{signature},capability}`.
   Any lowercase40hex candidate commit may register against the fixed published repository. The trusted factory must resolve that exact immutable commit from this repository/its PR refs, prove the required base39-file projection and permit changes only to the three board files before preparing execution. No arbitrary repository, URL, branch, ref or path is accepted from an HTTP caller. Exact request retries recover the same attempt; altered retries/replays refuse.
4. `POST /api/registrations/challenge`
   `{request_id,payee,authorization_id,wallet_authorization:{signature},node_capability}`.
   Client generates/preserves private32-byte-base64url node_capability. Returns
   `{schema,registration_id,challenge_b64,expires_at,app_policy_sha256}`.
5. `POST /api/registrations`
   `{registration_id,key_id,attestation_b64,client_data_b64,payee}` queues native
   attestation verification. `GET /api/registrations/:id` returns state and
   public enrollment package only. The worker compares exact canonical native
   enrollment clientData against the original challenge before verifying Apple.
6. `POST /api/attempts/:id/execution`
   `{request_id,mode:"self"|"best_effort",key_id}`. self uses an enrolled key;
   best_effort may use null. Returns pending_job_id, then public attempt status
   contains a server-selected execution packet after preparation. No user-selected
   trust root, command, policy, file path or verifier override.
7. `POST /api/attempts/:id/evidence`
   `{request_id,files:[{name,bytes,sha256}]}` exact21 original app files only.
   Returns submission_id/chunk_bytes. Sequential PUT
   `/api/attempts/:id/evidence/:submission_id/:name`, rawbody and
   `Content-Range: bytes START-END/TOTAL`. Full file hashes checked.
   Complete with POST samepath `/complete` `{request_id}`. Unknown partial writes
   retain residue and refuse implicit overwrites. Final verify is once-only;
   errors remain errors, not retried as a successful run.
8. `GET /api/attempts/:id` gives safe status. GET `/claim` is read-only and returns current claim data/status. Capability-authenticated POST `/claim` `{request_id}` queues a fresh once-journaled chain observation only after full bound functional success; exact retries recover the same job. This supports submitting the immutable commitments first, obtaining signatures only after actual Submitted state, then resolve/withdraw/received progression. No prospective signature or fabricated receipt is implied. Signature issuance still requires fresh actual
   chain/task/assignment/payee/commitment/deadline checks in the selected actor.

The public site connects a local browser wallet, signs authorization and displays
safe status. Its submit/resolve/withdraw wallet buttons require the fixed84532
chain/contract/payee/value. Broadcast hashes are explicitly pending, not receipt
or received-payment claims. Service does not auto-fund, send transactions or run
unselected models.

## Privileged worker API

Separate worker Bearer token, fixed task, HTTPS:

- POST `/api/worker/lease` `{worker_id,capabilities:[registration|prepareExecution|verifyEvidence|claim]}`.
  204 if no job; else `{job_id,lease_id,lease_expires_at,action,input,input_sha256}`.
  Digest is SHA256 of canonical **wire** input. A job is leased once; expiry does
  not cause blind redelivery. Worker persists intent/cached result before any
  nonce/enrollment/signing action. Uncertain state requires reconciliation.
- POST `/api/worker/jobs/:id/result`
  `{lease_id,input_sha256,status:"completed"|"uncertain"|"failed",result}`.
  Exact cached retries idempotent; conflicting result refused.
- Evidence files GET `/api/worker/jobs/:id/files/:name` with worker token.
  No private pod paths in wire input. Verify original bytes against descriptors.
- Preparation artifacts POST `/api/worker/jobs/:id/artifacts`
  `{lease_id,files:[{name,bytes,sha256}]}` then sequential4MiB PUT
  `/api/worker/jobs/:id/artifacts/:name`. Exactly five public artifacts:
  checker-context.json, closure-context.json, workload-admission.json,
  workload.sig, workload.img. Only complete rehashed files become packet URLs
  `/api/artifacts/:job/:name`.

Registration output has registered_key_id/enrollment_sha256/publicpackage.
Execution output binds market attempt_id and selected key_id, plus separate
native_execution_id and fixed packet/artifacts defined by the runner lane.
Verification output binds attempt_id/payee/candidate_commit/policy_sha256/
manifest_sha256/report_sha256, verification_level:"full", accepted boolean.
A true verdict additionally requires apple_verified/outputs_verified/
functional_pass:true, expected_exit_code:0, receipt_status:"completed".
The trusted worker must itself derive these from genuine full verification and
recomputed checker/input/output correspondence; this API is not an alternate
certificate-only acceptance policy.

Normal Mac nodes use private node capability at POST `/api/nodes/lease`
`{key_id,request_id,capability}` (fresh client-generated attempt upload capability).
This returns one prepared best-effort packet bound to that enrolled node, or204.
Exact lease retry recovers the same packet; client still uses its own durable
once-run journal. Node capability is never a service-authority token. Participant
payee/candidate remain immutable even when the chosen node has another owner.
No available node is a truthful queued state, not an execution guarantee.

## Bounds and retention

Default20 attempts,100 registrations,1000 authorizations/jobs,8GiB aggregate
submitted evidence,1.5GiB/attempt,1GiB max result image,32MiB other original file.
Disk checks and reserved-descriptor quota precede uploads. These limits can be
lowered in protected configuration. Expired authorization records remain to
preserve replay history; maintenance is an explicit operator action. No evidence
or uncertain scratch is automatically deleted. Wallet/capability/token contents
must not appear in public logs. Private volume backup and HTTPS availability are
operator responsibilities; this is not a storage permanence promise.
