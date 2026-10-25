# Bounty dashboard

Read-only tables for configured bounty contracts, service attempts, uploaded file metadata, verification results, withdrawable balances and withdrawal transactions. The interactive Arcade pilot lives in `applications/bounties`.

`server.cjs` exports `createHandler(config)` for an HTTP host. Its GET routes serve the dashboard and combined data; an authenticated PUT route accepts the operator's public read model. Private host configuration supplies `data_dir`, `base_path`, `ingest_token_sha256`, `expected_feed_ids` and `stores`. Each store has a stable `id`, `db_path` and optional public task mapping. The ingest token stays with the collector; browsers receive no credential.

`publish.py` normalizes the chain/feed snapshots and sends them to Andrew's dashboard host. `update.py` runs collection, legacy export and publication serially every two minutes under one lock. Current pilot records are read live by the web host. Each observation carries its snapshot timestamp and coverage.

## Chain collector

```sh
python3 applications/bounty-dashboard/chain/collect.py \
  --state-dir /absolute/persistent/chain-checkpoints \
  --out /absolute/output/chain.json --event-pages 200
```

Standard library only; it reads, never signs or sends. `chain/registry.json` lists the deployments the dashboard covers; the default is the WorkEscrow v2 on Base Sepolia. Each entry gives HTTPS RPC, chain ID, exact runtime SHA256, deployment block/transaction and supported codec. Add a network or contract by adding an entry with a supported ABI. A wrong chain, runtime or unsupported codec reports `unknown` with no balances.

Each getter snapshot reads all task and assignment IDs at one pinned block, checks the runtime and re-verifies the block hash. Wei values and ABI uint fields are decimal strings. Getter data is available before history indexing finishes: `deposited_wei`, creation time/transaction and assignment payouts are null (not zero) until their events are indexed. A resolved payout is a credit; it becomes a payment only when withdrawn.

Event queries use inclusive windows of at most 200 blocks (the official Base Sepolia RPC limit). The persistent checkpoint resumes after its last canonical block; a changed anchor rebuilds indexed history from deployment. Each event requires its successful canonical receipt and exact log membership. One invocation scans at most `--event-pages` windows; run it again to continue. `contracts[].coverage.events_complete` says whether indexing has reached the snapshot, and a failed scan leaves coverage incomplete with an error. Checkpoints are replaced atomically after each successful batch. Keep the state directory across runs and use one collector process per state/output directory.

`TaskClosed` is a requester refund credit in activity. `Withdrawn` events become `payments`: pooled account withdrawals with `task_key:null` and `assignment_key:null`, since the contract does not record which task a withdrawal pays out. `credits[]` reads `withdrawable(address)` at the pinned block for every task requester and assignment worker; these are unwithdrawn credits, kept apart from `payments[]`. Task snapshots also expose the getter roles, effort/completion amounts and submission/review/adjudication windows. Assignment outcomes (`Reject`, `Effort`, `Completion`) come from `Resolved` events and are absent until indexed.

`chain/abi.json` holds the read methods and static event ABI from the WorkEscrow artifact, with fixed selectors/event topics so collection needs no Keccak dependency.

## Attempt feeds

`feeds/project.mjs` uses Node 24's built-in `node:sqlite`. Import `readArcadeSource(config, {now})`, `readLegacySource(config, {now})` and `mergeFeeds(feeds)`, or run `node project.mjs CONFIG.json`; `now` is Unix seconds. The configuration has `sources`, each with `id`, `kind` (`arcade-pilot` or `bounty-demo`) and a private `db_path`, which never appears in the feed. A missing or invalid database produces a source error. Readers open SQLite read-only in a transactional snapshot and never import the services.

For ArcadePilot, configure `task: {task_id, chain_id, contract, slug, repository, title?, issue_number?}` from the service task, and `public_base_url` as the HTTPS pilot URL including its prefix. `artifact_root` optionally overrides the database parent. The reader examines attempts, evidence submissions and public artifact descriptors. Prepared admission deadlines come from a size/hash-checked public admission artifact. Expired prepared/queued records become `needs_attention` and keep `reported_state`; without deadline evidence, expiry is unknown. If `task` is omitted, the reader projects selected fields from the `records(config, task)` row. Set `funded: false` for rehearsals: task keys stay null and task metadata is labelled `Unfunded rehearsal`.

Legacy Store configuration uses `task_mappings`, chosen by matching chain getter package hashes to the retained `terms_sha256`. Mappings contain `package_hash`, `policy_hash`, `task_id`, `chain_id`, `contract` and optional `assignment_id`; the caller authenticates them. Duplicate matches are unknown, and unmapped attempts appear with `task_key: null`. Legacy attempts set `historical: true`; their `running` is the recorded state. Legacy submission hashes carry no byte counts or upload completion, so those fields are null.

Each attempt includes `source_id`. `inputs` and `upload` report their own counts, received bytes and completion; input completion comes from the stored upload manifest. Artifacts have `category: input|evidence` and `visibility: public|metadata_only`, and only a recognized public artifact URL is `public`. `updated_at` is copied from a stored update or verifier timestamp when one exists. `latest_record_created_at` is the newest record's creation time. `observed_at` is the time of this read, and verification fields are the verifier's recorded results. `task_metadata` is public context from task records; consumers mark conflicting titles/mappings unknown. The projection omits authentication, capabilities, wallet signatures, nonces, local paths, logs, raw reports, raw transcripts and private file contents.

## Checks

Node 24 and Python 3; no dependency installation.

```sh
node --test applications/bounty-dashboard/server.test.cjs \
  applications/bounty-dashboard/web/view.test.mjs \
  applications/bounty-dashboard/feeds/project.test.mjs
python3 -B -m unittest discover -s applications/bounty-dashboard/chain -p 'test_*.py'
python3 -B -m unittest discover -s applications/bounty-dashboard -p 'test_publish.py'
```

Direct rewards are listed separately from escrow withdrawals. Add a public
transaction to `chain/direct-payments.json` with its expected chain, sender,
recipient, wei amount and related task/attempt. The collector checks the actual
transaction, successful receipt and canonical block before publishing it as a
`direct_reward`. Unverified selections appear as a source error instead of a
payment. This list contains explicit reward records, not a scan of wallet
outflows; related task labels do not make a transfer an escrow settlement.
