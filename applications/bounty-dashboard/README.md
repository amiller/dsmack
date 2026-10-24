# Bounty dashboard

Read-only tables for configured bounty contracts, service attempts, uploaded file metadata, verification results, withdrawable balances and actual withdrawal transactions. The interactive Arcade pilot remains a separate application.

The default registry selects the deployed WorkEscrow v2 on Base Sepolia. Registry entries identify the chain, contract, deployment block and exact runtime hash. Additional deployments require explicit registry entries and a supported ABI. This registry is the dashboard's coverage boundary.

The chain collector reads every task and assignment at a pinned block. It indexes canonical events in bounded windows and retains a checkpoint. Task credits and account withdrawals have separate records; pooled withdrawals have no invented task attribution. See [chain/README.md](chain/README.md).

Attempt projections open their configured SQLite stores read-only. They select public metadata, retain reported historical states, and omit capabilities, credentials, raw transcripts and private file contents. See [feeds/README.md](feeds/README.md).

`server.cjs` exports `createHandler(config)` for an HTTP host. Its GET routes serve the dashboard and combined data; an authenticated PUT route accepts the operator's public read model. Private host configuration supplies `data_dir`, `base_path`, `ingest_token_sha256`, `expected_feed_ids` and `stores`. Each store has a stable `id`, `db_path` and optional public task mapping. The ingest token stays with the collector; browsers receive no credential.

`publish.py` normalizes the chain/feed snapshots and sends them to Andrew's dashboard host. `update.py` runs collection, historical export and publication serially every two minutes under one lock. Current pilot records are read live by the web host. Snapshot timestamps and coverage remain attached to the observations.

## Checks

Use Node24 and Python3; no dependency installation is required.

```sh
node --test applications/bounty-dashboard/server.test.cjs \
  applications/bounty-dashboard/web/view.test.mjs \
  applications/bounty-dashboard/feeds/project.test.mjs
python3 -B -m unittest discover -s applications/bounty-dashboard/chain -p 'test_*.py'
python3 -B -m unittest discover -s applications/bounty-dashboard -p 'test_publish.py'
```
