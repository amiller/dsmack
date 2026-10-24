# Read-only attempt feeds

`project.mjs` uses Node 24's built-in `node:sqlite`; no dependency install is
needed. Import `readArcadeSource(config, {now})`, `readLegacySource(config,
{now})` and `mergeFeeds(feeds)`, or run `node project.mjs CONFIG.json`. `now`
is Unix seconds. The JSON configuration contains `sources`, each with `id`,
`kind` (`arcade-pilot` or `bounty-demo`) and a private `db_path`. Paths never
appear in the feed. Missing/invalid databases produce a source error, not an
apparently successful empty list. Readers open SQLite read-only and use a
transactional snapshot; they never import the services or instantiate stores.

For ArcadePilot, configure `task: {task_id, chain_id, contract, slug,
repository, title?, issue_number?}` from the actual selected service task.
`public_base_url` is the existing HTTPS pilot URL including its prefix.
An optional `artifact_root` overrides the database parent. The reader examines
only attempts, evidence submissions, and public artifact descriptors. Prepared
admission deadlines are read only from a size/hash-checked public admission
artifact. Expired prepared/queued records become `needs_attention`, retaining
`reported_state`; this does not assert that a native execution failed. Missing
deadline evidence leaves expiry unknown. No private worker URLs are invented.

Historical Store configuration uses `task_mappings`, selected from authenticated
chain getter package hashes matched to the exact retained `terms_sha256`.
Mappings contain `package_hash`, `policy_hash` (retained provenance), `task_id`,
`chain_id`, and `contract`; `assignment_id` is optional only when separately
proven. The caller must authenticate that mapping/provenance. Duplicate matches
are unknown, never first-match guesses. Unmapped attempts remain visible with
`task_key: null`. Historical `running` is a recorded state, not live-process
status. Legacy submission hashes do not establish byte counts or upload
completion, so these fields remain null.

The explicit field projection omits authentication, capabilities, wallet
signatures, nonces, local paths, logs and raw reports. `task_metadata` is optional
public context derived from selected task records; consumers should mark
conflicting titles/mappings unknown. `latest_record_created_at` is the latest
record creation timestamp, **not** a claim of a recent status update. Source
`observed_at` records this read; verification fields describe recorded verifier
results, not independent re-verification by the dashboard.

Run focused controls with `node --test applications/bounty-dashboard/feeds/project.test.mjs`.
