# Bounded unattended coupon operator

This candidate renews one existing NEAR owner session and readmits the same signed
approval into the same pinned container and persistent volume. It does not create
coupons, keys, accounts, policies, guards or infrastructure. It is operator code,
not code to run on a recipient's computer. The operator holds a plaintext refresh
credential and a development Ed25519 approval authority; this is not qualified
private custody or a hardware-protected approval authority.

Use the existing always-on operator host with the existing authority directory.
Install a reviewed, immutable source checkout and its locked dependencies there.
Put the qualified Node 24 binary in `~/dsmack-operator/bin/node`, with its
reviewed version and SHA-256 retained in the private deployment record. This
is an isolated runtime for the coupon-free public probe; it does not replace
other host applications. The service template includes only this dedicated bin
directory plus standard system paths.
Transfer only the separately reviewed private owner records, signed controls and
pinned guest SSH identity/configuration over the authenticated existing operator
channel. Keep them owner-only, outside the checkout. The authority seed stays on
that host. An unattended SSH configuration must use a protected identity file and
pinned host keys, not an expiring forwarded agent. No credentials belong in a
systemd unit, environment, command line, public manifest or status page.

## Private plans

`tools/coupon_testnet_supervisor.py` takes an owner-only JSON plan with exactly
`version:1`, `owner_dir`, `state_dir`, `adapter`, `adapter_sha256`, `adapter_plan`.
The two directories must already exist, owned by the controller user, mode 0700.
The pinned adapter is `tools/coupon_testnet_ops.py`. Its owner-only plan contains
exactly `version:1`, `ssh_config`, `ssh_target`, `container`, `image_digest`,
`volume`, `mount_path`, `approval_file`, `config_file`, `authority_dir`,
`approval_public_key`, `owner_dir`, `state_dir`, `probe_script`,
`probe_script_sha256`, `public_bundle`. All values are operator inputs: do not
publish a filled plan. `image_digest` is the exact Docker image ID; public keys
and SHA-256 pins use lowercase hex. The probe is the reviewed normal client
public issuer probe, using the immutable four-public-file bundle.

The owner directory holds `owner-session.json` and `owner-refresh.json` in the
existing protected format. Renewal uses the original recorded login User-Agent,
the fixed official Cloud API host, one POST, bounded responses, and a same-owner
and organization GET. A valid rotated refresh is durably saved before any access
JWT or identity refusal. Automatic refresh retries are forbidden.

## Single-controller lifecycle

The scheduler owns one flock and inspects every 30 seconds. With less than 30
minutes of access lifetime, it renews only when no issuer job is active and the
configured Base RPC reports sufficient balance and fees for one claim. Before
mutation it fsyncs a reconciliation marker. The adapter:

1. Validates image, volume, disabled container logging, signed controls and the
   exact idle Node plus worker process shape.
2. Signs a configuration changing only the same owner's session JWT.
3. Pauses the container, checks the process shape and full SQLite/WAL table
   fingerprint again, and refuses a raced claim without killing it.
4. Copies the whole frozen volume to a private durable backup. Only an idle,
   unchanged container is killed and started; all rows, bindings, winners,
   journals, reservations, credentials and delivery envelopes are retained.
5. Creates a detached private FIFO holder, sends the two signed frames, waits
   for actual READY, and verifies the full table fingerprint unchanged.
6. Runs the normal fresh public Noise/quote probe before completing the marker.

The fingerprint covers every application table, including historical migration
and binding tables. JWT-only rotation must not change any row. A failure after
refresh intent remains `reconciliation-required`, even after process restart;
there is no automatic repeat of POST, stop/start or readmission. An operator must
inspect the protected marker, rotated owner records, container and backup before
explicitly reconciling it. A failed admission does not authorize a coupon retry.

The supplied [user service](systemd/dsmack-coupon-supervisor.service) is a template;
installing/enabling it and user lingering require the concrete rollout review.
Its fixed paths refer to the reviewed checkout and private plan. Detached holders
survive controller process exit; a host reboot requires explicit admission
reconciliation, not a blind container restart. Monitor the controller on the
always-on host. Do not call this boot recovery until the actual host reboot case
is qualified.

## Status and policy windows

`health.json` is an operator-attributed observation with exactly `state`,
`observed_at_unix`, `claiming_available`. States are `ready`, `unavailable`,
`unknown`, `maintenance`, `reconciliation-required`,
`approval-renewal-required`. Export only these fields through a reviewed public
status renderer; never expose the private directory or adapter outputs. A view
must expire this observation after 90 seconds and treat unknown, stale, failed
renewal, insufficient reserve, or insufficient policy lifetime as unavailable.
WSS reachability from the separate [issuer status tool](../../tools/coupon_testnet_status.py)
is not claiming readiness and is never provider model admission.

Hourly JWT renewal preserves the approval and issuer-pin bytes and the immutable
friend bundle. A signed approval's expiry is independent: this controller refuses
to extend it and reports unavailable 30 minutes beforehand. The stable discovery
URL must resolve the current immutable versioned bundle and status observation;
old bundle expiry remains enforced. Creating a new authority/policy epoch and
preserving prior obligations is a separate reviewed rollout.

## Qualification before enabling

Run the focused offline checks:

```sh
python3 -m unittest tools/test_coupon_testnet_supervisor.py tools/test_coupon_testnet_ops.py
```

After independent source review, fill protected plans on the chosen operator
host. Run `inspect` first, then one supervised `--once` renewal near its ordinary
threshold. Retain sanitized same-owner, unchanged full-state, fresh READY/Noise,
reserve and timing results. Exercise controller restart with a deliberately
incomplete mutation marker in a disposable private fixture: it must refuse
another mutation. Qualifying that one rotation does not qualify a new epoch,
public publication, fleet, private custody or production deployment.
