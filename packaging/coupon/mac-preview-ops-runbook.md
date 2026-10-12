# Mac preview operations runbook (sanitized placeholders)

Companion to [`tools/mac_preview_status.py`](../../tools/mac_preview_status.py) for the
one historically qualified public-testnet preview issuer admission; redemption is currently paused and unqualified on the operator Mac. Scope:
reading the operator-recorded inventory and preparing, reviewing and describing
operator actions. Every `<ANGLE-BRACKET>` item is a PLACEHOLDER the owner fills on
the operator host under its own review. Nothing here is a live target command, and
no procedure in this file performs a network call, SSH session, deployment, restart,
renewal, key read, process kill or provider operation.

## Qualification truth this runbook never changes

- One historically qualified issuer admission, with redemption currently paused and unqualified: the public-testnet PREVIEW issuer/admission.
- Managed private staging: **not qualified**. Private dev/reference apps: running
  but not a managed fleet and not independently qualified. Production: **not deployed**.
- Independent participant count stays unknown; it is never inferred from relay or
  probe activity.
- Automatic reboot recovery is **not qualified**. A host reboot requires explicit
  admission reconciliation, not a blind container restart.
- Custody truth is unchanged by any procedure here: state remains owner-readable
  and rollback protection remains unqualified. Reading status, backing up or
  restarting does not upgrade it.
- Running-but-obsolete apps (`historical_pilot`, `superseded_unused`,
  `idle_old_holder`) are later-reviewed retirement candidates only. Nothing here
  retires, stops or cleans them up.

## 1. Read the current sanitized status

```sh
python3 tools/mac_preview_status.py \
  --inventory <OWNER-READABLE-INVENTORY-PATH> \
  --now <CALLER-CURRENT-UTC-TIME>
```

- `--now` is required and must be the caller's real current UTC time; the reader
  has no clock of its own and never re-ages a stored verdict.
- `observation_status` is `fresh` up to 90 seconds of age, `stale` after that, and
  `unknown` when the observation is more than 30 seconds in the future. Missing,
  malformed or unknown input fails closed: no status is exported. Never copy a
  previous output forward as if it were current.
- `inventory_observation_fresh` is only an operator-attributed observation. It is not claiming
  readiness, not provider/model admission and not peer membership.
- `claiming_available` additionally requires a fresh inventory observation,
  over 650 seconds of owner authorization, a valid policy window, gas/provider
  readiness and observed absence of maintenance. The inventory schema carries no
  gas, provider or maintenance channel, so the reader reports `false` and names the
  unobserved predicates in `claiming_blockers`. Actual readiness is checked at the
  OFFER/CLAIM boundary; status never substitutes for it.

## 2. Graceful idle restart (operator placeholders)

1. Record the pre-state: the step-1 output plus the reviewed adapter inspection
   `<ADAPTER-INSPECT-COMMAND-PLACEHOLDER>`. Require zero issuing jobs and an idle
   READY shape. If a job is active, stop: no token, config or service change
   happens mid-issuance.
2. Take the full volume backup and full SQLite/WAL table fingerprint **before**
   rotation: `<VERIFIED-FULL-BACKUP-COMMAND-PLACEHOLDER>` and
   `<FULL-SQLITE-FINGERPRINT-COMMAND-PLACEHOLDER>`. Refuse to continue when the
   fingerprint differs from the recorded pre-state or a claim raced the backup.
   Backups stay private.
3. Restart only the pinned idle workload with the approved command
   `<OPERATOR-APPROVED-IDLE-RESTART-PLACEHOLDER>`. No credential belongs in any
   argv, environment, unit file or log.
4. After restart, re-run step 1 with a fresh `--now` and require the **same**
   `issuer_peer` and `issuer_compose_sha256` as the pre-state, then run the genuine
   public probe from an independent client:
   `<REVIEWED-PUBLIC-PROBE-COMMAND-PLACEHOLDER>`. A restarted port is not the same
   signer/peer; only the matching fresh probe is evidence.
5. Refuse ambiguous retry. Any failure after mutation intent stays
   `reconciliation-required`: inspect the protected marker, rotated owner records,
   container and backup, then reconcile explicitly
   `<RECONCILIATION-MARKER-INSPECT-PLACEHOLDER>`. Never automatically repeat a
   renewal POST, stop/start or readmission, and never treat a restarted admission
   as replacement entitlement for an already delivered credential.

## 3. Local checks

```sh
python3 -m unittest tools/test_mac_preview_status.py
```

These are offline, credential-free checks. They qualify the reader only: not a Mac
build, a restart, custody, a TEE deployment, managed-environment separation or any
provider interaction. Automatic reboot recovery and managed DEV/STAGING/TESTNET/PROD
separation remain unqualified until separately reviewed evidence exists.
