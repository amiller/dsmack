# Bounty settlement

Joins the ten original stage proofs of a bounty attempt into an acceptance
decision and projects it onto the WorkEscrow contract.

- `acceptance-adapter.mjs` verifies each original signed verifier report against
  configured report keys and stage contexts, authenticates receipts and output
  bytes, checks source delivery and the base-to-candidate relation, and runs the
  ten-stage join. [ADAPTER-CONTRACT.md](ADAPTER-CONTRACT.md) defines its API.
- `acceptance-service.mjs` / `serve-acceptance.mjs` serve that adapter on the
  `bounty-demo` HTTP application.
- `projection.mjs` maps an accepted certificate to an unsigned escrow submission
  and EIP-712 v2 proposal (`packageHash`, `policyHash`, `candidate`, `evidence`,
  `delivery`).
- `chain-observation.mjs` / `chain-service.mjs` read task funding, assignment,
  resolution and withdrawals for the WorkEscrow runtime on Base Sepolia.
- `construct-admission.mjs` builds the per-attempt admission
  ([ADMISSION-CONSTRUCTION.md](ADMISSION-CONSTRUCTION.md)).

## Acceptance service

```sh
node applications/bounty-settlement/serve-acceptance.mjs /absolute/config.json BYTES SHA256
```

The config (`dsmack-bounty-acceptance-service/1`) has keys `schema, state_path,
operator_token, verifier_keys, report_keys, admissions, evidence, repositories,
port`. `verifier_keys` maps certificate key IDs to public PEMs; `report_keys`
maps report key IDs to base64 raw 32-byte public keys. `evidence` maps attempt
IDs to `{path,bytes,sha256}` descriptors of a `dsmack-bounty-original-evidence-files/1`
document (`request`, `results`, and ten `originals` stages with `report`,
`receipt`, `manifest`, `public_inputs`, `outputs`). The server binds 127.0.0.1.

## Local rehearsals

```sh
# Anvil escrow rehearsal: settlement, duplicate resolution, withdrawal, timeout refund.
node applications/bounty-settlement/rehearse-local.mjs /path/to/WorkEscrow.json /new/output-directory
# HTTP walkthrough of the acceptance service with synthetic stage proofs.
node applications/bounty-settlement/walkthrough-local.mjs
```

`rehearse-local.mjs` needs `cast` and `anvil` on PATH (or `DSMACK_CAST`,
`DSMACK_ANVIL`).

## Tests

```sh
node --test --test-isolation=none applications/bounty-settlement/*.test.mjs
python3 -m pytest applications/bounty-settlement
```
