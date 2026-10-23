# io-contract-consumer — producer/verifier agreement for the v3 run-result (SWIFT04)

This directory is the **consumer adapter + independent producer/verifier golden
vectors** the loop40-swift-repair1 review (SWIFT04) required. It demonstrates that
the launcher's producer bytes (`app-src/Sources/mar/RunResultEnvelopeV3.swift` +
`V3Launch.swift`) satisfy the frozen `io-contract-reference` contract exactly.

## The three signed-byte corrections it pins

| member | repair1 (rejected) | repair2 (this candidate) | reference authority |
|---|---|---|---|
| envelope digest **E** | `sha256(bare envelope)` | `sha256_obj([ENVELOPE_DOMAIN, envelope])` | `statement.py:146-147` |
| result preimage | `NUL(domain, **M**, E, challenge)` | `NUL(domain, **L**, E, challenge)` | `statement.py:40-53` |
| envelope `status` | `"finalized"` | `"halted"` | `schemas.py:167` |

`L` = launch-evidence digest (`execution_evidence_digest(receipt_evidence_body)`);
`M` = `sha256(compose-manifest bytes)`; `E` = the domain-separated envelope digest.

## Files

- `gen_golden.py` — the **producer**: emits the exact bytes the Swift launcher
  must write, using the frozen `canonical_bytes`/`sha256_obj` (imported read-only
  through the hash-gated `frozen.py`). Deterministic; `--check` re-derives and
  compares to committed bytes.
- `consumer.py` — the **verifier + adapter**:
  - `adapt_v3_statement_to_reference()` normalizes the launcher's
    `dsmack-general-launcher/v3-run-statement/1` document into the reference
    `STATEMENT_SCHEMA` shape (drops the extra `result_assertion` member, rewrites
    the schema string) so `statement.authenticate_statement` can authenticate the
    launch binding and return `(N, L)`. **This is the consumer adapter the review
    said was missing.**
  - `consume()` validates the envelope via `schemas.validate_envelope_body`
    (which enforces `status == "halted"`), recomputes `E`, `M`, `L`, both
    assertion preimages, and binds the producer's `result_assertion` diagnostic to
    the recomputed `L`/`E`.
  - a negative suite proves the three repair1 defects are **refused** by the
    reference (status `finalized` → `bad_envelope_status`; bare-envelope `E` ≠
    domain-separated `E`; `M`-preimage ≠ `L`-preimage; a statement that binds `M`
    in `result_assertion` → `result_assertion_L_mismatch`).
- `vectors/` — committed golden bytes: `manifest.bin`, `envelope.<case>.json`,
  `statement.<case>.json`, `backend-run-result.<case>.json`, `case.<case>.json`,
  `INDEX.json`. Two cases: console complete and console truncated.
- `swift/` — the **producer-side** golden harness. `run_golden_swift.sh` compiles
  the REAL pure sources (`CanonicalJSON.swift`, `AssertionEvidence.swift`,
  `RunResultEnvelopeV3.swift`) + a 3-line shim + `GoldenMain.swift` with `swiftc`
  and asserts the production `parseRunResultV3` → `composeRunResultEnvelope` →
  `resultAssertionClientData` reproduce the committed golden bytes. It links NO
  Darwin framework and does NOT build the app, so it runs on any Swift+CryptoKit
  toolchain (the Mini). On a host with no `swiftc` it exits 3 (SKIP).

## Run

```
python3 gen_golden.py           # (re)emit vectors
python3 consumer.py             # verifier + adapter + negative suite  (RUN on Zed/Linux)
swift/run_golden_swift.sh       # producer harness                     (RUN on the Mini)
```

`consumer.py` is runnable offline on Zed/Linux (pure Python + the frozen
reference). Evidence of a passing run is in `../evidence/consumer-run.log`.

## Scope boundary

This is the PRODUCER↔contract agreement only. The enrollment-bound
`dsmack.runresult-pair-evidence/1`, the Apple-core assertion verification, staged
extraction and the signed report are the operator/verifier gate (REF lane),
outside this Swift lane. The launcher retains both raw assertions + recovered
counters + client-data digests (`pair-retention.json`) so that gate can compose
the frozen pair evidence from authenticated bytes.
