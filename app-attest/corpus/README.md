# App Attest rule-coverage corpus

Run from the repository root on zed:

```sh
. app-attest/circuit/env.sh
python3 app-attest/corpus/generate.py
python3 app-attest/corpus/run.py solidity
python3 app-attest/corpus/run.py circuit
python3 app-attest/corpus/report.py
```

Requires Python `cryptography`, Foundry and solc 0.8.21 at `$SOLC`, exported
by `app-attest/circuit/env.sh`. The Solidity stage selects
`FOUNDRY_TEST=../corpus/test`. Its large local block limit batches independent
P384 checks and is not evidence about transaction gas limits.

Generated JSON, test-root coordinates, generated `RootKey.sol` and logs stay
ignored in `app-attest/contracts/fixtures/local-data/mutations/`. Generate before compiling
the harness in `app-attest/corpus/test`, which is outside Forge's default `test` directory.
Ordinary `(cd app-attest/contracts && forge test --offline)` does not need corpus generation.
Each generation creates fresh ephemeral signing keys; rerun both stages afterward.
Private keys never leave the generator process.

The manifest splits `leaf` and `endorsement` cases. Leaf/authData/DER/CBOR cases
run through production `AppleAttest.enroll`, after endorsing their intermediate
through `AppleEndorsements`, and through `check-leaf.sh`. Intermediate cases run
only through production endorsement. A test subclass overrides the synthetic
root constant, following the endorsement fixture pattern. Real positives retain
the real Apple root. AuthData mutations recompute the nonce and re-sign the leaf;
intermediate mutations are root-signed except the explicit bad-signature case.

Every leaf fixture supplies 24 public fields plus explicit intermediate x/y.
Preparation does not parse malformed DER or CBOR. Public policy stays pinned to
the source fixture; leaf dates reflect date mutations. The circuit has no block
time or endorsement-expiry input, so date disagreements are reported explicitly.
Oversize fixed arrays reject at preparation and are labeled separately.

Duplicate IDs, accumulating same-subject keys, expiry after endorsement, all six
wrong entry-key limbs, issuer/subject mismatch and post-2030 endorsement are
included. Wrong-key cases deliberately corrupt test registry storage; they do
not claim that an unendorsed key can enter production storage.

Public-binding probes change each of fields 0–11 while keeping the witness valid.
Native enrollment derives these values rather than consuming this vector, so its
acceptance versus circuit rejection is expected and reported separately from the
four time-window differences. The ordinary native suite also endorses two keys
with the same subject and rejects a leaf signed by A when entry B is named.

The circuit runner fingerprints its checker sources and the copied source/manifests/compiled bytecode tree, distinguishes preparation
from witness failures, and stops after three consecutive infrastructure errors.
`expected-circuit.json` pins each rejection to file, line and assertion message (or preparation capacity). `report.py` fails on a different site and writes the ignored `app-attest/contracts/fixtures/local-data/mutations/report.md` with verdicts and uncovered require/assert
sites. Logs and the generated corpus are not committed.
