# Contributing to dsmack

Read README.md first; each step names the code that implements it. Keep changes
bounded, use a topic branch or `tools/dev-worktree.sh`, and get an independent
review before integration.

Python verifier development:

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 -m pytest -q tests
```

Contract setup and test commands are below. The runner and the Mac experiments need
an Apple silicon Mac on macOS 27 and a signing identity with App Attest; Linux
checks do not qualify them. See `runner/README.md`. Keep component state in
ignored `local-data/`. Some scripts sign apps or drive a remote Mac; do not run
them as documentation checks.

Tie evidence claims to their revision, device and conditions. Documentation
changes need link checks and `git diff --check`.

For the Linux leaf-circuit and contract checks, run from the checkout root.
Install prerequisites: Python 3 with pip, curl, tar, dpkg-deb, and flock.
The installer pins nargo beta.17, bb 3.0.3, Foundry 1.8.5 and both solc versions.
Set `ATTEST_TOOLS` explicitly to an absolute directory outside all worktrees
to share one installation. env.sh rejects missing binaries and tools resolved
outside that directory; install before sourcing it. Compiler,
CRS, package caches, downloads and temporary files live there; copied circuit
builds remain ignored under each checkout's `tools/attest-build`.

```sh
export ATTEST_TOOLS=/absolute/path/to/attest-tools
app-attest/circuit/install.sh
. app-attest/circuit/env.sh
python3 -m pip install --target local-data/python cryptography
export PYTHONPATH="$PWD/local-data/python"
python3 app-attest/contracts/test/make-intermediates.py
forge test --root contracts --offline --use "$SOLC"
forge test --root app-attest/contracts --offline --use "$SOLC"
```

The intermediate generator must run before `forge test`. Tests use the
Apple captures committed in `app-attest/contracts/fixtures`. They hold the
attested key, App ID, app and OS versions, validity window and our nonce; no
device identifier.

Run the separate rule-coverage corpus from the checkout root:

```sh
python3 app-attest/corpus/generate.py
python3 app-attest/corpus/run.py solidity
python3 app-attest/corpus/run.py circuit
python3 app-attest/corpus/report.py
```

Generate real proofs (also checks installed nargo/bb versions against pin.json),
then build the verifier artifact before running LeafEnrollmentTest:

```sh
app-attest/circuit/measure-leaf.sh
(cd app-attest/contracts/verifier && forge build --offline --use "$ATTEST_TOOLS/bin/solc-0.8.27")
FOUNDRY_PROFILE=real forge test --root app-attest/contracts --offline --use "$SOLC" --hardfork osaka --match-contract LeafEnrollmentTest --fork-url https://sepolia.base.org --fork-block-number 48371278 -vv
(cd app-attest/circuit/gas && forge test --offline --use "$ATTEST_TOOLS/bin/solc-0.8.27" --match-contract CompareLeafTest -vv)
forge test --root app-attest/contracts --offline --use "$SOLC" --hardfork osaka --fork-url https://sepolia.base.org --fork-block-number 48371278 --match-test 'test_GasAssertionNativeP256|test_AssertionCost' -vv
```

LeafEnrollmentTest checks the verifier artifact metadata's source keccak256
against the committed HonkVerifierLeaf.sol before deploying its bytecode.
Rebuild the artifact whenever that source changes. Regenerated verifier output
stays under ignored `proofs/leaf`, outside the gas project's source tree.
