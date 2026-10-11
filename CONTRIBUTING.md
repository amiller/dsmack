# Contributing to Dsmack

Start with the [README](README.md), [architecture](docs/architecture.md) and
[protocol index](docs/protocols/README.md). Use a topic branch or
`tools/dev-worktree.sh <name>`. Independent review is required before integration.

## Checks

Documentation:

```sh
python3 tools/check_docs.py
git diff --check
```

Python verifier and native-fixture regressions:

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 -m pytest -q tests --ignore=tests/test_ios_admission.py
```

The opt-in `tests/test_ios_admission.py` module additionally requires `web3`,
`eth-account` and `ATTEST_ADMISSION_TEST_RPC` pointing to a disposable loopback
Anvil chain. Configure that rehearsal separately before including it.

Coupon, KMS and operator tooling tests live alongside their modules. Run the
focused tests for the affected component. Some checks require extra declared
component dependencies; live RPC, hardware and paid effects require a deliberately
configured environment. The [synthetic package](packaging/coupon/README.md)
provides a credential-free local exercise.

Contract checks use `cd contracts && forge test` with the pinned dependencies
in `contracts/lib/`. Native development requires the [Mac toolchain](docs/native-build.md)
and [runner setup](runner/README.md); Linux checks do not qualify Mac hardware.

## Changes and evidence

Describe the user outcome, protocol/authority changes, checks and remaining limits.
Preserve independent participation, identity and coupon continuity. Treat wire
identifier changes as compatibility work. Tie attestation and privacy claims to
an exact revision, device, policy and observation time.

Keep generated output in `local-data/` or ignored build directories. Commit only
small, documented regression inputs; do not add complete capture directories,
release receipts, screenshots or copies of historical source. Several scripts sign
apps or call external services: do not run them as ordinary documentation checks.
Report sensitive issues through [the security process](SECURITY.md).
