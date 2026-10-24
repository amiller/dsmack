# Contributing to dsmack

Read README.md and AGENTS.md first. Work on a topic branch or
`tools/dev-worktree.sh <name>`.

Tests:

```sh
git submodule update --init
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
export ATTEST_TOOLS=/absolute/path/to/attest-tools
app-attest/circuit/install.sh
./test.sh
```

`install.sh` downloads nargo, bb, Foundry and solc into `$ATTEST_TOOLS`, which
can be shared across checkouts. It needs curl, tar and dpkg-deb; the circuit
scripts need flock.
`test.sh` sources `app-attest/circuit/env.sh` and runs the Python verifier
tests, both Foundry projects, the leaf circuit proofs and tests, and the
real-proof enrollment tests.

Documentation changes need link checks and `git diff --check`.

Release signing and download inspection: [docs/release/runner-release.md](docs/release/runner-release.md).
