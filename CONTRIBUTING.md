# Contributing to dsmack

Read README.md and AGENTS.md first. Work on a topic branch or
`tools/dev-worktree.sh <name>`.

Tests:

Use Python 3, Node 24+, Deno and Go (the version in the Go modules).

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
`test.sh` runs Python, Node, Deno, Go and the private-agent-web browser tests,
then sources `app-attest/circuit/env.sh` for the Foundry projects, leaf circuit
proofs and real-proof enrollment tests.

Documentation changes need link checks and `git diff --check`.

Release signing and download inspection: [docs/release/releasing.md](docs/release/releasing.md).
