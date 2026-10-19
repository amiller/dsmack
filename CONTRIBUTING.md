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

Contracts: `cd contracts && forge test`. The runner and the Mac experiments need
an Apple silicon Mac on macOS 27 and a signing identity with App Attest; Linux
checks do not qualify them. See `runner/README.md`. Keep component state in
ignored `local-data/`. Some scripts sign apps or drive a remote Mac; do not run
them as documentation checks.

Tie evidence claims to their revision, device and conditions. Documentation
changes need link checks and `git diff --check`.
