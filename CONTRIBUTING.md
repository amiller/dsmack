# Contributing to dsmack

Start with the charter and coupon/routing journey in README.md. Keep changes
bounded; use a topic branch or tools/dev-worktree.sh. Independent review is
required before integration. No private planning workspace is needed.

Python verifier development uses a disposable virtual environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 -m pytest -q tests
```

Contract work uses `cd contracts && forge test` with the declared Foundry/dependency
setup. Native/runner development requires the component's Mac toolchain and
instructions; Linux checks do not qualify it. Keep component state in ignored
local-data/. Several scripts sign apps, call external services or use a remote
Mac; do not run them as ordinary documentation checks.

Propose the intended user outcome, protocol/authority effects, applicable tests
and remaining limits. Preserve independent participation, identity and coupon
continuity. Treat changed wire identifiers as compatibility work. Use targeted
checks for affected components; documentation needs links and git diff --check.

This local candidate still has imported runner references to older local paths
and evidence. Those are portability blockers, not external contributor prerequisites
to be copied blindly. First-party license, security-reporting route, public issue/PR
home, portable build qualification and supported release ownership remain publication
work. Keep evidence claims tied to their actual revision, device and conditions.
