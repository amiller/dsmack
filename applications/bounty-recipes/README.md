# Bounty recipes

`protocol.py` defines the canonical bounty request, source tree manifest and
digests shared by `bounty-develop`, `bounty-judges` and `bounty-runtime`.
`protocol.synthetic.json` is a cross-checked golden request.

`board-search-pilot-v1/fixed-baseline/` holds the four original browser specs
from `amiller/bounty-arcade` commit `5c76d40`. `bounty-judges` stages them into
the primary review. `board-search-pilot-v1/toolchain/` builds the browser base
image with Playwright 1.64.0 at `/opt/checker`:

```sh
docker build --build-arg BROWSER_BASE=mcr.microsoft.com/playwright:v1.64.0-noble \
  applications/bounty-recipes/board-search-pilot-v1/toolchain
```

Tests: `python3 -m pytest applications/bounty-recipes`.
