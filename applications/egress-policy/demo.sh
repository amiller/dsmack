#!/usr/bin/env bash
# Run from this directory on the Linux builder, under /data.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p evidence
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOMAXPROCS=4 GOFLAGS=-p=4
export GOCACHE="$PWD/.go-cache"
cleanup_build() {
python3 - <<'CLEANUP'
from pathlib import Path
import shutil
root = Path.cwd()
cache, binary = root / '.go-cache', root / 'gateway'
reclaimed = sum(p.stat().st_size for p in cache.rglob('*') if p.is_file()) if cache.is_dir() else 0
if binary.is_file():
    reclaimed += binary.stat().st_size
    binary.unlink()
if cache.is_dir():
    shutil.rmtree(cache)
(root / 'evidence/build-cleanup.txt').write_text(f'Removed owned Go cache and executable; file bytes reclaimed: {reclaimed}\n')
CLEANUP
}
trap cleanup_build EXIT
CGO_ENABLED=1 go test -race -v ./... 2>&1 | tee evidence/unit-tests.txt
CGO_ENABLED=0 go build -trimpath -o gateway .
docker build --pull=false -t dsmack-egress-policy-20261027:prototype . >evidence/docker-build.txt 2>&1
python3 demo.py
