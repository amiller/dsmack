#!/usr/bin/env bash
# One compose file, two guests: a dind guest whose /var/run/dstack.sock is the
# dstack simulator, and one whose socket is the dsmack shim fed a grant minted
# by the simulator-hosted coordinator. Usage: e2e.sh <workdir with sim/ compat/ pylib/>
set -euo pipefail
D=$1; PY=python@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704
py() { docker run --rm -v "$D:/w" -w /w/compat -e PYTHONPATH=/w/pylib "$PY" python3 "$@"; }
guest() {  # guest <socket> <out>
  local name=dstack-compat-guest-$$
  docker run -d --rm --privileged --name "$name" -v "$1:/var/run/dstack.sock" -v "$D/compat:/c:ro" docker:28-dind >/dev/null
  until docker exec "$name" docker info >/dev/null 2>&1; do sleep 1; done
  docker exec "$name" docker compose -p w -f /c/docker-compose.json run --rm -T worker > "$2"
  docker rm -f "$name" >/dev/null
}

guest "$D/sim/dstack.sock" "$D/out-dstack.json"

mkdir -p "$D/mac"
python3 -c 'import json,sys; c=open(sys.argv[1]).read(); print(json.dumps({"manifest_version":2,"name":"worker","runner":"docker-compose","docker_compose_file":c}),end="")' \
  "$D/compat/docker-compose.json" > "$D/mac/app-compose.json"
hash=$(sha256sum "$D/mac/app-compose.json" | cut -d' ' -f1)
py grant.py /w/sim/dstack.sock task-1 mac-mini-7 "$hash" 600 > "$D/mac/grant.json"
docker run -d --rm --name dstack-compat-shim-$$ -v "$D:/w" -w /w/compat -e PYTHONPATH=/w/pylib "$PY" \
  python3 agent.py --grant /w/mac/grant.json --dir /w/mac worker >/dev/null
until [ -S "$D/mac/worker.sock" ]; do sleep 0.2; done
guest "$D/mac/worker.sock" "$D/out-dsmack.json"
docker rm -f dstack-compat-shim-$$ >/dev/null

py verify.py /w/out-dstack.json /w/out-dsmack.json
