#!/usr/bin/env bash
# The coordinator compose in a docker-in-docker guest whose /var/run/dstack.sock is the dstack
# simulator, with CDRegistry on anvil admitting the recorded runner build. Replays the recorded
# turns, restarts the app, then mints one admission. Usage: e2e.sh <dir>, laid out as in README.md.
set -euo pipefail
D=$(cd "$1" && pwd) N=dstack-coordinator-e2e RPC=http://172.17.0.1:18545 SPIKE=$D/src/applications/agent-turns/testdata/personal-agent
export FOUNDRY_DISABLE_NIGHTLY_WARNING=1
cleanup() { docker rm -f -v $N-guest >/dev/null 2>&1 || true; docker rmi dsmack-coordinator:local >/dev/null 2>&1 || true; kill $(jobs -p) 2>/dev/null || true; }
trap cleanup EXIT
mkdir "$D/out"
(cd "$D/sim" && exec ./dstack-simulator > "$D/out/simulator.log" 2>&1) &
"$D/bin/anvil" --host 172.17.0.1 --port 18545 > "$D/out/anvil.log" 2>&1 &
until [ -S "$D/sim/dstack.sock" ] && "$D/bin/cast" block-number --rpc-url $RPC >/dev/null 2>&1; do sleep 0.5; done

# anvil's unlocked dev account sends; the CodeDirectory is too long for a cast argument.
# chain deploy: CDRegistry with the recorded runner as its approved build. chain register REG: admit that CDHash.
chain() { python3 - "$RPC" "$D/cdreg" "$@" <<'EOF'
import json, sys, time, urllib.request
rpc, d, op, *reg = sys.argv[1:]
def call(method, params):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
    return json.loads(urllib.request.urlopen(urllib.request.Request(rpc, body, {'content-type': 'application/json'})).read())['result']
def tx(data, to=None):
    h = call('eth_sendTransaction', [{'from': call('eth_accounts', [])[0], 'data': data, 'gas': hex(30_000_000), **({'to': to} if to else {})}])
    while not (receipt := call('eth_getTransactionReceipt', [h])):
        time.sleep(0.2)
    assert receipt['status'] == '0x1', receipt
    return receipt
def build(signature, to):
    a = json.load(open(d + '/args.json'))
    parts = [bytes.fromhex(a[k][2:]) for k in ('cd', 'page0', 'ent')]
    head, tail = b'', b''
    for b in parts:
        head += (32 * len(parts) + len(tail)).to_bytes(32, 'big')
        tail += len(b).to_bytes(32, 'big') + b + bytes(-len(b) % 32)
    tx(signature + (head + tail).hex(), to)
if op == 'deploy':
    reg = [tx(open(d + '/cdregistry.bin').read().strip())['contractAddress']]
    build('0xa95f3af7', reg[0])
    print(reg[0])
else:
    build('0xe32d1415', reg[0])
EOF
}
REG=$(chain deploy)
DOCKER_BUILDKIT=0 docker build -q -t dsmack-coordinator:local -f "$D/src/applications/coordinator/Dockerfile" "$D/src" >/dev/null
docker run -d --privileged --name $N-guest -v "$D/sim/dstack.sock:/var/run/dstack.sock" \
  -v "$D/src/applications/coordinator:/c:ro" docker:28-dind --bip=10.99.0.1/24 >/dev/null
until docker exec $N-guest docker info >/dev/null 2>&1; do sleep 1; done
docker save dsmack-coordinator:local | docker exec -i $N-guest docker load -q
TOKEN=$(python3 -c 'import secrets; print(secrets.token_hex(16))')
compose() { docker exec -e OPERATOR_TOKEN=$TOKEN -e API_KEY=synthetic-not-a-credential -e RPC_URL=$RPC -e CDREGISTRY=$REG \
  $N-guest docker compose -p coord -f /c/docker-compose.json "$@"; }
compose up -d
URL=http://$(docker inspect -f '{{.NetworkSettings.IPAddress}}' $N-guest):8080
until curl -sf $URL/keys > "$D/out/keys-1.json"; do sleep 0.5; done
python3 -I "$D/src/applications/coordinator/e2e_client.py" unregistered $URL "$SPIKE"
chain register "$REG"
CDHASH=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['cdhash'])" "$D/cdreg/args.json")
echo "CDRegistry $REG rpIdHash($CDHASH) = $("$D/bin/cast" call --rpc-url $RPC "$REG" 'rpIdHash(bytes32)(bytes32)' "$CDHASH")"

# The recorded launches carry nonces the spike's keeper issued; issue the same ones here.
python3 -c 'import base64,json,sys
for n in (1, 2): print(json.loads(base64.b64decode(json.load(open(f"{sys.argv[1]}/evidence-turn-{n}.json"))["bootClientData"]))["nonce"])' "$SPIKE" |
while read -r n; do
  docker exec $N-guest docker exec coord-coordinator-1 python3 -c 'import sys,time; open("/state/nonces/" + sys.argv[1], "w").write(str(time.time()))' "$n"
done
python3 -I "$D/src/applications/coordinator/e2e_client.py" turns $URL $TOKEN "$SPIKE"

compose restart
until curl -sf $URL/keys > "$D/out/keys-2.json"; do sleep 0.5; done
cmp "$D/out/keys-1.json" "$D/out/keys-2.json"
curl -sf $URL/head/personal-agent-turns-20261025 | cmp - "$SPIKE/head.json"
echo "restart ok: same release key and head"

python3 -I "$D/src/applications/coordinator/e2e_client.py" admit $URL $TOKEN "$D/mac/release.json" "$D/mac/profile.json" \
  "$D/mac/disk.json" "$D/out/admission"
docker exec $N-guest docker exec coord-coordinator-1 cat /state/events.jsonl > "$D/out/events.jsonl"
docker exec $N-guest docker logs coord-coordinator-1 > "$D/out/coordinator.log" 2>&1
