#!/bin/bash
# (Re)start a local anvil (osaka: native P-256 at 0x100) on 18555, deploy, and start the relay on 18556.
# Restarts only processes recorded in <dir>/*.pid. The mini reaches both ports through:
#   ssh -N -R 18555:127.0.0.1:18555 -R 18556:127.0.0.1:18556 mini-mesh
set -euo pipefail
cd "$(dirname "$0")/.."
D=${1:?run dir}; mkdir -p "$D"
for p in relay anvil; do [ -f "$D/$p.pid" ] && kill "$(cat "$D/$p.pid")" 2>/dev/null; rm -f "$D/$p.pid"; done
sleep 1
nohup anvil --port 18555 --hardfork osaka > "$D/anvil.log" 2>&1 & echo $! > "$D/anvil.pid"
sleep 2
export PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 # anvil account 0
(cd contracts && MAC_BUILD=network/cd-args-macos.json DEPLOY_OUT=network/deploy-anvil.json forge script script/Network.s.sol \
  --rpc-url http://127.0.0.1:18555 --broadcast --gas-estimate-multiplier 200 > "../$D/deploy.log" 2>&1)
cp contracts/network/deploy-anvil.json "$D/"
rm -f "$D/relay.jsonl"
nohup python3 node/relay/relay.py --rpc http://127.0.0.1:18555 --deploy contracts/network/deploy-anvil.json --port 18556 --settle 0 --log "$D/relay.jsonl" > "$D/relay.out" 2>&1 & echo $! > "$D/relay.pid"
sleep 3; curl -sf localhost:18556/info
