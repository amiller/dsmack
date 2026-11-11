#!/usr/bin/env python3
"""Run one personal-agent turn on the Mac from the laptop and commit it to TurnHeads.

python3 run_turn.py <workload dir> <agent dir>

<workload dir> is workload.py's out/. <agent dir> holds `agent`, the agent's address written at provisioning,
the state blobs by sha256 and head.json for the turn; it is the turn's $STATE server. Reads the head from
TurnHeads ($HEADS), boots the turn with applications/libp2p-attest/run-mac.py in
$DSMACK_MAC_HOST:~/$DSMACK_MAC_RUNNER/t/<run id>, reads the result disk and sends the commit with cast
(ETH_RPC_URL and the cast wallet env).
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

HERE = Path(__file__).resolve().parent
RUN_MAC = HERE.parents[1]/'libp2p-attest/run-mac.py'
NAME = 'personal-agent-turn-v1'
wl, agent_dir = map(Path, sys.argv[1:3])
mac, runner, heads = os.environ['DSMACK_MAC_HOST'], os.environ['DSMACK_MAC_RUNNER'], os.environ['HEADS']
cast = lambda *a: subprocess.run(['cast', *a], check=True, capture_output=True, text=True).stdout.split()
ssh = lambda cmd, **kw: subprocess.run(['ssh', mac, cmd], check=True, **kw)

agent = (agent_dir/'agent').read_text().strip()
head = cast('call', heads, 'heads(address)(uint256,bytes32)', agent)
turn, state = int(head[0]), head[-1][2:]
(agent_dir/'head.json').write_text(json.dumps({'turn': turn, 'state': state}))

run_id = uuid.uuid4().hex[:12]
t = f'{runner}/t/{run_id}'
ssh(f'mkdir -p {t}')
subprocess.run(['scp', '-q', str(wl/'disk/workload.img'), str(wl/'compose-manifest.json'), f'{mac}:{t}/'], check=True)
out = wl/'runs'/run_id
out.mkdir(parents=True)
try:
    with open(RUN_MAC, 'rb') as script:
        ssh(f'python3 -I - ~/{runner} ~/{t}', stdin=script)
    subprocess.run(['scp', '-q', f'{mac}:{t}/out/result.img', f'{mac}:{t}/stdout.txt', f'{mac}:{t}/stderr.txt', str(out)], check=True)
finally:
    ssh(f'rm -rf ~/{t}')
subprocess.run(['/sbin/debugfs', '-R', f'rdump / {out}', str(out/'result.img')], check=True, capture_output=True)
artifacts = out/NAME/'outputs/artifacts'
commit, blob = json.loads((artifacts/'commit').read_bytes()), (artifacts/'state').read_bytes()
assert (commit['turn'], commit['state_in']) == (turn, state), 'the turn ran from another head'
assert commit['agent'] == agent, 'the turn signed as another agent'
assert hashlib.sha256(blob).hexdigest() == commit['state_out'], 'state artifact does not match state_out'
(agent_dir/commit['state_out']).write_bytes(blob)
cast('send', heads, 'commit(uint256,bytes32,bytes32,uint8,bytes32,bytes32)', str(turn), '0x' + state,
     '0x' + commit['state_out'], str(commit['v']), '0x' + commit['r'], '0x' + commit['s'])
print(json.dumps(commit))
