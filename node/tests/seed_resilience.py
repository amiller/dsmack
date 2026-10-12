"""Live seed resilience test: two sealer seeds on a Mac against a disposable Anvil DemoV2 network.
Laptop side. The Mac directory --remote must hold build/ from node/tests/seed_build.sh; every
config, launchd plist, log, seal and enrollment state stays inside it (CFFIXED_USER_HOME).
Checks: one seed killed, the other serves; a restarted seed reloads its seal with no transaction;
both killed and restarted, both reload; seals deleted and all holders dead, seed-recover.sh
reaches `seed ready` at N+1 and the second seed then recovers from the first."""
import argparse, json, os, shlex, subprocess, time
from pathlib import Path
from web3 import Web3

ROOT = Path(__file__).resolve().parents[2]
KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'  # public Anvil account 0
ZERO = b'\0' * 32
ap = argparse.ArgumentParser()
ap.add_argument('--host', default='mini-mesh'); ap.add_argument('--remote', required=True); ap.add_argument('--out', type=Path, required=True)
ap.add_argument('--rpc-port', type=int, default=18755); ap.add_argument('--relay-port', type=int, default=18756)
args = ap.parse_args()
out = args.out.resolve(); out.mkdir(parents=True, exist_ok=False); R = args.remote
SSH = ['ssh', '-o', 'ControlPath=none', '-o', 'ExitOnForwardFailure=yes']
procs = []

def note(**e):
    print(json.dumps(e), flush=True)
    with open(out/'driver.jsonl', 'a') as f: f.write(json.dumps({'t': time.time(), **e}) + '\n')

def ssh(cmd, **kw): return subprocess.run([*SSH, args.host, cmd], check=True, text=True, capture_output=True, **kw).stdout

def background(cmd, name, env=None):
    procs.append(subprocess.Popen(cmd, stdout=open(out/f'{name}.out', 'w'), stderr=subprocess.STDOUT, env=env))

def recover(*a, env=None):
    r = subprocess.run(['bash', str(ROOT/'scripts/release/seed-recover.sh'), *a], text=True, capture_output=True,
                       env={**os.environ, 'SSH_OPTS': '-o ControlPath=none', **(env or {})})
    (out/'seed-recover.log').open('a').write(f'$ {a}\n{r.stdout}{r.stderr}\n')
    assert r.returncode == 0, r.stderr
    return r.stdout

def mac(sub, *a):  # the Mac-side halves of seed-recover.sh, used to stop and start test agents
    return ssh(f'bash -s -- {sub} ' + ' '.join(map(shlex.quote, a)), input=(ROOT/'scripts/release/seed-recover.sh').read_text())

def events(name):
    text = ssh(f'cat {R}/logs/{name}.jsonl 2>/dev/null || true'); (out/f'{name}.jsonl').write_text(text)
    return [json.loads(l) for l in text.splitlines() if l.startswith('{')]

def wait(name, pred, label, since=0, timeout=300):
    end = time.time() + timeout
    while time.time() < end:
        for e in events(name)[since:]:
            if pred(e): note(check=f'{name}: {label}', ok=True, detail=e); return e
        time.sleep(2)
    raise AssertionError(f'{name}: no {label}')

def txs(): return sum(1 for l in open(out/'relay.jsonl') if json.loads(l)['kind'] == 'tx') if (out/'relay.jsonl').exists() else 0
def epoch(): return demo.functions.keyEpochs(ZERO).call()
def plist(n): return f'{R}/agents/{n}.plist'
def stop(n): mac('mac-stop', plist(n)); note(stopped=n)
def start(n, e):
    since = len(events(n)); tx = txs()
    note(started=n, ready=mac('mac-start', plist(n), str(e)).strip())
    return since, tx
def sealed(n): return ssh(f'test -f {R}/{n}.sealed-key && echo yes || echo no').strip() == 'yes'

# Chain, relay and tunnels. The relay resolves artifacts relative to the deploy file's grandparent.
subprocess.run(['scp', '-o', 'ControlPath=none', f'{args.host}:{R}/build/cd-args.json', str(out/'cd-args.json')], check=True)
(out/'out').symlink_to(ROOT/'contracts/out'); (out/'deploy').mkdir()
background(['anvil', '--port', str(args.rpc_port), '--hardfork', 'osaka', '--block-time', '1'], 'anvil'); time.sleep(3)
rpc = f'http://127.0.0.1:{args.rpc_port}'
subprocess.run(['python3', 'scripts/release/deploy_network.py', '--rpc', rpc, '--build', str(out/'cd-args.json'),
                '--out', str(out/'deploy/deploy.json'), '--activate', '--category', '3'], cwd=ROOT, env={**os.environ, 'PRIVATE_KEY': KEY}, check=True, capture_output=True)
deploy = json.loads((out/'deploy/deploy.json').read_text())
w3 = Web3(Web3.HTTPProvider(rpc))
demo = w3.eth.contract(address=deploy['DemoV1'], abi=json.loads((ROOT/'contracts/out/DemoV2.sol/DemoV2.json').read_text())['abi'])
background(['python3', str(ROOT/'node/relay/relay.py'), '--rpc', rpc, '--deploy', str(out/'deploy/deploy.json'), '--port', str(args.relay_port),
            '--settle', '0', '--log', str(out/'relay.jsonl')], 'relay', {**os.environ, 'PRIVATE_KEY': KEY})
background([*SSH, '-N', '-R', f'{args.rpc_port}:127.0.0.1:{args.rpc_port}', '-R', f'{args.relay_port}:127.0.0.1:{args.relay_port}', args.host], 'tunnel')
time.sleep(4)
assert all(p.poll() is None for p in procs), 'anvil, relay or tunnel exited'
assert 'owner' in ssh(f'curl -sf http://127.0.0.1:{args.relay_port}/info'), 'relay unreachable from the Mac'
note(deploy=deploy['DemoV1'], category=deploy['macCategory'])

stamp = Path(R).name[-12:]
names = {n: f'sr{stamp}-{n}' for n in 'abcp'}
def config(n, **extra):
    return {'rpc': rpc, 'registry': deploy['DemoV1'], 'chainId': 31337, 'category': deploy['macCategory'], 'protocolVersion': 2,
            'relay': f'http://127.0.0.1:{args.relay_port}', 'name': names[n], 'persistentIdentity': True, **extra}
configs = {'a': config('a', sealer=True, peer=[names['b']]), 'b': config('b', sealer=True, peer=[names['a']]),
           'c': config('c', peer=[names['a']]), 'p': config('p', peer=[names['a'], names['b']])}
for n, c in configs.items():
    role = 'connect' if n == 'p' else 'seed'
    agent = {'Label': f'dev.dsmack.test.{names[n]}', 'KeepAlive': n != 'p', 'RunAtLoad': True, 'ThrottleInterval': 10,
             'ProgramArguments': ['/usr/bin/open', '-n', '-W', '--env', f'CFFIXED_USER_HOME={R}/home', '--stdout', f'{R}/logs/{n}.jsonl',
                                  '--stderr', f'{R}/logs/{n}.err', f'{R}/build/Node.app', '--args', f'{R}/{n}.json', role]}
    ssh(f'mkdir -p {R}/logs {R}/agents {R}/home && cat > {R}/{n}.json', input=json.dumps(c))
    ssh(f'cat > {R}/agents/{n}.json && plutil -convert xml1 -o {plist(n)} {R}/agents/{n}.json', input=json.dumps(agent))

try:
    # 0. Seed a bootstraps and seals; b gets the key from a and seals; non-sealer c never writes a seal.
    N = epoch(); start('a', N); start('b', N)
    assert sealed('a') and sealed('b'), 'sealer seeds wrote no seal'
    start('c', N); time.sleep(5); assert not sealed('c'), 'non-sealer wrote a seal'; stop('c')
    note(check='non-sealer seed never writes a seal', ok=True)
    # Policy probes: same team, other CDHash opens a's seal; ad hoc unentitled copy cannot.
    probe = ssh(f'{R}/build/SeedSealTests.app/Contents/MacOS/test open {R}/a.json')
    adhoc = subprocess.run([*SSH, args.host, f'{R}/build/seal-test-adhoc open {R}/a.json'], text=True, capture_output=True).stdout
    note(probe_same_team_other_cdhash=json.loads(probe), probe_adhoc_unentitled=json.loads(adhoc))
    assert json.loads(probe)['opened'] and not json.loads(adhoc)['opened']
    # 1. a killed: participant p (peers a, b) fails over to b and gets the key.
    stop('a'); since = len(events('p'))
    ssh(f'launchctl bootstrap gui/$(id -u) {plist("p")}')
    wait('p', lambda e: e['event'] == 'imported group key', 'key from the surviving seed', since, timeout=400)
    assert any(e['event'] == 'peer failed' and e.get('peer') == names['a'] for e in events('p')), 'p did not try a first'
    ssh(f'launchctl bootout gui/$(id -u)/dev.dsmack.test.{names["p"]} 2>/dev/null || true')
    # 2. a restarted: reloads its seal, no transaction.
    since, tx = start('a', N); time.sleep(10)
    assert any(e['event'] == 'sealed key loaded' for e in events('a')[since:]) and txs() == tx, 'restart used a transaction'
    note(check='a reloaded seal with no transaction', ok=True, txs=tx)
    # 3. both killed and restarted: both reload, no transaction.
    stop('a'); stop('b'); tx = txs()
    sa, _ = start('a', N); sb, _ = start('b', N); time.sleep(10)
    assert all(any(e['event'] == 'sealed key loaded' for e in events(n)[s:]) for n, s in (('a', sa), ('b', sb))) and txs() == tx
    note(check='both reloaded seals with no transaction', ok=True, txs=tx)
    # 4. seals deleted, every holder dead: seed-recover.sh reaches seed ready at N+1; b then recovers from a.
    stop('a'); stop('b'); ssh(f'rm {R}/a.sealed-key {R}/b.sealed-key')
    ready = recover('--rpc', rpc, '--registry', deploy['DemoV1'], '--plist', plist('a'), '--host', args.host, env={'PRIVATE_KEY': KEY})
    assert epoch() == N + 1 and f'"keyEpoch":{N+1}' in ready, ready
    note(check='seed-recover.sh reached seed ready at N+1', ok=True, detail=ready.strip())
    sb, _ = start('b', N + 1)
    wait('b', lambda e: e['event'] == 'key verified' and e.get('keyEpoch') == N + 1, 'key from a at N+1', sb)
    assert sealed('a') and sealed('b')
    note(result='all checks passed')
finally:
    for n in 'abcp':
        subprocess.run([*SSH, args.host, f'bash -s -- mac-stop {plist(n)}'], input=(ROOT/'scripts/release/seed-recover.sh').read_text(), text=True, capture_output=True)
    for n in 'ab':
        note(cleanup=n, result=subprocess.run([*SSH, args.host, f'{R}/build/SeedSealTests.app/Contents/MacOS/test delete {R}/{n}.json'], text=True, capture_output=True).stdout.strip())
    for n in 'abcp': events(n)
    for p in procs: p.terminate()
