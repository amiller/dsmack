"""Live dsmack-sdk rung 1: sdk/test_sdk.py against two real Mac nodes on a disposable Anvil network. Laptop side.
The Mac directory --remote must hold build/ from `NODE_FLAGS='-D SDK_TEST_TRUST' node/tests/seed_build.sh` (a test
build: the App Attest root and runner CDHashes come from config, for synthetic runner fixtures). Deploys DemoV2 with a
MeasurementRegistry category admitting that build's M, and AppRegistry, which both nodes read (config appRegistry);
node A seeds (bootstraps G), node B participates and imports G from A through the relay. The suite's epoch bump must
leave B running: it re-acquires the new key from A and keeps serving the previous epoch. Both serve sdkPort on Mac
loopback, forwarded here; stand-in runners (runner/kms/sdk_runner.py) run here. Every config, plist, log and enrollment
state stays inside --remote.
--runner-dir names a Mac runner/ checkout holding build/ and build-other/ from runner/sign.sh (the second signed with
BUNDLE_VERSION=2: same code, another CDHash). Then build/ must instead be a release-mode node (no SDK_TEST_TRUST) with
build/cdhash.txt compiled in (`SDK_RUNNERS=$(cat runner/build/cdhash.txt) node/tests/seed_build.sh`): the configs carry
no sdkRunners and no anchor (Apple's root is compiled in), and every runner boot is that signed runner on the Mac with
fresh App Attest, booting --oci (the coupon image) in a VM (node/tests/sdk_real_runner.py); build-other is the runner
with a wrong CDHash."""
import argparse, atexit, hashlib, json, os, secrets, subprocess, sys, time
from pathlib import Path
from web3 import Web3

ROOT = Path(__file__).resolve().parents[2]
KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'  # public Anvil account 0
ap = argparse.ArgumentParser()
ap.add_argument('--host', default='mini-mesh'); ap.add_argument('--remote', required=True); ap.add_argument('--out', type=Path, required=True)
ap.add_argument('--rpc-port', type=int, default=18955); ap.add_argument('--relay-port', type=int, default=18956)
ap.add_argument('--sdk-ports', type=int, nargs=2, default=[18961, 18962])
ap.add_argument('--runner-dir'); ap.add_argument('--oci', type=Path); ap.add_argument('--kernel')  # Mac paths are absolute
ap.add_argument('--bridge-port', type=int, default=18970)  # Mac loopback port the test guests tunnel to, forwarded here
args = ap.parse_args()
out = args.out.resolve(); out.mkdir(parents=True, exist_ok=False); R = args.remote
procs = []
atexit.register(lambda: [p.terminate() for p in procs])


def note(**e):
    print(json.dumps(e), flush=True)
    with open(out / 'driver.jsonl', 'a') as f: f.write(json.dumps({'t': time.time(), **e}) + '\n')


def ssh(cmd, **kw): return subprocess.run(['ssh', args.host, cmd], check=True, text=True, capture_output=True, **kw).stdout
def background(cmd, name, env=None): procs.append(subprocess.Popen(cmd, stdout=open(out / f'{name}.out', 'w'), stderr=subprocess.STDOUT, env=env))
def run(*cmd, cwd=ROOT, **kw): return subprocess.run([str(c) for c in cmd], check=True, capture_output=True, text=True, cwd=cwd, **kw).stdout


def events(n):
    text = ssh(f'cat {R}/logs/{n}.jsonl 2>/dev/null || true'); (out / f'node-{n}.jsonl').write_text(text)
    return [json.loads(l) for l in text.splitlines() if l.startswith('{')]


def wait(n, pred, label, timeout=400):
    end = time.time() + timeout
    while time.time() < end:
        for e in events(n):
            if pred(e): note(check=f'{n}: {label}', detail=e); return e
        time.sleep(3)
    raise AssertionError(f'{n}: no {label}')


rpc = f'http://127.0.0.1:{args.rpc_port}'
env = {**os.environ, 'PRIVATE_KEY': KEY}
subprocess.run(['scp', f'{args.host}:{R}/build/cd-args.json', str(out / 'cd-args.json')], check=True)
measured = json.loads(ssh(f'{R}/build/Node.app/Contents/MacOS/node --measure'))
(out / 'measurement.json').write_text(json.dumps(measured, indent=1) + '\n')
(out / 'out').symlink_to(ROOT / 'contracts/out'); (out / 'deploy').mkdir()
background(['anvil', '--port', str(args.rpc_port), '--hardfork', 'osaka', '--block-time', '1'], 'anvil'); time.sleep(3)
run(sys.executable, 'scripts/release/deploy_network.py', '--rpc', rpc, '--build', out / 'cd-args.json', '--out', out / 'deploy/network.json',
    '--activate', '--category', '3', env=env)
run(sys.executable, 'scripts/release/deploy_measured.py', '--rpc', rpc, '--network', out / 'deploy/network.json', '--out', out / 'deploy/measured.json', env=env)
net, msr = (json.loads((out / f'deploy/{n}.json').read_text()) for n in ('network', 'measured'))
w3 = Web3(Web3.HTTPProvider(rpc)); owner = w3.eth.account.from_key(KEY)
registry = w3.eth.contract(address=msr['measurementRegistry'], abi=json.loads((ROOT / 'contracts/out/MeasurementRegistry.sol/MeasurementRegistry.json').read_text())['abi'])


def send(fn, label):
    tx = fn.build_transaction({'from': owner.address, 'nonce': w3.eth.get_transaction_count(owner.address, 'pending')})
    receipt = w3.eth.wait_for_transaction_receipt(w3.eth.send_raw_transaction(owner.sign_transaction(tx).raw_transaction))
    assert receipt['status'] == 1, label
    note(tx=label, hash=receipt['transactionHash'].to_0x_hex(), gas=receipt['gasUsed'])


h = lambda k: bytes.fromhex(measured[k].removeprefix('0x'))
send(registry.functions.admit(h('M'), 0, 2**64 - 1), 'MeasurementRegistry.admit(M)')
send(registry.functions.register(h('cd'), h('page0'), h('ent'), measured['L'], measured['S']), 'MeasurementRegistry.register(build)')
forge = run('forge', 'script', 'script/AppRegistry.s.sol', '--rpc-url', rpc, '--broadcast', env={**env, 'FOUNDRY_DISABLE_NIGHTLY_WARNING': '1'}, cwd=ROOT / 'contracts')
app_registry = forge.split('AppRegistry ')[1].split()[0]
deploy = {**net, 'macCategory': msr['measuredCategory'], 'measured': msr, 'AppRegistry': app_registry, 'M': measured['M'], 'cdhash': measured['cdhash']}
(out / 'deploy/deploy.json').write_text(json.dumps(deploy, indent=1) + '\n')
note(deploy=deploy['DemoV1'], measuredCategory=msr['measuredCategory'], measurementRegistry=msr['measurementRegistry'], appRegistry=app_registry, M=measured['M'])
background([sys.executable, str(ROOT / 'node/relay/relay.py'), '--rpc', rpc, '--deploy', str(out / 'deploy/deploy.json'), '--port', str(args.relay_port),
            '--settle', '0', '--log', str(out / 'relay.jsonl')], 'relay', env)
# Forwards go on the shared ssh control master (an `ssh -N` mux client exits at once), cancelled at exit.
forwards = ['-R', f'{args.rpc_port}:127.0.0.1:{args.rpc_port}', '-R', f'{args.relay_port}:127.0.0.1:{args.relay_port}',
            *(['-R', f'{args.bridge_port}:127.0.0.1:{args.bridge_port}'] if args.runner_dir else []),
            *[x for p in args.sdk_ports for x in ('-L', f'{p}:127.0.0.1:{p}')]]
subprocess.run(['ssh', '-O', 'forward', *forwards, args.host], check=True)
atexit.register(lambda: subprocess.run(['ssh', '-O', 'cancel', *forwards, args.host]))
time.sleep(2)
assert all(p.poll() is None for p in procs), 'anvil or relay exited'
assert 'owner' in ssh(f'curl -sf http://127.0.0.1:{args.relay_port}/info'), 'relay unreachable from the Mac'

# Synthetic runner fixture for this run (fresh enrolled_at; the committed fixture's is older than the node's 12 h).
composes = {}
sys.path[:0] = [str(ROOT / 'sdk'), str(ROOT / 'app/macos')]
import test_sdk
coupon = ROOT / 'apps/coupon-sdk/app-compose.json'
vm_image = json.loads(json.loads(coupon.read_text())['docker_compose_file'])['services']['app']['image'] if args.runner_dir else None
for n, c in test_sdk.COMPOSES.items():
    composes[n] = out / f'compose-{n}.json'; composes[n].write_bytes(test_sdk.compose(*c, vm_image=vm_image, bridge_port=args.bridge_port))
composes['coupon'] = coupon
fixture = out / 'runner-fixture.json'
note(fixture=run(sys.executable, 'node/tests/sdk_runner_fixture.py', fixture,
                 *[f'--compose={n}={hashlib.sha256(p.read_bytes()).hexdigest()}' for n, p in composes.items()]).strip())
sponsor_seed = secrets.token_hex(32)  # stand-in runners still send allow records; these nodes ignore them
stamp = Path(R).name[-8:]
names = {'A': f'sdk{stamp}-a', 'B': f'sdk{stamp}-b'}
cfg = {n: {'rpc': rpc, 'registry': deploy['DemoV1'], 'chainId': 31337, 'category': deploy['macCategory'], 'protocolVersion': 2,
           'relay': f'http://127.0.0.1:{args.relay_port}', 'name': names[n], 'persistentIdentity': True, 'publicDirectory': False,
           'sdkPort': port, 'sdkRunners': ['0x' + '5a' * 32], 'appRegistry': app_registry,
           'sdkTestAnchor': json.loads(fixture.read_text())['synthetic_root']} for n, port in zip('AB', args.sdk_ports)}
cfg['B']['peer'] = names['A']
runner = None
if args.runner_dir:
    rd = args.runner_dir
    cdhash, other = (ssh(f'cat {rd}/{b}/cdhash.txt').strip() for b in ('build', 'build-other'))
    assert cdhash != other
    compiled = ssh(f'cat {R}/build/sdk-runners.txt').split()
    assert compiled == [cdhash], f'build/ must be a release-mode node with only {cdhash} compiled in, has {compiled}'
    subprocess.run(['scp', str(args.oci), f'{args.host}:{R}/{args.oci.name}'], check=True)
    runner = {'host': args.host, 'remote': f'{R}/runs', 'kernel': args.kernel, 'oci': f'{R}/{args.oci.name}', 'bridge_port': args.bridge_port,
              'apps': {'good': f'{rd}/build/Runner.app', 'wrong_cdhash': f'{rd}/build-other/Runner.app'}, 'cdhash': cdhash, 'other_cdhash': other}
    for c in cfg.values():  # the release-mode node takes runners from its compiled list and Apple's root from its code
        del c['sdkRunners'], c['sdkTestAnchor']
    # Refusal: the same release-mode node binary given a config-only runner list (the other runner) does not start.
    refuse = {**cfg['A'], 'sdkRunners': ['0x' + other], 'name': names['A'] + '-refuse'}
    ssh(f'cat > {R}/refuse-config-runners.json', input=json.dumps(refuse))
    r = subprocess.run(['ssh', args.host, f'{R}/build/Node.app/Contents/MacOS/node {R}/refuse-config-runners.json seed'], text=True, capture_output=True)
    (out / 'refusal-config-runners.txt').write_text(f'exit {r.returncode}\n{r.stdout}{r.stderr}')
    assert r.returncode == 1 and 'sdkRunners is compiled into the node (inside M)' in r.stdout, r.stdout + r.stderr
    note(check='release-mode node refuses config-only sdkRunners', exit=r.returncode, output=r.stdout.strip())
    note(runner=runner, compiled_runners=compiled)
ssh(f'rm -rf {R}/home {R}/logs')  # fresh enrollment state for this chain
for n, role in (('A', 'seed'), ('B', 'participate')):
    agent = {'Label': f'dev.dsmack.test.{names[n]}', 'KeepAlive': False, 'RunAtLoad': True,
             'ProgramArguments': ['/usr/bin/open', '-n', '-W', '--env', f'CFFIXED_USER_HOME={R}/home', '--stdout', f'{R}/logs/{n}.jsonl',
                                  '--stderr', f'{R}/logs/{n}.err', f'{R}/build/Node.app', '--args', f'{R}/{n}.json', role]}
    ssh(f'mkdir -p {R}/logs {R}/agents {R}/home && cat > {R}/{n}.json', input=json.dumps(cfg[n]))
    ssh(f'cat > {R}/agents/{n}.json && plutil -convert xml1 -o {R}/agents/{n}.plist {R}/agents/{n}.json', input=json.dumps(agent))
    (out / f'config-{n}.json').write_text(json.dumps(cfg[n], indent=1) + '\n')
plist = lambda n: f'{R}/agents/{n}.plist'
recover = (ROOT / 'scripts/release/seed-recover.sh').read_text()
try:
    demo = w3.eth.contract(address=deploy['DemoV1'], abi=json.loads((ROOT / 'contracts/out/DemoV2.sol/DemoV2.json').read_text())['abi'])
    note(started='A', ready=ssh(f'bash -s -- mac-start {plist("A")} {demo.functions.keyEpochs(bytes(32)).call()}', input=recover).strip())
    ssh(f'launchctl bootstrap gui/$(id -u) {plist("B")}')
    wait('B', lambda e: e['event'] == 'participating', 'imported G and participating')
    for n in 'AB':
        listening = wait(n, lambda e: e['event'] == 'sdk listening', 'sdk listening')
        assert not runner or listening['runners'] == ['0x' + runner['cdhash']], listening  # the compiled-in runner
    e2e = {'rpc': rpc, 'chain_id': 31337, 'registry': deploy['DemoV1'], 'demo': deploy['DemoV1'], 'app_registry': app_registry, 'owner_key': KEY,
           'sponsor_seed': sponsor_seed, 'fixture': str(fixture), 'composes': {n: str(p) for n, p in composes.items()},
           'nodes': {n: f'127.0.0.1:{p}' for n, p in zip('AB', args.sdk_ports)}, **({'runner': runner} if runner else {})}
    (out / 'e2e.json').write_text(json.dumps(e2e))
    r = subprocess.run([sys.executable, '-m', 'pytest', '-v', str(ROOT / 'sdk/test_sdk.py')], text=True, capture_output=True, cwd=ROOT,
                       env={**os.environ, 'SDK_E2E': str(out / 'e2e.json'), 'SDK_EVIDENCE_DIR': str(out / 'tests')})
    (out / 'pytest.txt').write_text(r.stdout + r.stderr)
    note(pytest=r.stdout.strip().splitlines()[-1], returncode=r.returncode)
    b_events = events('B')
    rotated = [e for e in b_events if e['event'] == 'participating' and e['keyEpoch'] > 0]
    alive = 'PID' in ssh(f'launchctl list dev.dsmack.test.{names["B"]} || true')
    note(check='B: participant rotated without exiting', key_epoch_changed=sum(e['event'] == 'key epoch changed' for e in b_events),
         participating_after_bump=rotated[-1:] , still_running=alive)
    assert rotated and rotated[-1]['previousEpoch'] == rotated[-1]['keyEpoch'] - 1 and alive, 'participant B did not rotate in place'
    assert r.returncode == 0, 'pytest failed'
finally:
    if runner:  # this run's runners only: each has --out under its own runs/ directory
        subprocess.run(['ssh', args.host, f"pkill -f -- '--out {runner['remote']}/'"])
    for n in 'AB':
        subprocess.run(['ssh', args.host, f'bash -s -- mac-stop {plist(n)}'], input=recover, text=True, capture_output=True)
        events(n)
