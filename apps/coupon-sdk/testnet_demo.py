"""Coupon app against NEAR testnet through two stand-in nodes sharing one test group key.
Usage: testnet_demo.py OUT_DIR. Keys live in OUT_DIR/state (0600) and are never printed. Steps: local anvil
AppRegistry admits app-compose.json under its app_id and a test sponsor signs its allow record; stand-in nodes A and B
boot it with synthetic runner evidence; the container (image from the compose) derives the account via
/var/run/dsmack.sock; a faucet-funded throwaway funds the implicit account; the container on node B signs one transfer back."""
import hashlib, json, os, secrets, subprocess, sys, time, urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path[:0] = [str(HERE), str(ROOT / 'sdk/python')]
import near_tx

OUT = Path(sys.argv[1]).resolve()
STATE = OUT / 'state'
STATE.mkdir(parents=True, exist_ok=True)
NEAR = 'https://rpc.testnet.near.org'
ANVIL, RPC = 18745, 'http://127.0.0.1:18745'
OWNER_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'  # anvil account 0, public test key
OWNER = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'
log = {}
procs = []


def record():
    (OUT / 'testnet-demo.json').write_text(json.dumps(log, indent=1) + '\n')


def run(*cmd, **kw):
    return subprocess.run([str(c) for c in cmd], check=True, capture_output=True, text=True, **kw).stdout


def secret(name, make):
    path = STATE / name
    if not path.exists():
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(fd, make().encode())
        os.close(fd)
    return path


def wait(pred):
    for _ in range(150):
        if pred():
            return
        time.sleep(0.2)
    raise TimeoutError


compose = HERE / 'app-compose.json'
c = json.loads(compose.read_bytes())
image = json.loads(c['docker_compose_file'])['services']['app']['image']
compose_hash = hashlib.sha256(compose.read_bytes()).hexdigest()
log['compose'] = {'app_id': c['app_id'], 'compose_hash': compose_hash, 'image': image}
try:
    procs.append(subprocess.Popen(['anvil', '--port', str(ANVIL), '--silent']))
    wait(lambda: subprocess.run(['cast', 'block-number', '--rpc-url', RPC], capture_output=True).returncode == 0)
    out = run('forge', 'script', 'script/AppRegistry.s.sol', '--rpc-url', RPC, '--broadcast', cwd=ROOT / 'contracts',
              env={**os.environ, 'PRIVATE_KEY': OWNER_KEY, 'APP_ID': '0x' + c['app_id'], 'APP_ADMIN': OWNER,
                   'COMPOSE_HASH': '0x' + compose_hash, 'FOUNDRY_DISABLE_NIGHTLY_WARNING': '1'})
    reg = out.split('AppRegistry ')[1].split()[0]
    log['app_registry_anvil'] = {'address': reg, 'forge': [l.strip() for l in out.splitlines() if 'gas' in l.lower()]}
    group = secret('group.key', lambda: secrets.token_bytes(31).rjust(32, b'\0').hex())
    sponsor = secret('sponsor.key', lambda: secrets.token_bytes(32).hex())
    from cryptography.hazmat.primitives.asymmetric import ed25519
    sponsor_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sponsor.read_text()))
    import dsmack_sdk
    until = int(time.time()) + 6 * 3600
    allow = OUT / 'allow.json'
    allow.write_text(json.dumps({'scope': '0x' + '00' * 32, 'until': until, 'signature': '0x' + sponsor_key.sign(
        dsmack_sdk.allow_message(31337, '0x' + '11' * 20, c['app_id'], compose_hash, '00' * 32, until)).hex()}))
    fixture = OUT / 'runner-fixture.json'
    run(sys.executable, ROOT / 'node/tests/sdk_runner_fixture.py', fixture, f'--compose=coupon={compose_hash}')
    socks = {}
    for name, port in (('A', 18891), ('B', 18892)):
        procs.append(subprocess.Popen([sys.executable, ROOT / 'runner/kms/sdk_node.py', '--port', str(port), f'--group-key=1={group}',
                                       '--rpc', RPC, '--registry', '0x' + '11' * 20, '--chain-id', '31337', '--scope', '00' * 32,
                                       '--sponsor', sponsor_key.public_key().public_bytes_raw().hex(), '--anchor', json.loads(fixture.read_text())['synthetic_root'],
                                       '--runner', '5a' * 32, '--member', '0x' + '00' * 32, '--m', '0x' + '00' * 32, '--checked-tx', 'standin'],
                                      stderr=open(OUT / f'node-{name}.log', 'w')))
        time.sleep(0.5)
        sockdir = STATE / f'sock-{name}'
        sockdir.mkdir(exist_ok=True)
        (sockdir / 'dsmack.sock').unlink(missing_ok=True)
        procs.append(subprocess.Popen([sys.executable, ROOT / 'runner/kms/sdk_runner.py', '--compose', compose, '--node', f'127.0.0.1:{port}',
                                       '--allow', allow, '--fixture', fixture, '--enrollment', 'coupon', '--socket', 'dsmack.sock'],
                                      cwd=sockdir, stderr=open(OUT / f'runner-{name}.log', 'w')))
        wait(lambda: (sockdir / 'dsmack.sock').exists())
        socks[name] = sockdir / 'dsmack.sock'

    def app(name, *argv):
        return json.loads(run('docker', 'run', '--rm', '-v', f'{socks[name]}:/var/run/dsmack.sock', '-e', 'NEAR_TRANSPORT=direct',
                              image.replace('local/', '').split('@')[0] + ':local', *argv))
    a, b = app('A', 'account'), app('B', 'account')
    if a['account_id'] != b['account_id']:
        raise SystemExit(f'nodes disagree: {a} {b}')
    account = a['account_id']
    log['account'] = {'node_A': a, 'node_B': b}
    record()

    seed_path = secret('throwaway.key', lambda: secrets.token_bytes(32).hex())
    seed = bytes.fromhex(seed_path.read_text())
    if not (STATE / 'throwaway.id').exists():
        tid = f'dsmack-sdk-demo-{secrets.token_hex(4)}.testnet'
        req = urllib.request.Request('https://helper.testnet.near.org/account', json.dumps(
            {'newAccountId': tid, 'newAccountPublicKey': 'ed25519:' + near_tx.b58encode(near_tx.public(seed))}).encode(),
            {'content-type': 'application/json'})
        log['faucet'] = {'account_id': tid, 'helper_status': urllib.request.urlopen(req, timeout=120).status}
        (STATE / 'throwaway.id').write_text(tid)
    tid = (STATE / 'throwaway.id').read_text()
    wait(lambda: subprocess.run([sys.executable, '-c', f'import sys; sys.path.insert(0, {str(HERE)!r}); import near_tx; near_tx.balance({NEAR!r}, {tid!r})'],
                                capture_output=True, env={**os.environ, 'NEAR_TRANSPORT': 'direct'}).returncode == 0)
    os.environ['NEAR_TRANSPORT'] = 'direct'
    log['throwaway'] = {'account_id': tid, 'balance_before': str(near_tx.balance(NEAR, tid))}
    fund = near_tx.transfer(NEAR, seed, tid, account, 10**24)
    log['fund_implicit'] = {'hash': fund['transaction']['hash'], 'status': fund['status'], 'from': tid, 'to': account, 'yocto': str(10**24)}
    log['implicit_balance_after_fund'] = str(near_tx.balance(NEAR, account))
    record()
    back = app('B', 'transfer', tid, str(10**23))
    log['implicit_signs_transfer'] = back
    log['implicit_balance_after_transfer'] = str(near_tx.balance(NEAR, account))
    log['explorer'] = {k: f'https://testnet.nearblocks.io/txns/{h}' for k, h in
                       (('fund', log['fund_implicit']['hash']), ('implicit_transfer', back['transfer']['hash']))}
    record()
    print(json.dumps({k: log[k] for k in ('compose', 'explorer')} | {'account_id': account}, indent=1))
finally:
    for p in procs:
        p.terminate()
