"""dsmack-sdk against stand-in nodes on a local anvil AppRegistry. Run: python3 -m pytest sdk/test_sdk.py
SDK_EVIDENCE_DIR=<dir> also records each outcome there as JSON."""
import hashlib, json, os, secrets, socket, subprocess, sys, time
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'sdk/python'))
import dsmack_sdk as sdk
from dsmack_sdk import verify

ANVIL_PORT = 18645
RPC = f'http://127.0.0.1:{ANVIL_PORT}'
OWNER_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'  # anvil account 0, public test key
OWNER = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'
SCOPE = '00' * 32
REGISTRY = '0x' + '11' * 20   # stand-in DemoV2 address in the derivation context
X, Y = (hashlib.sha256(b'dsmack-sdk-test/app-' + n).hexdigest() for n in (b'x', b'y'))
OUT = Path(os.environ['SDK_EVIDENCE_DIR']) if 'SDK_EVIDENCE_DIR' in os.environ else None


def record(name, obj):
    if OUT:
        OUT.mkdir(parents=True, exist_ok=True)
        (OUT / f'{name}.json').write_text(json.dumps(obj, indent=1, sort_keys=True) + '\n')


def run(*cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw).stdout


def wait(pred):
    for _ in range(100):
        if pred():
            return
        time.sleep(0.1)
    raise TimeoutError


def listening(port):
    with socket.socket() as s:
        return s.connect_ex(('127.0.0.1', port)) == 0


def compose(app_id, name, env):
    dc = {'services': {'app': {'image': 'docker.io/library/python@sha256:' + '0' * 64, 'environment': env}}}
    return json.dumps({'app_id': app_id, 'docker_compose_file': json.dumps(dc, sort_keys=True), 'egress': {'allow': []},
                       'kms_enabled': True, 'manifest_version': 2, 'name': name, 'runner': 'docker-compose'},
                      sort_keys=True, separators=(',', ':')).encode()


def secret(path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, secrets.token_bytes(31).rjust(32, b'\0').hex().encode())   # < P-256 n
    os.close(fd)
    return path


@pytest.fixture(scope='module')
def net(tmp_path_factory):
    d = tmp_path_factory.mktemp('sdk')
    procs = [subprocess.Popen(['anvil', '--port', str(ANVIL_PORT), '--silent'])]
    wait(lambda: listening(ANVIL_PORT))
    out = run('forge', 'script', 'script/AppRegistry.s.sol', '--rpc-url', RPC, '--broadcast',
              cwd=ROOT / 'contracts', env={**os.environ, 'PRIVATE_KEY': OWNER_KEY, 'FOUNDRY_DISABLE_NIGHTLY_WARNING': '1'})
    reg = out.split('AppRegistry ')[1].split()[0]
    gas = {'deploy_script_output': [l.strip() for l in out.splitlines() if 'gas' in l.lower()]}
    composes = {n: compose(*a) for n, a in {'C1': (X, 'c1', {'A': '1'}), "C1'": (X, 'c1', {'A': '2'}),
                                             'C2': (Y, 'c2', {'A': '1'}), 'C3': (X, 'c3', {'A': '1'})}.items()}
    send = lambda *a: json.loads(run('cast', 'send', '--json', '--rpc-url', RPC, '--private-key', OWNER_KEY, reg, *a))
    for app in (X, Y):
        gas[f'createApp {app[:8]}'] = int(send('createApp(bytes32,address,bytes32)', '0x' + app, OWNER, '0x' + SCOPE)['gasUsed'], 16)
    for n, app in (('C1', X), ("C1'", X), ('C2', Y)):
        h = hashlib.sha256(composes[n]).hexdigest()
        gas[f'admit {n}'] = int(send('admit(bytes32,bytes32,uint64,uint64)', '0x' + app, '0x' + h, '0', str(2**64 - 1))['gasUsed'], 16)
    for n, c in composes.items():
        (d / f'{n}.json').write_bytes(c)
    group = secret(d / 'group.key')
    runner_ok, runner_bad = secret(d / 'runner-ok.key'), secret(d / 'runner-bad.key')
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    ok_pub = ec.derive_private_key(int(runner_ok.read_text(), 16), ec.SECP256R1()).public_key().public_bytes(
        Encoding.X962, PublicFormat.UncompressedPoint).hex()
    nodes = {}
    for name, port, scope in (('A', 18791, SCOPE), ('B', 18792, SCOPE), ('S', 18793, '01' * 32)):
        procs.append(subprocess.Popen([sys.executable, ROOT / 'runner/kms/sdk_node.py', '--port', str(port), '--group-key', group,
                                       '--rpc', RPC, '--app-registry', reg, '--registry', REGISTRY, '--chain-id', '31337',
                                       '--scope', scope, '--key-epoch', '1', '--admit-runner', ok_pub, '--member', '00' * 32,
                                       '--m', 'standin', '--checked-tx', 'standin'], stderr=open(d / f'node-{name}.log', 'w')))
        nodes[name] = f'http://127.0.0.1:{port}'
        wait(lambda: listening(port))

    def boot(node, compose_name, runner=runner_ok):
        sock = d / f'{node}-{compose_name}-{runner.stem}.sock'
        p = subprocess.Popen([sys.executable, ROOT / 'runner/kms/sdk_runner.py', '--compose', d / f'{compose_name}.json',
                              '--node', nodes[node], '--runner-key', runner, '--socket', sock], stderr=subprocess.PIPE, text=True)
        procs.append(p)
        wait(lambda: sock.exists() or p.poll() is not None)
        if p.poll() is not None:
            return None, p.stderr.read().strip(), sock
        return sdk.Client(str(sock)), None, sock
    record('gas-anvil', gas)
    yield {'boot': boot, 'runner_bad': runner_bad, 'reg': reg, 'gas': gas}
    for p in procs:
        p.terminate()


def demo_key(client):
    info = client.info()
    reply = client.get_key('demo', 'ed25519:demo')
    verify.key_reply(reply, 'demo', 'ed25519:demo', info['group_public'])
    return info, reply


def test_same_group_key_same_app_key(net):
    (a, _, _), (b, _, _) = net['boot']('A', 'C1'), net['boot']('B', 'C1')
    (ia, ra), (ib, rb) = demo_key(a), demo_key(b)
    assert ra['key'] == rb['key'] and ra['public_key'] == rb['public_key']
    assert ia['compose_hash'] == ib['compose_hash'] and ia['app_id'] == X
    c, _, _ = net['boot']('A', "C1'")
    _, rc = demo_key(c)
    assert rc['public_key'] == ra['public_key'] and c.info()['compose_hash'] != ia['compose_hash']
    ev = a.evidence(hashlib.sha256(b'claim_pub').digest())
    statement = verify.evidence(ev, hashlib.sha256(b'claim_pub').digest(), ia['group_public'])
    assert statement[-65 - 8 - 32:-65 - 8].hex() == ia['compose_hash']
    record('1-same-group-key-same-key', {'node_A': {'info': ia, 'public_key': ra['public_key']},
                                         'node_B': {'info': ib, 'public_key': rb['public_key']},
                                         "node_A_C1prime": {'compose_hash': c.info()['compose_hash'], 'public_key': rc['public_key']},
                                         'chains_verified': True, 'evidence_A': ev})


def test_different_app_different_key(net):
    (a, _, _), (y, _, _) = net['boot']('A', 'C1'), net['boot']('A', 'C2')
    (_, ra), (iy, ry) = demo_key(a), demo_key(y)
    assert iy['app_id'] == Y and ry['public_key'] != ra['public_key'] and ry['key'] != ra['key']
    k1, k2 = a.get_key('demo', 'secp256k1:demo'), a.get_key('other', 'ed25519:demo')
    assert len({ra['key'], k1['key'], k2['key']}) == 3
    with pytest.raises(sdk.DsmackError, match='purpose'):
        a.get_key('demo', 'demo')
    record('2-different-app-different-key', {'app_X': {'public_key': ra['public_key']}, 'app_Y': {'app_id': Y, 'public_key': ry['public_key']}})


def test_unlisted_compose_refused(net):
    client, err, sock = net['boot']('A', 'C3')
    assert client is None and 'compose_not_allowed' in err and not sock.exists()
    client, err2, _ = net['boot']('S', 'C1')
    assert client is None and 'scope_not_held' in err2
    record('3-unlisted-compose-refused', {'C3_no_window': err, 'C1_at_node_without_scope': err2, 'socket_created': False})


def test_unadmitted_runner_gets_nothing(net):
    client, err, sock = net['boot']('A', 'C1', net['runner_bad'])
    assert client is None and 'runner_not_admitted' in err and not sock.exists()
    record('4-unadmitted-caller-nothing', {'error': err, 'socket_created': False})


def test_js_twin(net):
    a, _, sock = net['boot']('B', 'C1')
    _, ra = demo_key(a)
    out = json.loads(run('node', ROOT / 'sdk/js/test-client.mjs', sock))
    assert out['get_key']['public_key'] == ra['public_key'] and out['info']['app_id'] == X
    root = sdk.app_root(bytes([7]) * 32, 31337, '0x' + '11' * 20, '00' * 32, 1, 'ab' * 32)
    assert out['vectors'] == {'app_root': root.hex(), 'leaf': sdk.leaf(root, 'near-account', 'ed25519:near-account').hex()}
    record('5-js-twin', {'public_key': out['get_key']['public_key'], 'derivation_vectors_match_python': True})
