"""dsmack-sdk end to end: stand-in runners (runner/kms/sdk_runner.py) with synthetic runner App Attest evidence
against node SDK ports. Run: python3 -m pytest sdk/test_sdk.py
Default: stand-in nodes (runner/kms/sdk_node.py) on a local anvil with AppRegistry. SDK_E2E=<json> instead targets
real nodes (node/tests/sdk_e2e.py writes it): {rpc, chain_id, registry, demo, app_registry, owner_key, sponsor_seed,
fixture, nodes: {A, B}, composes: {name: path}}; with a "runner" entry (sdk_e2e.py --runner-dir) each boot is the signed
Swift runner on the Mac with fresh App Attest (node/tests/sdk_real_runner.py) instead of the stand-in.
SDK_EVIDENCE_DIR=<dir> records each outcome there as JSON. Real nodes read AppRegistry at a block; stand-in nodes still
check sponsor allow records, so each admitted window also gets one."""
import base64, hashlib, json, os, secrets, socket, subprocess, sys, time
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'sdk/python'), str(ROOT / 'runner/kms'), str(ROOT)]
import dsmack_sdk as sdk
from dsmack_sdk import b, verify
from dsmack_sdk.node import pub
from synthetic_attest import SyntheticRunner
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

OWNER_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'  # anvil account 0, public test key
OWNER = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'
SCOPE = '00' * 32
X, Y, Z = (hashlib.sha256(b'dsmack-sdk-test/app-' + n).hexdigest() for n in (b'x', b'y', b'z'))
SCOPE_Z = '01' * 32   # app Z's table scope; no node holds a key for it
OUT = Path(os.environ['SDK_EVIDENCE_DIR']) if 'SDK_EVIDENCE_DIR' in os.environ else None
FIXTURE = ROOT / 'node/tests/sdk_runner_fixture.json'


def record(name, obj):
    if OUT:
        OUT.mkdir(parents=True, exist_ok=True)
        (OUT / f'{name}.json').write_text(json.dumps(obj, indent=1, sort_keys=True) + '\n')


def run(*cmd, **kw):
    return subprocess.run([str(c) for c in cmd], check=True, capture_output=True, text=True, **kw).stdout


def wait(pred, tries=100, every=0.1):
    for _ in range(tries):
        if pred():
            return
        time.sleep(every)
    raise TimeoutError


def listening(port):
    with socket.socket() as s:
        return s.connect_ex(('127.0.0.1', port)) == 0


def compose(app_id, name, env, vm_image=None):
    """vm_image: a bootable image for the real runner, whose guest idles while the test uses its socket."""
    dc = {'services': {'app': {'image': 'docker.io/library/python@sha256:' + '0' * 64, 'environment': env}}}
    egress = {'allow': []}
    if vm_image:
        dc['services']['app'].update(image=vm_image, command=['python', '-c', 'import time; time.sleep(900)'])
        egress.update(max_requests=0, max_tokens=0)
    return json.dumps({'app_id': app_id, 'docker_compose_file': json.dumps(dc, sort_keys=True), 'egress': egress,
                       'kms_enabled': True, 'manifest_version': 2, 'name': name, 'runner': 'docker-compose'},
                      sort_keys=True, separators=(',', ':')).encode()


COMPOSES = {'C1': (X, 'c1', {'A': '1'}), "C1'": (X, 'c1', {'A': '2'}), 'C2': (Y, 'c2', {'A': '1'}), 'C3': (X, 'c3', {'A': '1'}),
            'C4': (Z, 'c4', {'A': '1'}), 'C5': (X, 'c5', {'A': '1'})}
WINDOWS = (('C1', X), ("C1'", X), ('C2', Y), ('C4', Z), ('C5', X))   # admitted on AppRegistry (and allow records); C3 is not


def secret(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, value.encode())
    os.close(fd)
    return path


def standin(d):
    """Anvil + AppRegistry + stand-in nodes A and B holding one test G at epoch 1; bump restarts A at epoch 2."""
    port = 18645
    procs = [subprocess.Popen(['anvil', '--port', str(port), '--silent'])]
    wait(lambda: listening(port))
    rpc = f'http://127.0.0.1:{port}'
    out = run('forge', 'script', 'script/AppRegistry.s.sol', '--rpc-url', rpc, '--broadcast',
              cwd=ROOT / 'contracts', env={**os.environ, 'PRIVATE_KEY': OWNER_KEY, 'FOUNDRY_DISABLE_NIGHTLY_WARNING': '1'})
    paths = {}
    for n, c in COMPOSES.items():
        paths[n] = d / f'{n}.json'
        paths[n].write_bytes(compose(*c))
    paths['coupon'] = ROOT / 'apps/coupon-sdk/app-compose.json'
    fx = d / 'fixture.json'
    run(sys.executable, ROOT / 'node/tests/sdk_runner_fixture.py', fx, *[f'--compose={n}={hashlib.sha256(paths[n].read_bytes()).hexdigest()}' for n in paths])
    sponsor = secrets.token_hex(32)
    sponsor_pub = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sponsor)).public_key().public_bytes_raw().hex()
    g1, g2 = (secret(d / f'group-{e}.key', secrets.token_bytes(31).rjust(32, b'\0').hex()) for e in (1, 2))
    cfg = {'rpc': rpc, 'chain_id': 31337, 'registry': '0x' + '11' * 20, 'app_registry': out.split('AppRegistry ')[1].split()[0],
           'owner_key': OWNER_KEY, 'sponsor_seed': sponsor, 'fixture': str(fx), 'composes': {n: str(p) for n, p in paths.items()},
           'nodes': {'A': '127.0.0.1:18791', 'B': '127.0.0.1:18792'}}
    anchor = json.loads(fx.read_text())['synthetic_root']
    nodes = {}

    def node(name, keys):
        if name in nodes:
            nodes[name].terminate()
            nodes[name].wait()
        port = int(cfg['nodes'][name].split(':')[1])
        nodes[name] = subprocess.Popen([sys.executable, ROOT / 'runner/kms/sdk_node.py', '--port', str(port), *[f'--group-key={e}={k}' for e, k in keys],
                                        '--rpc', rpc, '--registry', cfg['registry'], '--chain-id', '31337', '--scope', SCOPE, '--sponsor', sponsor_pub,
                                        '--anchor', anchor, '--runner', '5a' * 32, '--member', '0x' + '00' * 32, '--m', '0x' + '4d' * 32,
                                        '--checked-tx', 'standin'], stderr=open(d / f'node-{name}.log', 'a'))
        procs.append(nodes[name])
        wait(lambda: listening(port))
    node('A', [(1, g1)]), node('B', [(1, g1)])
    cfg['bump'] = lambda: [node(n, [(1, g1), (2, g2)]) for n in 'AB']
    return cfg, procs


@pytest.fixture(scope='module')
def net(tmp_path_factory):
    d = tmp_path_factory.mktemp('sdk')
    procs = []
    if 'SDK_E2E' in os.environ:
        cfg = json.loads(Path(os.environ['SDK_E2E']).read_text())
        cfg['bump'] = lambda: run('cast', 'send', '--rpc-url', cfg['rpc'], '--private-key', cfg['owner_key'], cfg['demo'], 'startKeyEpoch(bytes32)', '0x' + SCOPE)
    else:
        cfg, procs = standin(d)
    reg, rpc = cfg['app_registry'], cfg['rpc']
    send = lambda *a: json.loads(run('cast', 'send', '--json', '--rpc-url', rpc, '--private-key', cfg['owner_key'], reg, *a))
    gas = {}
    for app, scope in ((X, SCOPE), (Y, SCOPE), (Z, SCOPE_Z)):
        gas[f'createApp {app[:8]}'] = int(send('createApp(bytes32,address,bytes32)', '0x' + app, OWNER, '0x' + scope)['gasUsed'], 16)
    sponsor = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(cfg['sponsor_seed']))
    until = int(time.time()) + 3 * 3600

    def allow(app, compose_hash, scope=SCOPE):
        message = sdk.allow_message(cfg['chain_id'], cfg['registry'], app, compose_hash, scope, until)
        return {'scope': '0x' + scope, 'until': until, 'signature': '0x' + sponsor.sign(message).hex()}
    hashes = {n: hashlib.sha256(Path(p).read_bytes()).hexdigest() for n, p in cfg['composes'].items()}
    records = {}
    for n, app in WINDOWS:
        gas[f'admit {n}'] = int(send('admit(bytes32,bytes32,uint64,uint64)', '0x' + app, '0x' + hashes[n], '0', str(2**64 - 1))['gasUsed'], 16)
        records[n] = allow(app, hashes[n], SCOPE_Z if app == Z else SCOPE)
    for n, r in records.items():
        (d / f'allow-{n}.json').write_text(json.dumps(r))

    real = None
    if 'runner' in cfg:
        sys.path[:0] = [str(ROOT / 'node/tests')]
        from sdk_real_runner import RealRunners
        real = RealRunners(cfg, d)

    def boot(node, name, allow_from=None, enrollment=None, extra=(), record_=None):
        """Starts a runner for compose `name` on node; returns (Client, None, sock) or (None, error, sock)."""
        sock = d / f'{node}-{name}-{secrets.token_hex(3)}.sock'
        allow_path = d / f'allow-{allow_from or name}.json'
        if record_ is not None:
            allow_path = d / f'allow-custom-{secrets.token_hex(3)}.json'
            allow_path.write_text(json.dumps(record_))
        if real:
            assert enrollment in (None, name, 'wrong_cdhash'), 'a real runner enrolls only for the compose it boots'
            path, err, _ = real.boot(cfg['nodes'][node], cfg['composes'][name], json.loads(allow_path.read_text()),
                                     'wrong_cdhash' if enrollment == 'wrong_cdhash' else 'good', attest='--no-evidence' not in extra)
            return (sdk.Client(str(path)), None, path) if path else (None, err, sock)
        p = subprocess.Popen([sys.executable, ROOT / 'runner/kms/sdk_runner.py', '--compose', cfg['composes'][name], '--node', cfg['nodes'][node],
                              '--allow', allow_path, '--fixture', cfg['fixture'], '--enrollment', enrollment or name, '--socket', sock, *extra],
                             stderr=subprocess.PIPE, text=True)
        procs.append(p)
        wait(lambda: sock.exists() or p.poll() is not None, 300)
        if p.poll() is not None:
            return None, p.stderr.read().strip(), sock
        return sdk.Client(str(sock)), None, sock
    record('gas-anvil', gas)
    yield {**cfg, 'boot': boot, 'hashes': hashes, 'allow': allow, 'dir': d, 'real': real, 'send': send}
    for p in procs:
        p.terminate()
    if real:
        real.close()


def demo_key(client, epoch=None, group_public=None):
    info = client.info()
    reply = client.get_key('demo', 'ed25519:demo', epoch)
    verify.key_reply(reply, 'demo', 'ed25519:demo', group_public or info['group_public'])
    return info, reply


def test_vectors_match_swift():
    """The vectors node/tests/SDKVectors.swift pins, from the same fixed group scalars."""
    g2 = (0x22).to_bytes(32, 'big')
    root = sdk.app_root(g2, 84532, '0xd4b33c83576a6049d29c6b849ec73491e52781a0', SCOPE, 2, 'a1' * 32)
    assert root.hex() == 'ff7581dad655737c4a35ef4192a3f5897bfdf54ea7c70570b8c185a4230fab59'
    assert pub(ec.derive_private_key(sdk.app_signer(root), ec.SECP256R1())) == APP_PUB_X2
    assert sdk.leaf(root, 'near-account', 'ed25519:near-account').hex() == LEAF_X2
    record('0-vectors', {'app_root_x2': root.hex(), 'app_pub_x2': APP_PUB_X2, 'leaf_x2_near_account': LEAF_X2})


def test_fixture_evidence_verifies():
    """Client-side runner evidence from the committed fixture, checked by verifier/core.py at the fixture's time."""
    from verifier.core import Policy, verify_assertion, verify_attestation
    fx = json.loads(FIXTURE.read_text())
    runner = SyntheticRunner(FIXTURE, 'good')
    request = {'v': 1, 'op': 'info', 'app_id': '0x' + X, 'compose_hash': '0x' + fx['compose_sha256'], 'allow': {'scope': '0x' + SCOPE, 'until': 1, 'signature': '0x'}}
    data = sdk.runner_data('0x' + '09' * 32, request)
    e = runner.attest(data)
    policy = Policy('DC9JH5DRMY.dev.dsmack.provider', environment='production', categories=(3,), cdhashes=(b(fx['cdhash']),), require_macos_acl=True)
    pem = b'-----BEGIN CERTIFICATE-----\n' + base64.encodebytes(base64.b64decode(fx['synthetic_root'])) + b'-----END CERTIFICATE-----\n'
    enrolled = verify_attestation(base64.b64decode(e['attestation']), e['keyId'], base64.b64decode(e['bootClientData']), policy, pem, fx['now'])
    verify_assertion(base64.b64decode(e['assertion']), base64.b64decode(e['assertClientData']), enrolled['public_key'], 0, policy)
    assert json.loads(base64.b64decode(e['assertClientData']))['data'].startswith('dsmack-sdk-runner/1|0x' + '09' * 32 + '|0x')


def test_same_group_key_same_app_key(net):
    (a, err_a, _), (bb, err_b, _) = net['boot']('A', 'C1'), net['boot']('B', 'C1')
    assert a and bb, (err_a, err_b)
    (ia, ra), (ib, rb) = demo_key(a), demo_key(bb)
    assert ra['key'] == rb['key'] and ra['public_key'] == rb['public_key']
    assert ia['group_public'] == ib['group_public']
    assert b(ia['compose_hash']) == b(ib['compose_hash']) == b(net['hashes']['C1']) and b(ia['app_id']) == b(X)
    c, err, _ = net['boot']('A', "C1'")
    assert c, err
    _, rc = demo_key(c)
    assert rc['public_key'] == ra['public_key'] and b(c.info()['compose_hash']) != b(ia['compose_hash'])
    ev = a.evidence(hashlib.sha256(b'claim_pub').digest())
    statement = verify.evidence(ev, hashlib.sha256(b'claim_pub').digest(), ia['group_public'])
    assert statement[-65 - 64 - 32:-65 - 64] == b(ia['compose_hash']) and statement[-65 - 32:-65] == b(ia['M'])
    if net['real']:
        assert ia['cdhash'] == ib['cdhash'] == net['runner']['cdhash']
        ev['assertion_verified'] = apple_assertion(ev['assertion'], net['runner']['cdhash'], ia['compose_hash'],
                                                   hashlib.sha256(b'claim_pub').digest().hex(), 'dsmack-sdk-assert/1')
    record('1-same-group-key-same-key', {'node_A': {'info': ia, 'public_key': ra['public_key'], 'chain': ra['chain']},
                                         'node_B': {'info': ib, 'public_key': rb['public_key']},
                                         "node_A_C1prime": {'compose_hash': c.info()['compose_hash'], 'public_key': rc['public_key']},
                                         'chains_verified': True, 'evidence_A': ev})


def test_different_app_different_key(net):
    (a, _, _), (y, err, _) = net['boot']('A', 'C1'), net['boot']('A', 'C2')
    assert y, err
    (_, ra), (iy, ry) = demo_key(a), demo_key(y)
    assert b(iy['app_id']) == b(Y) and ry['public_key'] != ra['public_key'] and ry['key'] != ra['key']
    k1, k2, k3 = a.get_key('demo', 'secp256k1:demo'), a.get_key('other', 'ed25519:demo'), a.get_key('demo', 'p256:demo')
    assert len({ra['key'], k1['key'], k2['key'], k3['key']}) == 4
    group = a.info()['group_public']
    verify.key_reply(k1, 'demo', 'secp256k1:demo', group), verify.key_reply(k3, 'demo', 'p256:demo', group)
    assert set(a.get_key('demo', 'raw:demo')) == {'v', 'key'}
    with pytest.raises(sdk.DsmackError, match='purpose'):
        a.get_key('demo', 'demo')
    record('2-different-app-different-key', {'app_X': {'public_key': ra['public_key'], 'secp256k1': k1['public_key'], 'p256': k3['public_key']},
                                             'app_Y': {'app_id': Y, 'public_key': ry['public_key']}})


def test_unlisted_compose_refused(net):
    client, err, sock = net['boot']('A', 'C3', allow_from='C1')
    assert client is None and 'compose not allowed under app_id' in err and not sock.exists()
    client, err2, _ = net['boot']('A', 'C4')
    assert client is None and f'no group key held for scope 0x{SCOPE_Z}' in err2
    record('3-unlisted-compose-refused', {'C3_not_in_table': err, 'C4_scope_not_held': err2, 'socket_created': False})


def test_no_evidence_runner_refused(net):
    client, err, sock = net['boot']('A', 'C1', extra=['--no-evidence'])
    # The real runner's --no-attest still sends evidence, of type "dev"; the stand-in sends none.
    assert client is None and ('runner evidence fields' if net['real'] else 'runner evidence required') in err and not sock.exists()
    client, err2, _ = net['boot']('A', 'C1', enrollment='wrong_cdhash')
    assert client is None and 'cdhash_policy_failed' in err2
    out = {'no_evidence': err, 'runner_cdhash_not_admitted': err2, 'socket_created': False}
    if not net['real']:  # an honest runner cannot enroll for a compose other than the one it boots
        client, err3, _ = net['boot']('A', 'C1', enrollment='C2')
        assert client is None and 'not this compose' in err3
        out['enrollment_for_other_compose'] = err3
    record('4-no-evidence-refused', out)


def test_js_twin(net):
    a, err, sock = net['boot']('B', 'C1')
    assert a, err
    _, ra = demo_key(a)
    out = json.loads(run('node', ROOT / 'sdk/js/test-client.mjs', sock))
    assert out['get_key']['public_key'] == ra['public_key'] and b(out['info']['app_id']) == b(X)
    root = sdk.app_root(bytes([7]) * 32, 31337, '0x' + '11' * 20, SCOPE, 1, 'ab' * 32)
    assert out['vectors'] == {'app_root': root.hex(), 'leaf': sdk.leaf(root, 'near-account', 'ed25519:near-account').hex()}
    record('5-js-twin', {'public_key': out['get_key']['public_key'], 'derivation_vectors_match_python': True})


def test_coupon_account_derive(net):
    """apps/coupon-sdk's derive step (coupon_account.py account) through a runner for its compose."""
    h = net['hashes']['coupon']
    app = json.loads(Path(net['composes']['coupon']).read_bytes())['app_id']
    send = lambda *a: run('cast', 'send', '--rpc-url', net['rpc'], '--private-key', net['owner_key'], net['app_registry'], *a)
    send('createApp(bytes32,address,bytes32)', '0x' + app, OWNER, '0x' + SCOPE)
    send('admit(bytes32,bytes32,uint64,uint64)', '0x' + app, '0x' + h, '0', str(2**64 - 1))
    if net['real']:  # the coupon container itself, in the Runner VM, through /var/run/dsmack.sock
        stdout, log = net['real'].run_to_exit(net['nodes']['A'], net['composes']['coupon'], net['allow'](app, h))
        out = json.loads(stdout.strip().splitlines()[-1])
        assert 'guest exited' in log, log
    else:
        c, err, sock = net['boot']('A', 'coupon', record_=net['allow'](app, h))
        assert c, err
        out = json.loads(run(sys.executable, ROOT / 'apps/coupon-sdk/coupon_account.py', 'account',
                             env={**os.environ, 'PYTHONPATH': str(ROOT / 'sdk/python'), 'DSMACK_SOCKET': str(sock), 'NEAR_RPC': 'unused-by-account'}))
    assert out['chain_verified'] and b(out['compose_hash']) == b(h) and len(out['account_id']) == 64
    record('6-coupon-account', out)


@pytest.mark.skipif('SDK_E2E' not in os.environ, reason='stand-in nodes check allow records, not AppRegistry')
def test_registry_window(net):
    """The node reads composes(app, compose) at a block: open window served, closed window refused, and the statement's
    earlier block still reads as allowed (the verifier's re-read)."""
    c, err, _ = net['boot']('B', 'C5')
    assert c, err
    _, r = demo_key(c)
    statement = b(r['chain'][0]['message'])
    issued = int.from_bytes(statement[16 + 6 * 32:16 + 7 * 32], 'big')
    h = '0x' + net['hashes']['C5']
    closed = int(run('cast', 'block-number', '--rpc-url', net['rpc']))
    assert issued < closed
    net['send']('admit(bytes32,bytes32,uint64,uint64)', '0x' + X, h, '0', str(closed))
    with pytest.raises(sdk.DsmackError, match=f'compose window closed at block {closed}'):
        c.info()
    again, err2, _ = net['boot']('A', 'C5')
    assert again is None and f'compose window closed at block {closed}' in err2
    allowed = lambda at: run('cast', 'call', '--rpc-url', net['rpc'], '--block', str(at), net['app_registry'],
                             'isAllowed(bytes32,bytes32,uint256)(bool)', '0x' + X, h, str(issued)).strip()
    latest = int(run('cast', 'block-number', '--rpc-url', net['rpc']))
    assert allowed(issued) == 'true' and allowed(latest) == 'true'
    record('8-registry-window', {'statement_block': issued, 'window_until': closed, 'refused_open_runner': True,
                                 'refused_new_boot': err2, 'isAllowed_at_statement_block': True, 'isAllowed_statement_block_read_at_latest': True})


def test_previous_epoch_after_bump(net):
    """A (seed) and B (participant) both serve the new epoch and the previous one after startKeyEpoch."""
    before, clients = {}, {}
    for n in 'AB':
        clients[n], err, _ = net['boot'](n, 'C1')
        assert clients[n], err
        before[n] = demo_key(clients[n])
    old = before['A'][0]['key_epoch']
    net['bump']()
    rec = {'epoch_before': old}
    for n in 'AB':
        before_info, before_key = before[n]
        deadline = time.time() + 300
        while net['real'] and clients[n].info()['key_epoch'] != old + 1:  # through the runner booted before the bump
            assert time.time() < deadline
            time.sleep(5)
        while True:
            c, err, _ = net['boot'](n, 'C1')
            if c and c.info()['key_epoch'] == old + 1:
                break
            assert time.time() < deadline, err
            time.sleep(5)
        info, now = demo_key(c)
        _, prev = demo_key(c, old, before_info['group_public'])
        assert now['public_key'] != before_key['public_key'] and info['group_public'] != before_info['group_public']
        assert prev['public_key'] == before_key['public_key'] and prev['key_epoch'] == old
        with pytest.raises(sdk.DsmackError, match=f'key epoch {old + 2} not held'):
            c.get_key('demo', 'ed25519:demo', old + 2)
        rec[n] = {'epoch_after': info['key_epoch'], 'public_key_before': before_key['public_key'], 'public_key_after': now['public_key'],
                  'public_key_previous_epoch_after_bump': prev['public_key'], 'group_public_before': before_info['group_public'],
                  'group_public_after': info['group_public']}
    assert rec['A']['public_key_after'] == rec['B']['public_key_after']
    record('7-previous-epoch', rec)


def apple_assertion(e, cdhash, compose_hash, data, domain):
    """A real runner's App Attest evidence, checked by verifier/core.py against Apple's root, for this CDHash only."""
    sys.path[:0] = [str(ROOT / 'app/macos')]
    from check_evidence import policy, root
    from verifier.core import verify_assertion, verify_attestation
    pol = policy(b(cdhash))
    enrolled = verify_attestation(base64.b64decode(e['attestation']), e['keyId'], base64.b64decode(e['bootClientData']), pol, root(), time.time())
    verify_assertion(base64.b64decode(e['assertion']), base64.b64decode(e['assertClientData']), enrolled['public_key'], 0, pol)
    asserted = json.loads(base64.b64decode(e['assertClientData']))
    assert asserted == {'compose_hash': b(compose_hash).hex(), 'data': data, 'domain': domain}, asserted
    return True


APP_PUB_X2 = '0499a9357634ed27c08281b0b7eae22d69f20bfdf4df82b4a56e20ba8d6ce4914becc54035cd9c3112e69b314bdf9d5f7f0692877e1efbc3a38c565ef9ddd237fb'
LEAF_X2 = 'dd5ea56b2eee1eda3497b19e04546459abb967d68dab4dd96245579a85269bf0'
