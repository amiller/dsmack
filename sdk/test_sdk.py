"""dsmack-sdk end to end: stand-in runners (runner/kms/sdk_runner.py) with synthetic runner App Attest evidence
against node SDK ports. Run: python3 -m pytest sdk/test_sdk.py
Default: stand-in nodes (runner/kms/sdk_node.py) on a local anvil with AppRegistry. SDK_E2E=<json> instead targets
real nodes (node/tests/sdk_e2e.py writes it): {rpc, chain_id, registry, demo, app_registry, owner_key,
fixture, nodes: {A, B}, composes: {name: path}}; with a "runner" entry (sdk_e2e.py --runner-dir) each boot is the signed
Swift runner on the Mac with fresh App Attest (node/tests/sdk_real_runner.py) instead of the stand-in.
SDK_EVIDENCE_DIR=<dir> records each outcome there as JSON. Real and stand-in nodes both admit the runner first, then read
AppRegistry at a block; stand-in nodes hold a test G committed on a real DemoV2 (runner/kms/standin_chain.py), and every
runner and this suite check G against sharedKeys(scope) on chain."""
import base64, hashlib, json, os, secrets, socket, subprocess, sys, time
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'sdk/python'), str(ROOT / 'runner/kms'), str(ROOT)]
import dsmack_sdk as sdk
from dsmack_sdk import b, verify
from dsmack_sdk.node import pub
from synthetic_attest import SyntheticRunner
import standin_chain
from cryptography.hazmat.primitives.asymmetric import ec

OWNER_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'  # anvil account 0, public test key
OWNER = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'
SCOPE = '00' * 32
X, Y, Z = (hashlib.sha256(b'dsmack-sdk-test/app-' + n).hexdigest() for n in (b'x', b'y', b'z'))
SCOPE_Z = '01' * 32   # app Z's table scope; no node holds a key for it
OUT = Path(os.environ['SDK_EVIDENCE_DIR']) if 'SDK_EVIDENCE_DIR' in os.environ else None
FIXTURE = ROOT / 'node/tests/sdk_runner_fixture.json'
RELEASE_APP_REGISTRY = '0xa4d26dedf4d086216a0e2cfbc7bda49918f5c5c3'   # node/mac/NetworkConfig.swift appRegistry
RELEASE_RPC, RELEASE_REGISTRY = 'https://sepolia.base.org', '0xd4B33C83576a6049d29c6B849ec73491e52781a0'   # and its rpc, registry


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


def compose(app_id, name, env, vm_image=None, bridge_port=None):
    """vm_image: a bootable image for the real runner, whose guest bridges its /var/run/dsmack.sock to the test
    (node/tests/sdk_real_runner.py) through runner CONNECT tunnels to bridge_port."""
    dc = {'services': {'app': {'image': 'docker.io/library/python@sha256:' + '0' * 64, 'environment': env}}}
    egress = {'allow': []}
    if vm_image:
        sys.path[:0] = [str(ROOT / 'node/tests')]
        from sdk_real_runner import bridge_compose
        command, tcp = bridge_compose(bridge_port)
        dc['services']['app'].update(image=vm_image, command=command)
        egress.update(max_requests=0, max_tokens=0, tcp=tcp)
    return json.dumps({'app_id': app_id, 'docker_compose_file': json.dumps(dc, sort_keys=True), 'egress': egress,
                       'kms_enabled': True, 'manifest_version': 2, 'name': name, 'runner': 'docker-compose'},
                      sort_keys=True, separators=(',', ':')).encode()


COMPOSES = {'C1': (X, 'c1', {'A': '1'}), "C1'": (X, 'c1', {'A': '2'}), 'C2': (Y, 'c2', {'A': '1'}), 'C3': (X, 'c3', {'A': '1'}),
            'C4': (Z, 'c4', {'A': '1'}), 'C5': (X, 'c5', {'A': '1'})}
WINDOWS = (('C1', X), ("C1'", X), ('C2', Y), ('C4', Z), ('C5', X))   # admitted on AppRegistry; C3 is not


def secret(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, value.encode())
    os.close(fd)
    return path


def standin(d):
    """Anvil + AppRegistry + DemoV2 at key epoch 1 with test G1 committed + stand-in nodes A and B holding G1 and G2;
    bump is DemoV2.startKeyEpoch with G2 committed, and the running nodes follow it."""
    port = 18645
    procs = [subprocess.Popen(['anvil', '--port', str(port), '--silent'])]
    wait(lambda: listening(port))
    rpc = f'http://127.0.0.1:{port}'
    out = run('forge', 'script', 'script/AppRegistry.s.sol', '--rpc-url', rpc, '--broadcast',
              cwd=ROOT / 'contracts', env={**os.environ, 'PRIVATE_KEY': OWNER_KEY, 'FOUNDRY_DISABLE_NIGHTLY_WARNING': '1'})
    demo = standin_chain.deploy_demo(rpc, OWNER_KEY, OWNER)
    paths = {}
    for n, c in COMPOSES.items():
        paths[n] = d / f'{n}.json'
        paths[n].write_bytes(compose(*c))
    paths['coupon'] = ROOT / 'apps/coupon-sdk/app-compose.json'
    fx = d / 'fixture.json'
    run(sys.executable, ROOT / 'node/tests/sdk_runner_fixture.py', fx, *[f'--compose={n}={hashlib.sha256(paths[n].read_bytes()).hexdigest()}' for n in paths])
    g1, g2 = (secret(d / f'group-{e}.key', secrets.token_bytes(31).rjust(32, b'\0').hex()) for e in (1, 2))
    standin_chain.start_epoch(rpc, OWNER_KEY, demo, SCOPE)
    standin_chain.commit(rpc, demo, SCOPE, g1.read_text())
    cfg = {'rpc': rpc, 'chain_id': 31337, 'registry': demo, 'demo': demo, 'app_registry': out.split('AppRegistry ')[1].split()[0],
           'owner_key': OWNER_KEY, 'fixture': str(fx), 'composes': {n: str(p) for n, p in paths.items()},
           'nodes': {'A': '127.0.0.1:18791', 'B': '127.0.0.1:18792'}}
    anchor = json.loads(fx.read_text())['synthetic_root']
    nodes = {}

    def node(name, keys):
        port = int(cfg['nodes'][name].split(':')[1])
        nodes[name] = subprocess.Popen([sys.executable, ROOT / 'runner/kms/sdk_node.py', '--port', str(port), *[f'--group-key={e}={k}' for e, k in keys],
                                        '--rpc', rpc, '--registry', cfg['registry'], '--app-registry', cfg['app_registry'], '--chain-id', '31337', '--scope', SCOPE,
                                        '--anchor', anchor, '--runner', json.loads(fx.read_text())['runner_m'], '--member', '0x' + '00' * 32, '--m', '0x' + '4d' * 32,
                                        '--checked-tx', 'standin'], stderr=open(d / f'node-{name}.log', 'a'))
        procs.append(nodes[name])
        wait(lambda: listening(port))
    node('A', [(1, g1), (2, g2)]), node('B', [(1, g1), (2, g2)])
    cfg['bump'] = lambda: (standin_chain.start_epoch(rpc, OWNER_KEY, demo, SCOPE), standin_chain.commit(rpc, demo, SCOPE, g2.read_text()))
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
    hashes = {n: hashlib.sha256(Path(p).read_bytes()).hexdigest() for n, p in cfg['composes'].items()}
    for n, app in WINDOWS:
        gas[f'admit {n}'] = int(send('admit(bytes32,bytes32,uint64,uint64)', '0x' + app, '0x' + hashes[n], '0', str(2**64 - 1))['gasUsed'], 16)

    real = None
    if 'runner' in cfg:
        sys.path[:0] = [str(ROOT / 'node/tests')]
        from sdk_real_runner import RealRunners
        real = RealRunners(cfg, d)

    def boot(node, name, enrollment=None, extra=()):
        """Starts a runner for compose `name` on node; returns (Client, None, sock) or (None, error, sock)."""
        sock = d / f'{node}-{name}-{secrets.token_hex(3)}.sock'
        if real:
            assert enrollment in (None, name, 'resigned', 'modified'), 'a real runner enrolls only for the compose it boots'
            path, err, _ = real.boot(cfg['nodes'][node], cfg['composes'][name], enrollment if enrollment in ('resigned', 'modified') else 'good',
                                     attest='--no-evidence' not in extra)
            return (sdk.Client(str(path)), None, path) if path else (None, err, sock)
        p = subprocess.Popen([sys.executable, ROOT / 'runner/kms/sdk_runner.py', '--compose', cfg['composes'][name], '--node', cfg['nodes'][node],
                              '--rpc', cfg['rpc'], '--registry', cfg['registry'], '--app-registry', cfg['app_registry'], '--fixture', cfg['fixture'], '--enrollment', enrollment or name, '--socket', sock, *extra],
                             stderr=subprocess.PIPE, text=True)
        procs.append(p)
        wait(lambda: sock.exists() or p.poll() is not None, 300)
        if p.poll() is not None:
            return None, p.stderr.read().strip(), sock
        return sdk.Client(str(sock)), None, sock
    record('gas-anvil', gas)
    yield {**cfg, 'boot': boot, 'hashes': hashes, 'dir': d, 'real': real, 'send': send}
    for p in procs:
        p.terminate()
    if real:
        real.close()


def demo_key(client, net, epoch=None, group_public=None):
    """get_key('demo'), both chain links checked, and G checked against the registry's sharedKeys(scope) on chain."""
    info = client.info()
    reply = client.get_key('demo', 'ed25519:demo', epoch)
    group = group_public or info['group_public']
    st = verify.statement_fields(verify.key_reply(reply, 'demo', 'ed25519:demo', group))
    assert st['key_epoch'] == reply['key_epoch'] and st['registry'] == net['registry'].lower() and st['app_registry'] == net['app_registry'].lower()
    verify.group_on_chain(net['rpc'], net['registry'], st['scope'], st['key_epoch'], group, st['block'], previous=epoch is not None)
    return info, reply


def test_vectors_match_swift():
    """The vectors node/tests/SDKVectors.swift pins, from the same fixed group scalars. B2: another AppRegistry naming the
    same app_id derives another root."""
    g2 = (0x22).to_bytes(32, 'big')
    root = sdk.app_root(g2, 84532, '0xd4b33c83576a6049d29c6b849ec73491e52781a0', RELEASE_APP_REGISTRY, SCOPE, 2, 'a1' * 32)
    assert root.hex() == APP_ROOT_X2
    assert sdk.app_root(g2, 84532, '0xd4b33c83576a6049d29c6b849ec73491e52781a0', '0x9a676e781a523b5d0c0e43731313a708cb607508', SCOPE, 2, 'a1' * 32) != root
    assert pub(ec.derive_private_key(sdk.app_signer(root), ec.SECP256R1())) == APP_PUB_X2
    assert sdk.leaf(root, 'near-account', 'ed25519:near-account').hex() == LEAF_X2
    record('0-vectors', {'app_root_x2': root.hex(), 'app_pub_x2': APP_PUB_X2, 'leaf_x2_near_account': LEAF_X2})


@pytest.mark.skipif('SDK_LIVE_BASE_SEPOLIA' not in os.environ, reason='read-only check against the release RPC; set SDK_LIVE_BASE_SEPOLIA=1')
def test_previous_epoch_on_base_sepolia():
    """The previous-epoch group-key check against the release network, read only. sepolia.base.org caps eth_getLogs at
    200 blocks, so the check bisects keyEpochs(scope) instead. The previous epoch's last block found that way is
    cross-checked by the KeyEpochStarted(scope, prev + 1) log in the block after it (a one-block log range)."""
    u, r = RELEASE_RPC, RELEASE_REGISTRY
    latest = int(verify.rpc(u, 'eth_blockNumber', []), 16)
    now = verify.key_epoch_at(u, r, SCOPE, latest)
    assert now >= 2, now
    shared = lambda at: b(verify.rpc(u, 'eth_call', [{'to': r, 'data': verify.SHARED_KEYS + SCOPE}, hex(at)]))
    g_now = '04' + shared(latest)[:64].hex()
    assert verify.group_on_chain(u, r, SCOPE, now, g_now, latest) == latest
    end = verify.epoch_end(u, r, SCOPE, now - 1, latest)
    assert verify.key_epoch_at(u, r, SCOPE, end) == now - 1 and verify.key_epoch_at(u, r, SCOPE, end + 1) == now
    started = verify.rpc(u, 'eth_getLogs', [{'address': r, 'topics': ['0x143519224fe404fde2f926e45a8cd8de4da43c648680d13caadff828449c7ad0', '0x' + SCOPE],
                                             'fromBlock': hex(end + 1), 'toBlock': hex(end + 1)}])
    assert [int(l['data'], 16) for l in started] == [now], started
    k = shared(end)
    assert k[127] == 1
    g_prev = '04' + k[:64].hex()
    assert verify.group_on_chain(u, r, SCOPE, now - 1, g_prev, latest, previous=True) == end
    with pytest.raises(verify.Invalid, match='is not the current key epoch'):
        verify.group_on_chain(u, r, SCOPE, now - 1, g_prev, latest)
    with pytest.raises(verify.Invalid, match='group key is not sharedKeys'):
        verify.group_on_chain(u, r, SCOPE, now - 1, g_now, latest, previous=True)
    if now >= 3:
        with pytest.raises(verify.Invalid, match='is not the current key epoch'):
            verify.group_on_chain(u, r, SCOPE, now - 2, g_prev, latest, previous=True)
    record('12-previous-epoch-base-sepolia', {'rpc': u, 'registry': r, 'latest': latest, 'key_epoch': now, 'previous_epoch_last_block': end,
                                              'group_public_now': g_now, 'group_public_previous': g_prev})


def test_runner_network_is_release_network():
    """The runner's compiled network (RunnerNetwork, inside M_runner) is the node's ReleaseNetwork."""
    import re
    node = json.loads(re.search(r'#"""\s*(\{.*?\})\s*"""#', (ROOT / 'node/mac/NetworkConfig.swift').read_text(), re.S).group(1))
    runner = dict(re.findall(r'(rpc|registry|appRegistry) = "([^"]+)"', (ROOT / 'runner/Sources/runner/GroupCheck.swift').read_text()))
    chain = int(re.search(r'chainId: UInt64 = (\d+)', (ROOT / 'runner/Sources/runner/GroupCheck.swift').read_text()).group(1))
    assert runner == {k: node[k] for k in ('rpc', 'registry', 'appRegistry')} and chain == node['chainId'], (runner, chain)
    assert (RELEASE_RPC, RELEASE_REGISTRY, RELEASE_APP_REGISTRY) == (node['rpc'], node['registry'], node['appRegistry'].lower())


def test_fixture_evidence_verifies():
    """Client-side runner evidence from the committed fixture, checked by verifier/core.py at the fixture's time."""
    from verifier.core import Policy, verify_assertion, verify_attestation
    fx = json.loads(FIXTURE.read_text())
    runner = SyntheticRunner(FIXTURE, 'good')
    request = {'v': 1, 'op': 'info', 'app_id': '0x' + X, 'compose_hash': '0x' + fx['compose_sha256']}
    data = sdk.runner_data('0x' + '09' * 32, request)
    e = runner.attest(data)
    policy = Policy('DC9JH5DRMY.dev.dsmack.provider', environment='production', categories=(6,), cdhashes=(b(fx['enrollments']['good']['cdhash']),), require_macos_acl=True)
    pem = b'-----BEGIN CERTIFICATE-----\n' + base64.encodebytes(base64.b64decode(fx['synthetic_root'])) + b'-----END CERTIFICATE-----\n'
    enrolled = verify_attestation(base64.b64decode(e['attestation']), e['keyId'], base64.b64decode(e['bootClientData']), policy, pem, fx['now'])
    verify_assertion(base64.b64decode(e['assertion']), base64.b64decode(e['assertClientData']), enrolled['public_key'], 0, policy)
    asserted = json.loads(base64.b64decode(e['assertClientData']))
    assert asserted['domain'] == 'dsmack-sdk-runner/1' and asserted['data'].startswith('dsmack-sdk-runner/1|0x' + '09' * 32 + '|0x')


def test_same_group_key_same_app_key(net):
    (a, err_a, _), (bb, err_b, _) = net['boot']('A', 'C1'), net['boot']('B', 'C1')
    assert a and bb, (err_a, err_b)
    (ia, ra), (ib, rb) = demo_key(a, net), demo_key(bb, net)
    assert ra['key'] == rb['key'] and ra['public_key'] == rb['public_key']
    assert ia['group_public'] == ib['group_public']
    assert b(ia['compose_hash']) == b(ib['compose_hash']) == b(net['hashes']['C1']) and b(ia['app_id']) == b(X)
    c, err, _ = net['boot']('A', "C1'")
    assert c, err
    _, rc = demo_key(c, net)
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
    (_, ra), (iy, ry) = demo_key(a, net), demo_key(y, net)
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
    client, err, sock = net['boot']('A', 'C3')
    assert client is None and 'compose not allowed under app_id' in err and not sock.exists()
    client, err2, _ = net['boot']('A', 'C4')
    assert client is None and f'no group key held for scope 0x{SCOPE_Z}' in err2
    record('3-unlisted-compose-refused', {'C3_not_in_table': err, 'C4_scope_not_held': err2, 'socket_created': False})


def test_no_evidence_runner_refused(net):
    client, err, sock = net['boot']('A', 'C1', extra=['--no-evidence'])
    # The real runner's --no-attest still sends evidence, of type "dev"; the stand-in sends none.
    assert client is None and 'runner_not_admitted' in err and ('runner evidence fields' if net['real'] else 'runner evidence required') in err and not sock.exists()
    out = {'no_evidence': err, 'socket_created': False}
    if not net['real']:  # an honest runner cannot enroll for a compose other than the one it boots
        client, err3, _ = net['boot']('A', 'C1', enrollment='C2')
        assert client is None and 'not this compose' in err3
        out['enrollment_for_other_compose'] = err3
    record('4-no-evidence-refused', out)


def test_attest_assertion_is_not_admission(net):
    """B1: runner.local/attest signs any caller's data in domain mac-compose-assert/1, and any host process reaches it over
    the run's egress.sock. Such an assertion, over the right challenge and request, with the admitted runner's own
    CodeDirectory, gets runner_not_admitted and no sealed root. Stand-in: the synthetic runner signs in that domain."""
    if not net['real']:
        client, err, sock = net['boot']('A', 'C1', extra=['--admission-domain', 'mac-compose-assert/1'])
        assert client is None and 'runner_not_admitted: runner assertion is not over this challenge and request' in err and not sock.exists(), err
        record('11-attest-is-not-admission', {'standin_refused': err})
        return
    c, err, sock = net['boot']('A', 'C1')
    assert c, err
    rd = net['real'].rd_of[str(sock)]
    code = net['real'].runner_code('good')   # before the challenge, which expires in 60 s
    host, port = net['nodes']['A'].rsplit(':', 1)
    with socket.create_connection((host, int(port)), timeout=60) as s:
        lines = s.makefile('rb')
        ask = lambda q: (s.sendall(json.dumps(q).encode() + b'\n'), json.loads(lines.readline()))[1]
        challenge = ask({'v': 1, 'op': 'challenge'})['challenge']
        eph = ec.generate_private_key(ec.SECP256R1())
        q = {'v': 1, 'op': 'get_key', 'app_id': X, 'compose_hash': net['hashes']['C1'], 'eph_pub': pub(eph)}
        borrowed = net['real'].host_attest(rd, sdk.runner_data(challenge, q))
        assert borrowed['type'] == 'macrunner' and json.loads(base64.b64decode(borrowed['assertClientData']))['domain'] == 'mac-compose-assert/1'
        reply = ask({**q, 'runner_evidence': {**borrowed, 'code': code}})
    assert 'runner_not_admitted: runner assertion is not over this challenge and request' in reply.get('error', '') and 'sealed' not in reply, reply
    record('11-attest-is-not-admission', {'run_dir': rd, 'host_egress_attest_domain': 'mac-compose-assert/1', 'node_reply': reply})


def test_runner_admitted_by_measurement(net):
    """Runners are admitted by M_runner of their attested CodeDirectory, not by CDHash: another signing of the admitted
    runner (stand-in: another team's App ID and CDHash; real: the same binary re-signed, build-other) is admitted and
    derives the same key; a modified runner is refused; (stand-in) a CodeDirectory that is not the attested one is refused."""
    good, err, _ = net['boot']('A', 'C1')
    assert good, err
    _, key = demo_key(good, net)
    other, err, _ = net['boot']('A', 'C1', enrollment='resigned' if net['real'] else 'C1@other_team')
    assert other, err
    _, other_key = demo_key(other, net)
    assert other_key['public_key'] == key['public_key']
    out = {'other_signing_public_key': other_key['public_key'], 'public_key': key['public_key']}
    if net['real']:
        assert other.info()['cdhash'] == net['runner']['other_cdhash'] != good.info()['cdhash'] == net['runner']['cdhash']
        out.update(cdhash=net['runner']['cdhash'], other_cdhash=net['runner']['other_cdhash'], m_runner=net['runner']['m_runner'])
    client, err, _ = net['boot']('A', 'C1', enrollment='modified' if net['real'] else 'C1@modified')
    assert client is None and 'not admitted' in err and 'runner measurement 0x' in err, err
    out['modified_refused'] = err
    if not net['real']:
        client, err, _ = net['boot']('A', 'C1', extra=['--code', 'resigned'])
        assert client is None and 'runner CodeDirectory is not the attested CDHash' in err, err
        out['codedirectory_not_attested_refused'] = err
    record('10-runner-by-measurement', out)


def test_js_twin(net):
    a, err, sock = net['boot']('B', 'C1')
    assert a, err
    _, ra = demo_key(a, net)
    out = json.loads(run('node', ROOT / 'sdk/js/test-client.mjs', sock))
    assert out['get_key']['public_key'] == ra['public_key'] and b(out['info']['app_id']) == b(X)
    root = sdk.app_root(bytes([7]) * 32, 31337, '0x' + '11' * 20, '0x' + '22' * 20, SCOPE, 1, 'ab' * 32)
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
        stdout, log = net['real'].run_to_exit(net['nodes']['A'], net['composes']['coupon'])
        out = json.loads(stdout.strip().splitlines()[-1])
        assert 'guest exited' in log, log
    else:
        c, err, sock = net['boot']('A', 'coupon')
        assert c, err
        out = json.loads(run(sys.executable, ROOT / 'apps/coupon-sdk/coupon_account.py', 'account',
                             env={**os.environ, 'PYTHONPATH': str(ROOT / 'sdk/python'), 'DSMACK_SOCKET': str(sock), 'NEAR_RPC': 'unused-by-account'}))
    assert out['chain_verified'] and b(out['compose_hash']) == b(h) and len(out['account_id']) == 64
    assert app == '25e69b5ec66f7453e69abfcf0e4ec54e35643db48be80fa9f96c464010d8429f'   # keccak("dsmack-coupon-v1"), the registered coupon app
    st = verify.statement_fields(b(out['statement']))
    verify.group_on_chain(net['rpc'], net['registry'], st['scope'], st['key_epoch'], out['group_public'], st['block'])
    record('6-coupon-account', out)


def test_no_host_socket(net):
    """The real runner's guest socket has no host path: the run directory holds egress.sock and no other socket, and the
    runner process holds no named unix socket but egress.sock, while the guest still gets keys (through its own bridge)."""
    if not net['real']:
        pytest.skip('the stand-in runner serves a host unix socket by design')
    c, err, sock = net['boot']('A', 'C1')
    assert c, err
    _, r = demo_key(c, net)
    rd = net['real'].rd_of[str(sock)]
    seen = net['real'].host_sockets(rd)
    assert [Path(f).name for f in seen['socket_files']] == ['egress.sock'], seen
    named = [n for n in seen['runner_unix_sockets'] if '/' in n]
    assert seen['runner_pid'].isdigit() and named and all(n.endswith('/out/egress.sock') for n in named) and not any(n.endswith('dsmack.sock') for n in seen['runner_unix_sockets']), seen
    record('9-no-host-socket', {**seen, 'run_dir': rd, 'guest_public_key': r['public_key']})


def test_registry_window(net):
    """The node reads composes(app, compose) at a block: open window served, closed window refused, and the statement's
    earlier block still reads as allowed (the verifier's re-read)."""
    c, err, _ = net['boot']('B', 'C5')
    assert c, err
    _, r = demo_key(c, net)
    statement = b(r['chain'][0]['message'])
    issued = verify.statement_fields(statement)['block']
    h = '0x' + net['hashes']['C5']
    closed = int(run('cast', 'block-number', '--rpc-url', net['rpc'])) + 1   # the admit below lands at this block or later
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
        before[n] = demo_key(clients[n], net)
    old = before['A'][0]['key_epoch']
    net['bump']()
    rec = {'epoch_before': old}
    for n in 'AB':
        before_info, before_key = before[n]
        deadline = time.time() + 300
        while True:  # the node's epoch, through the runner booted before the bump
            try:
                if clients[n].info()['key_epoch'] == old + 1:
                    break
            except sdk.DsmackError as e:  # the node holds no group key until it re-acquires one for the new epoch
                assert 'no group key held' in str(e) and time.time() < deadline, e
            assert time.time() < deadline
            time.sleep(5)
        # A runner booted before the bump follows the node: get_key without epoch is the new epoch's key, not the boot's.
        _, followed = demo_key(clients[n], net)
        assert followed['key_epoch'] == old + 1 and followed['public_key'] != before_key['public_key'], followed
        while True:
            c, err, _ = net['boot'](n, 'C1')
            if c and c.info()['key_epoch'] == old + 1:
                break
            assert time.time() < deadline, err
            time.sleep(5)
        info, now = demo_key(c, net)
        _, prev = demo_key(c, net, old, before_info['group_public'])
        assert now['public_key'] != before_key['public_key'] and info['group_public'] != before_info['group_public']
        assert prev['public_key'] == before_key['public_key'] and prev['key_epoch'] == old
        with pytest.raises(sdk.DsmackError, match=f'key epoch {old + 2} not held'):
            c.get_key('demo', 'ed25519:demo', old + 2)
        assert followed['public_key'] == now['public_key']
        rec[n] = {'epoch_after': info['key_epoch'], 'runner_booted_before_bump_follows': followed['key_epoch'], 'public_key_before': before_key['public_key'], 'public_key_after': now['public_key'],
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


APP_ROOT_X2 = 'da78017f89ce06c6205664157e1e3fa384a4b1d8e62cfa8c33746e10556c7c6a'
APP_PUB_X2 = '047a0ed31182cc27b524756cee7c136ca159ad7d8d38cc6ca6f8ebc8b5454464925eeb9117c01f764b3ef4540483cb3956fb3071e4bbbd07c1cebc87e8279a98e7'
LEAF_X2 = 'a32bdf67bc68f143508912f0d807b6dd17c62c2c2a8560bd25ea11bcfaf404e5'
