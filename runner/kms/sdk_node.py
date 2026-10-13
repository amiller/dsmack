"""Stand-in Dsmack node for the dsmack-sdk port, for hosts without a signed Mac node: the wire and checks of
node/shared/SDK.swift SDKService (challenge, get_key, evidence, info; runner admission first, by App Attest evidence in
domain dsmack-sdk-runner/1 through verifier/core.py and the runner's measurement M_runner from its attested
CodeDirectory, refused with runner_not_admitted; then AppRegistry apps(app_id) and composes(app_id, compose_hash) read
at the current block, scope from the table; previous epoch kept). Test group keys (--group-key EPOCH=PATH, a P-256
scalar as 64 hex, mode 0600, never logged) replace the node's held G; the current epoch is keyEpochs(scope) on the
group-key registry (--registry, a DemoV2) at the read block, and the one before it is the held previous epoch. --anchor is the fixture's synthetic root, never Apple's. The block is the chain's.
"""
import argparse, base64, hashlib, json, os, socketserver, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'sdk/python'), str(ROOT), str(ROOT / 'scripts/release')]
from measure import app_identifier, measure
import dsmack_sdk as sdk
from dsmack_sdk import b, b32
from dsmack_sdk.node import pub
from dsmack_sdk.verify import Invalid, rpc
from verifier.core import Policy, Reject, verify_assertion, verify_attestation
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

p = argparse.ArgumentParser()
p.add_argument('--port', type=int, required=True)
p.add_argument('--group-key', action='append', required=True, help='EPOCH=PATH')
p.add_argument('--rpc', required=True)
p.add_argument('--registry', required=True, help='group-key registry (DemoV2) address in the derivation context')
p.add_argument('--app-registry', required=True, help='AppRegistry address the node reads and names in the derivation context')
p.add_argument('--chain-id', type=int, required=True)
p.add_argument('--scope', required=True, help='bytes32 hex this node holds G for')
p.add_argument('--anchor', required=True, help='App Attest root, base64 DER (a synthetic fixture root)')
p.add_argument('--runner', action='append', required=True, help='admitted runner measurement M_runner, hex')
p.add_argument('--member', required=True)
p.add_argument('--m', required=True, help='node measurement M, bytes32 hex')
p.add_argument('--checked-tx', required=True)
args = p.parse_args()

KEYS = {}
for spec in args.group_key:
    e, path = spec.split('=', 1)
    KEYS[int(e)] = ec.derive_private_key(int(Path(path).read_text().strip(), 16), ec.SECP256R1())
ROOT_PEM = b'-----BEGIN CERTIFICATE-----\n' + base64.encodebytes(base64.b64decode(args.anchor)) + b'-----END CERTIFICATE-----\n'
RUNNERS = {b32(m) for m in args.runner}
h = lambda x: '0x' + x.hex()


def require(ok, why):
    if not ok:
        raise ValueError(why)


def sign(key, message):
    r, s = decode_dss_signature(key.sign(message, ec.ECDSA(hashes.SHA256())))
    return h(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))


def allowed_scope(app_id, compose_hash):
    """Chain.appEntry and SDK.allowedScope: the app's scope if compose_hash has an open window at the current block."""
    bl = int(rpc(args.rpc, 'eth_blockNumber', []), 16)
    call = lambda data: b(rpc(args.rpc, 'eth_call', [{'to': args.app_registry, 'data': data}, hex(bl)]))
    app = call('0x38bb6def' + app_id.hex())                          # apps(bytes32)
    window = call('0x61ae7c43' + app_id.hex() + compose_hash.hex())  # composes(bytes32,bytes32)
    admin, scope, start, until = app[12:32], app[32:], int.from_bytes(window[:32], 'big'), int.from_bytes(window[32:], 'big')
    require(admin != bytes(20), f'app_id not in AppRegistry at block {bl}')
    require(until != 0, f'compose not allowed under app_id at block {bl}')
    require(start <= bl, f'compose window opens at block {start}, read at {bl}')
    require(bl < until, f'compose window closed at block {until}, read at {bl}')
    return scope, bl


def admit(q, compose_hash, session):
    e = q.get('runner_evidence')
    require(e is not None, 'runner evidence required')
    issued, session['challenge'] = session['challenge'], None
    require(issued is not None, 'runner evidence needs a challenge on this connection')
    require(time.time() <= issued[1] + 60, 'challenge expired')
    request = {k: v for k, v in q.items() if k != 'runner_evidence'}
    try:
        boot, asserted = base64.b64decode(e['bootClientData']), base64.b64decode(e['assertClientData'])
        code = {k: base64.b64decode(v) if k in ('cd', 'page0', 'ent') else v for k, v in e['code'].items()}
        require(set(code) == {'cd', 'page0', 'ent', 'L', 'S'}, 'code measurement fields')
        cdhash = hashlib.sha256(code['cd']).digest()
        policy = Policy(app_identifier(code['ent']), environment='production', categories=(3,), cdhashes=(cdhash,), require_macos_acl=True)
        try:
            enrolled = verify_attestation(base64.b64decode(e['attestation']), e['keyId'], boot, policy, ROOT_PEM)
        except Reject as r:
            require(str(r) != 'cdhash_policy_failed', 'runner CodeDirectory is not the attested CDHash')
            raise
        runner_m = measure(**code)
        require(runner_m in RUNNERS, f'runner measurement 0x{runner_m.hex()} not admitted')
        bd = json.loads(boot)
        require(bd['domain'] in ('mac-compose-boot/1', 'mac-compose-enroll/1') and bd['attested'] is True and bd['compose_hash'] == compose_hash.hex()
                and -60 <= time.time() - bd['enrolled_at'] <= 12 * 3600, 'runner enrollment is not this compose or is stale')
        verify_assertion(base64.b64decode(e['assertion']), asserted, enrolled['public_key'], 0, policy)
        body = json.loads(asserted)
        require(set(body) == {'compose_hash', 'data', 'domain'} and body['domain'] == sdk.RUNNER_DOMAIN and body['compose_hash'] == compose_hash.hex()
                and body['data'] == sdk.runner_data(issued[0], request), 'runner assertion is not over this challenge and request')
    except Reject as r:
        raise ValueError(f'runner evidence: {r}')
    session['compose'] = compose_hash


def release(app_id, compose_hash, epoch):
    scope, bl = allowed_scope(b32(app_id), b32(compose_hash))
    require(scope == b32(args.scope), f'no group key held for scope {h(scope)}')
    current = int(rpc(args.rpc, 'eth_call', [{'to': args.registry, 'data': '0xd71779d9' + b32(args.scope).hex()}, hex(bl)]), 16)  # keyEpochs
    require(epoch is not None or current in KEYS, f'no group key held for scope 0x{args.scope}')
    e = current if epoch is None else epoch
    require(e in KEYS and e in (current, current - 1), f'key epoch {e} not held for scope 0x{args.scope}')
    g = KEYS[e]
    root = sdk.app_root(g.private_numbers().private_value.to_bytes(32, 'big'), args.chain_id, args.registry, args.app_registry, args.scope, e, app_id)
    signer = ec.derive_private_key(sdk.app_signer(root), ec.SECP256R1())
    statement = sdk.app_statement(args.chain_id, args.registry, args.app_registry, args.scope, e, app_id, compose_hash, bl, args.m, pub(signer))
    return root, signer, statement, {'app_id': h(b32(app_id)), 'compose_hash': h(b32(compose_hash)), 'scope': h(b32(args.scope)), 'key_epoch': e,
                                     'chain_id': args.chain_id, 'registry': args.registry, 'app_registry': args.app_registry, 'block': bl, 'M': h(b32(args.m)), 'app_pub': '0x' + pub(signer),
                                     'statement': h(statement), 'group_signature': sign(g, statement), 'group_public': '0x' + pub(g)}


def handle(q, session):
    require(q.get('v') == 1, 'unsupported v')
    if q.get('op') == 'challenge':
        c = os.urandom(32)
        session['challenge'] = (c.hex(), time.time())
        return {'challenge': h(c)}
    require(all(k in q for k in ('op', 'app_id', 'compose_hash')), 'request needs op, app_id and compose_hash')
    require(q['op'] in ('get_key', 'evidence', 'info'), 'unknown op')
    compose_hash = b32(q['compose_hash'])
    if session['compose'] is None:
        try:
            admit(q, compose_hash, session)
        except (ValueError, KeyError) as e:
            raise ValueError(f'runner_not_admitted: {e}')
    require(session['compose'] == compose_hash, 'connection admitted for another compose')
    root, signer, statement, fields = release(q['app_id'], q['compose_hash'], q.get('epoch'))
    if q['op'] == 'get_key':
        eph = ec.generate_private_key(ec.SECP256R1())
        shared = eph.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b(q['eph_pub'])))
        nonce = os.urandom(12)
        sealed = AESGCM(HKDF(hashes.SHA256(), 32, None, b'dsmack-sdk/v1/release').derive(shared)).encrypt(nonce, root, hashlib.sha256(statement).digest())
        return {**fields, 'epk': '0x' + pub(eph), 'sealed': h(nonce + sealed)}
    if q['op'] == 'evidence':
        data = b(q['report_data'])
        require(len(data) <= 64, 'report_data is at most 64 bytes')
        return {**fields, 'report_data': h(data), 'app_signature': sign(signer, sdk.evidence_statement(data)),
                'member': args.member, 'checked_tx': args.checked_tx}
    return {**fields, 'member': args.member, 'sdk': sdk.SDK}


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        session = {'challenge': None, 'compose': None}
        for line in self.rfile:
            try:
                reply = handle(json.loads(line), session)
            except (ValueError, KeyError, Invalid) as e:
                reply = {'error': str(e)}
            self.wfile.write(json.dumps({**reply, 'v': 1}, sort_keys=True).encode() + b'\n')


print(f'sdk-node: scope {args.scope[:10]}... group keys for epochs {sorted(KEYS)}; listening 127.0.0.1:{args.port}', file=sys.stderr, flush=True)
socketserver.ThreadingTCPServer.allow_reuse_address = True
socketserver.ThreadingTCPServer(('127.0.0.1', args.port), Handler).serve_forever()
