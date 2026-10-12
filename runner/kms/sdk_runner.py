"""Stand-in for the runner's dsmack-sdk side (planning: dsmack-sdk design §1-2): boots one compose against a
node (sdk_node.py), gets the app root sealed to a fresh eph key, and serves the design's JSON-lines API on a
unix socket that a guest mounts as /var/run/dsmack.sock. The real runner is Swift and serves it over vsock;
this process is for tests on hosts without Virtualization.framework.

compose_hash = sha256(exact compose bytes); app_id is the compose's top-level "app_id". The boot request is
signed by --runner-key (a P-256 scalar, 64 hex), the stand-in for the runner's App Attest key. If the node
refuses, this exits non-zero before creating the socket: the guest gets nothing.

Ops: get_key {path, purpose} -> {key, public_key, chain}; evidence {report_data} -> bundle; info. `epoch`
other than the booted key_epoch is refused (slice 2). `sign` is not served (slice 2).
"""
import argparse, base64, hashlib, json, os, socketserver, sys, urllib.error, urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'sdk/python'))
import dsmack_sdk as sdk
from dsmack_sdk.verify import app_link, public_key, scalar
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

p = argparse.ArgumentParser()
p.add_argument('--compose', type=Path, required=True)
p.add_argument('--node', required=True, help='http://127.0.0.1:PORT')
p.add_argument('--runner-key', type=Path, required=True)
p.add_argument('--socket', type=Path, required=True)
args = p.parse_args()

pub = lambda k: k.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint).hex()


def sign(key, message):
    r, s = decode_dss_signature(key.sign(message, ec.ECDSA(hashes.SHA256())))
    return (r.to_bytes(32, 'big') + s.to_bytes(32, 'big')).hex()


compose_bytes = args.compose.read_bytes()
COMPOSE_HASH = hashlib.sha256(compose_bytes).hexdigest()
APP_ID = json.loads(compose_bytes)['app_id']
RUNNER = ec.derive_private_key(int(args.runner_key.read_text().strip(), 16), ec.SECP256R1())
RUNNER_PUB = pub(RUNNER)
eph = ec.generate_private_key(ec.SECP256R1())
nonce = json.loads(urllib.request.urlopen(args.node + '/nonce', timeout=10).read())['nonce']
client_data = json.dumps({'app_id': APP_ID, 'compose_hash': COMPOSE_HASH, 'eph_pub': pub(eph), 'nonce': nonce,
                          'domain': 'dsmack-sdk-boot/1'}, sort_keys=True, separators=(',', ':')).encode()
body = json.dumps({'client_data': base64.b64encode(client_data).decode(), 'runner_pub': RUNNER_PUB,
                   'signature': sign(RUNNER, client_data)}).encode()
try:
    res = json.loads(urllib.request.urlopen(urllib.request.Request(args.node + '/release', body, {'content-type': 'application/json'}), timeout=10).read())
except urllib.error.HTTPError as e:
    sys.exit(f'sdk-runner: boot release refused: {e.code} {e.read().decode()}')
shared = eph.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(res['epk'])))
sealed = base64.b64decode(res['sealed'])
parcel = json.loads(AESGCM(HKDF(hashes.SHA256(), 32, None, b'dsmack-sdk-release/1').derive(shared)).decrypt(
    sealed[:12], sealed[12:], hashlib.sha256(client_data).digest()))
ROOT, NODE, BLOCK = bytes.fromhex(parcel['app_root']), parcel['node'], parcel['block']
APP_KEY = ec.derive_private_key(scalar('p256', sdk.app_sign_seed(ROOT)), ec.SECP256R1())
APP_PUB = pub(APP_KEY)
STATEMENT = {'signer': NODE['group_public'], 'signature': parcel['statement_signature'],
             'message': sdk.app_statement(NODE['chain_id'], NODE['registry'], NODE['scope'], NODE['key_epoch'], APP_ID,
                                          COMPOSE_HASH, BLOCK, APP_PUB).hex()}
if app_link(STATEMENT, NODE['group_public']) != APP_PUB:
    sys.exit('sdk-runner: node statement does not name this app root')
INFO = {'app_id': APP_ID, 'compose_hash': COMPOSE_HASH, 'scope': NODE['scope'], 'key_epoch': NODE['key_epoch'],
        'chain_id': NODE['chain_id'], 'registry': NODE['registry'], 'app_registry': NODE['app_registry'], 'block': BLOCK,
        'group_public': NODE['group_public'], 'member': NODE['member'], 'm': NODE['m'],
        'cdhash': 'standin:' + hashlib.sha256(bytes.fromhex(RUNNER_PUB)).hexdigest(), 'sdk': sdk.SDK}


def get_key(req):
    if req.get('epoch', NODE['key_epoch']) != NODE['key_epoch']:
        raise ValueError('epoch_not_held')
    key = sdk.leaf(ROOT, req['path'], req['purpose'])
    pk = public_key(req['purpose'], key)
    if pk is None:
        return {'key': key.hex()}
    if sdk.split_purpose(req['purpose']) != 'ed25519':
        key = scalar(sdk.split_purpose(req['purpose']), key).to_bytes(32, 'big')
    link = sdk.key_statement(req['path'], req['purpose'], pk)
    return {'key': key.hex(), 'public_key': pk,
            'chain': [STATEMENT, {'signer': APP_PUB, 'message': link.hex(), 'signature': sign(APP_KEY, link)}]}


def evidence(req):
    data = bytes.fromhex(req['report_data'])
    if len(data) > 64:
        raise ValueError('report_data_too_long')
    assertion = json.dumps({'compose_hash': COMPOSE_HASH, 'data': data.hex(), 'domain': 'dsmack-sdk-assert/1'},
                           sort_keys=True, separators=(',', ':')).encode()
    return {'statement': STATEMENT,
            'report': {'signer': APP_PUB, 'message': sdk.evidence_statement(data).hex(), 'signature': sign(APP_KEY, sdk.evidence_statement(data))},
            'assertion': {'kind': 'standin-p256', 'runner_pub': RUNNER_PUB, 'client_data': base64.b64encode(assertion).decode(),
                          'signature': sign(RUNNER, assertion)},
            'node': {k: NODE[k] for k in ('member', 'checked_tx', 'key_epoch', 'm')}}


OPS = {'get_key': get_key, 'evidence': evidence, 'info': lambda req: INFO}


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        for line in self.rfile:
            try:
                req = json.loads(line)
                if req.get('v') != 1 or req.get('op') not in OPS:
                    raise ValueError('unknown_version_or_op')
                reply = {'v': 1, **OPS[req['op']](req)}
            except (ValueError, KeyError) as e:
                reply = {'v': 1, 'error': f'{type(e).__name__}: {e}'}
            self.wfile.write(json.dumps(reply).encode() + b'\n')


print(f'sdk-runner: app {APP_ID[:16]}... compose {COMPOSE_HASH[:16]}... block {BLOCK}; serving {args.socket}', file=sys.stderr, flush=True)
server = socketserver.ThreadingUnixStreamServer(str(args.socket), Handler)
os.chmod(args.socket, 0o666)
server.serve_forever()
