"""Stand-in for the runner's dsmack-sdk side (planning: dsmack-sdk design §1-2), for local development and tests on
hosts without Virtualization.framework: boots one compose against a node's sdkPort (the Swift node or sdk_node.py),
holding one admitted connection, and serves the design's JSON-lines API on a unix socket that a guest mounts as
/var/run/dsmack.sock. The real runner is Swift and serves it over vsock.

compose_hash = sha256(exact compose bytes); app_id is the compose's top-level "app_id". Runner evidence is test-only
synthetic App Attest (--fixture, --enrollment; runner/kms/synthetic_attest.py); --no-evidence sends none. Every release
is checked on chain (--rpc, --registry: the group-key registry, --app-registry): G must be the committed sharedKeys(scope)
of the registry's current key epoch (or the previous one, asked for explicitly). If the node refuses or the check fails, this exits non-zero before creating the socket: the
guest gets nothing. get_key without epoch asks the node each time, so it follows the node's current epoch.

Ops: get_key {path, purpose, epoch?} -> {key, public_key, chain}; evidence {report_data} -> bundle; info.
`sign` is not served (slice 2).
"""
import argparse, hashlib, json, os, socketserver, sys, threading
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parents[1] / 'sdk/python'), str(HERE)]
import dsmack_sdk as sdk
from dsmack_sdk import b
from dsmack_sdk.node import NodeSession, pub
from dsmack_sdk.verify import Invalid, group_on_chain, public_key, require, rpc, scalar
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from synthetic_attest import SyntheticRunner

p = argparse.ArgumentParser()
p.add_argument('--compose', type=Path, required=True)
p.add_argument('--node', required=True, help='127.0.0.1:PORT')
p.add_argument('--rpc', required=True)
p.add_argument('--registry', required=True)
p.add_argument('--app-registry', required=True)
p.add_argument('--fixture', type=Path, required=True)
p.add_argument('--enrollment', default='good')
p.add_argument('--code', help="send this fixture code entry instead of the enrollment's (a CodeDirectory that is not the attested one)")
p.add_argument('--no-evidence', action='store_true')
p.add_argument('--admission-domain', default=sdk.RUNNER_DOMAIN, help="test only: sign admission in another domain (runner.local/attest's mac-compose-assert/1)")
p.add_argument('--socket', type=Path, required=True)
args = p.parse_args()


def sign(key, message):
    r, s = decode_dss_signature(key.sign(message, ec.ECDSA(hashes.SHA256())))
    return (r.to_bytes(32, 'big') + s.to_bytes(32, 'big')).hex()


compose_bytes = args.compose.read_bytes()
COMPOSE_HASH = hashlib.sha256(compose_bytes).hexdigest()
APP_ID = json.loads(compose_bytes)['app_id']
RUNNER = SyntheticRunner(args.fixture, args.enrollment, args.code)
node = NodeSession(args.node, APP_ID, COMPOSE_HASH, None if args.no_evidence else lambda data: RUNNER.attest(data, args.admission_domain))
lock = threading.Lock()
ROOTS = {}


def boot(epoch=None):
    with lock:
        root, r = node.release(epoch)
    require(r['registry'].lower() == args.registry.lower() and r['app_registry'].lower() == args.app_registry.lower()
            and r['chain_id'] == int(rpc(args.rpc, 'eth_chainId', []), 16), 'release names another chain, registry or AppRegistry')
    group_on_chain(args.rpc, args.registry, r['scope'], r['key_epoch'], r['group_public'], r['block'], previous=epoch is not None)
    signer = ec.derive_private_key(sdk.app_signer(root), ec.SECP256R1())
    ROOTS[r['key_epoch']] = (root, signer, {'signer': r['group_public'], 'message': r['statement'], 'signature': r['group_signature']})
    return r['key_epoch']


try:
    EPOCH = boot()
except Exception as e:
    sys.exit(f'sdk-runner: boot release refused: {e}')


def get_key(req):
    e = req.get('epoch')
    if e is None or e not in ROOTS:
        e = boot(e)
    root, signer, statement = ROOTS[e]
    key = sdk.leaf(root, req['path'], req['purpose'])
    pk = public_key(req['purpose'], key)
    if pk is None:
        return {'key': key.hex()}
    if sdk.split_purpose(req['purpose']) != 'ed25519':
        key = scalar(sdk.split_purpose(req['purpose']), key).to_bytes(32, 'big')
    link = sdk.key_statement(req['path'], req['purpose'], pk)
    return {'key': key.hex(), 'public_key': pk, 'key_epoch': e,
            'chain': [statement, {'signer': pub(signer), 'message': link.hex(), 'signature': sign(signer, link)}]}


def evidence(req):
    data = b(req['report_data'])
    if len(data) > 64:
        raise ValueError('report_data is at most 64 bytes')
    with lock:
        r = node.request('evidence', report_data=data.hex())
    return {'statement': {'signer': r['group_public'], 'message': r['statement'], 'signature': r['group_signature']},
            'report': {'signer': r['app_pub'], 'message': sdk.evidence_statement(data).hex(), 'signature': r['app_signature']},
            'assertion': RUNNER.attest(data.hex(), 'dsmack-sdk-assert/1'),
            'node': {k: r[k] for k in ('member', 'checked_tx', 'key_epoch', 'M', 'block')}}


def info(req):
    with lock:
        r = node.request('info')
    return {**{k: r[k] for k in ('app_id', 'compose_hash', 'scope', 'key_epoch', 'chain_id', 'registry', 'app_registry', 'block', 'group_public', 'member', 'M')},
            'cdhash': RUNNER.cdhash, 'sdk': r['sdk']}


OPS = {'get_key': get_key, 'evidence': evidence, 'info': info}


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        for line in self.rfile:
            try:
                req = json.loads(line)
                if req.get('v') != 1 or req.get('op') not in OPS:
                    raise ValueError('unknown_version_or_op')
                reply = {'v': 1, **OPS[req['op']](req)}
            except (ValueError, KeyError, sdk.DsmackError, Invalid) as e:
                reply = {'v': 1, 'error': f'{type(e).__name__}: {e}'}
            self.wfile.write(json.dumps(reply).encode() + b'\n')


print(f'sdk-runner: app {APP_ID[:16]}... compose {COMPOSE_HASH[:16]}... epoch {EPOCH}; serving {args.socket}', file=sys.stderr, flush=True)
server = socketserver.ThreadingUnixStreamServer(str(args.socket), Handler)
os.chmod(args.socket, 0o666)
server.serve_forever()
