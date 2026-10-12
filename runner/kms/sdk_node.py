"""Stand-in Dsmack node for the dsmack-sdk boot release (planning: dsmack-sdk design §1, §3), derived from
kms.py: a test group key G (--group-key, a P-256 scalar as 64 hex, mode 0600, never logged) replaces
master.key, and the allow list is AppRegistry on chain instead of --allow.

GET /nonce, then POST /release {client_data, runner_pub, signature}: client_data is the JSON
{app_id, compose_hash, eph_pub, nonce, domain:"dsmack-sdk-boot/1"} signed (P-256, raw r‖s) by the runner's
stand-in App Attest key runner_pub, which must be on --admit-runner (stand-in for CDHash admission). At the
latest block B the node reads AppRegistry.apps(app_id) (must exist, scope must be --scope) and
isAllowed(app_id, compose_hash, B); then app_root = HKDF(G, salt context, "dsmack-sdk/v1/app"), app_pub from
app_root, and G signs the app statement. The parcel {app_root, block, statement_signature, node} is sealed to
eph_pub as kms.py seals (ECDH P-256 with a one-time epk, HKDF-SHA256 info "dsmack-sdk-release/1",
AES-256-GCM nonce ‖ ct ‖ tag, AAD sha256(client_data)). Refusals are 403 {error}; nothing is released.
"""
import argparse, base64, hashlib, json, os, secrets, sys, time, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'sdk/python'))
import dsmack_sdk as sdk
from dsmack_sdk.verify import InvalidSignature, p256_verify, scalar
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

p = argparse.ArgumentParser()
p.add_argument('--port', type=int, required=True)
p.add_argument('--group-key', type=Path, required=True)
p.add_argument('--rpc', required=True)
p.add_argument('--app-registry', required=True)
p.add_argument('--registry', required=True, help='group-key registry (DemoV2) address in the derivation context')
p.add_argument('--chain-id', type=int, required=True)
p.add_argument('--scope', required=True, help='bytes32 hex this node holds G for')
p.add_argument('--key-epoch', type=int, required=True)
p.add_argument('--admit-runner', action='append', required=True, help='runner stand-in attest public key hex')
p.add_argument('--member', required=True)
p.add_argument('--m', required=True, help='node measurement M')
p.add_argument('--checked-tx', required=True)
args = p.parse_args()

G = bytes.fromhex(args.group_key.read_text().strip())
G_KEY = ec.derive_private_key(int.from_bytes(G, 'big'), ec.SECP256R1())
pub = lambda k: k.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint).hex()
GROUP_PUBLIC = pub(G_KEY)
NONCES = {}


def require(ok, why):
    if not ok:
        raise PermissionError(why)


def sign(key, message):
    r, s = decode_dss_signature(key.sign(message, ec.ECDSA(hashes.SHA256())))
    return (r.to_bytes(32, 'big') + s.to_bytes(32, 'big')).hex()


def rpc(method, params):
    req = urllib.request.Request(args.rpc, json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode(),
                                 {'content-type': 'application/json'})
    reply = json.loads(urllib.request.urlopen(req, timeout=10).read())
    if 'error' in reply:
        raise RuntimeError(reply['error'])
    return reply['result']


def call(data, block):
    return bytes.fromhex(rpc('eth_call', [{'to': args.app_registry, 'data': data}, hex(block)])[2:])


def release(req):
    client_data = base64.b64decode(req['client_data'])
    client = json.loads(client_data)
    require(req['runner_pub'] in args.admit_runner, 'runner_not_admitted')
    p256_verify(req['runner_pub'], client_data, req['signature'])
    require(client['domain'] == 'dsmack-sdk-boot/1', 'wrong_client_data_domain')
    issued = NONCES.pop(client['nonce'], None)
    require(issued is not None and time.time() - issued < 60, 'unknown_or_stale_nonce')
    app_id, compose_hash = client['app_id'], client['compose_hash']
    block = int(rpc('eth_blockNumber', []), 16)
    app = call('0x38bb6def' + app_id, block)                                     # apps(bytes32)
    require(int.from_bytes(app[:32], 'big') != 0, 'unknown_app')
    require(app[32:64].hex() == args.scope, 'scope_not_held')
    allowed = call('0x41c89acf' + app_id + compose_hash + block.to_bytes(32, 'big').hex(), block)  # isAllowed
    require(int.from_bytes(allowed, 'big') == 1, 'compose_not_allowed')
    root = sdk.app_root(G, args.chain_id, args.registry, args.scope, args.key_epoch, app_id)
    app_pub = pub(ec.derive_private_key(scalar('p256', sdk.app_sign_seed(root)), ec.SECP256R1()))
    statement = sdk.app_statement(args.chain_id, args.registry, args.scope, args.key_epoch, app_id, compose_hash, block, app_pub)
    print(f'sdk-node: released app {app_id[:16]}... compose {compose_hash[:16]}... at block {block}', file=sys.stderr)
    parcel = {'app_root': root.hex(), 'block': block, 'statement_signature': sign(G_KEY, statement),
              'node': {'chain_id': args.chain_id, 'registry': args.registry, 'app_registry': args.app_registry,
                       'scope': args.scope, 'key_epoch': args.key_epoch, 'group_public': GROUP_PUBLIC,
                       'member': args.member, 'm': args.m, 'checked_tx': args.checked_tx}}
    node_key = ec.generate_private_key(ec.SECP256R1())
    shared = node_key.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(client['eph_pub'])))
    aead = HKDF(hashes.SHA256(), 32, None, b'dsmack-sdk-release/1').derive(shared)
    nonce = os.urandom(12)
    return {'epk': pub(node_key),
            'sealed': base64.b64encode(nonce + AESGCM(aead).encrypt(nonce, json.dumps(parcel).encode(), hashlib.sha256(client_data).digest())).decode()}


class H(BaseHTTPRequestHandler):
    def reply(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header('content-type', 'application/json')
        self.send_header('content-length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        require(self.path == '/nonce', 'not_found')
        nonce = secrets.token_hex(32)
        NONCES[nonce] = time.time()
        self.reply(200, {'nonce': nonce})

    def do_POST(self):
        require(self.path == '/release', 'not_found')
        req = json.loads(self.rfile.read(int(self.headers['content-length'])))
        try:
            self.reply(200, release(req))
        except (PermissionError, InvalidSignature) as e:
            print(f'sdk-node: refused: {e!r}', file=sys.stderr)
            self.reply(403, {'error': str(e) or 'bad_runner_signature'})


print(f'sdk-node: group_public {GROUP_PUBLIC[:18]}... scope {args.scope[:8]}... epoch {args.key_epoch}', file=sys.stderr)
ThreadingHTTPServer(('127.0.0.1', args.port), H).serve_forever()
