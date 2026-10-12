"""dsmack-sdk client: derived keys and evidence for compose apps (stdlib only, synchronous).

Wire (planning: dsmack-sdk design §2): JSON lines on /var/run/dsmack.sock, one reply per request,
{"v":1,"op":...}; a refusal is {"v":1,"error":...}. Byte encodings frozen here, all hex on the wire:
chain_id u256 BE (32), registry address (20), scope bytes32, key_epoch u64 BE (8), app_id bytes32,
compose_hash bytes32, block u64 BE (8), app_pub P-256 uncompressed (65), len = u32 BE.
Signatures are P-256 ECDSA over SHA-256, raw r‖s (64).
"""
import hashlib, hmac, json, socket

SOCKET = '/var/run/dsmack.sock'
SDK = 'dsmack-sdk/1'
TAGS = ('ed25519', 'secp256k1', 'p256', 'raw')


def hkdf(ikm, salt, info, n=32):
    prk = hmac.new(salt or bytes(32), ikm, hashlib.sha256).digest()
    out, t, i = b'', b'', 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out, i = out + t, i + 1
    return out[:n]


def lp(b):
    return len(b).to_bytes(4, 'big') + b


def context(chain_id, registry, scope, key_epoch, app_id):
    return chain_id.to_bytes(32, 'big') + bytes.fromhex(registry.removeprefix('0x')) + bytes.fromhex(scope) \
        + key_epoch.to_bytes(8, 'big') + bytes.fromhex(app_id)


def app_root(group_scalar, chain_id, registry, scope, key_epoch, app_id):
    """In the node: G's scalar to the app root; nothing node-specific enters."""
    return hkdf(group_scalar, context(chain_id, registry, scope, key_epoch, app_id), b'dsmack-sdk/v1/app')


def split_purpose(purpose):
    tag, sep, _ = purpose.partition(':')
    if not sep or tag not in TAGS:
        raise ValueError(f'purpose must start with one of {", ".join(t + ":" for t in TAGS)}')
    return tag


def leaf(root, path, purpose):
    """In the runner: the app root to the key for (path, purpose)."""
    split_purpose(purpose)
    return hkdf(root, b'', b'dsmack-sdk/v1/key' + lp(path.encode()) + lp(purpose.encode()))


def app_sign_seed(root):
    """Seed of the per-app P-256 key app_pub (reduced mod n by the holder)."""
    return hkdf(root, b'', b'dsmack-sdk/v1/app-sign')


def app_statement(chain_id, registry, scope, key_epoch, app_id, compose_hash, block, app_pub):
    """Chain link 1, signed by G."""
    return b'dsmack-sdk/app/1' + context(chain_id, registry, scope, key_epoch, app_id) \
        + bytes.fromhex(compose_hash) + block.to_bytes(8, 'big') + bytes.fromhex(app_pub)


def key_statement(path, purpose, public_key):
    """Chain link 2, signed by app_pub."""
    return b'dsmack-sdk/key/1' + lp(path.encode()) + lp(purpose.encode()) + lp(bytes.fromhex(public_key))


def evidence_statement(report_data):
    return b'dsmack-sdk/evidence/1' + report_data


class DsmackError(Exception):
    pass


class Client:
    def __init__(self, path=SOCKET):
        self.path = path

    def call(self, op, **args):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(self.path)
            s.sendall(json.dumps({'v': 1, 'op': op, **args}).encode() + b'\n')
            reply = json.loads(s.makefile('rb').readline())
        if 'error' in reply:
            raise DsmackError(reply['error'])
        return reply

    def get_key(self, path, purpose, epoch=None):
        return self.call('get_key', path=path, purpose=purpose, **({} if epoch is None else {'epoch': epoch}))

    def evidence(self, report_data):
        if len(report_data) > 64:
            raise ValueError('report_data is at most 64 bytes')
        return self.call('evidence', report_data=report_data.hex())

    def info(self):
        return self.call('info')
