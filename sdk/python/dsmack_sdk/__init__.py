"""dsmack-sdk client: derived keys and evidence for compose apps (stdlib only, synchronous).

Wire (planning: dsmack-sdk design §2): JSON lines, one reply per request, {"v":1,"op":...}; a refusal is
{"v":1,"error":...}. The guest asks its runner on /var/run/dsmack.sock (Client); the runner asks its node on
loopback TCP (node.NodeSession). Byte encodings match node/shared/SDK.swift, every integer and address an ABI word:
chain_id, key_epoch, block and until u256 BE (32), registry address left-padded to 32, scope, app_id, compose_hash
and M bytes32, app_pub P-256 uncompressed (65), lp(x) = u32 BE length ‖ x. Hex on the wire may carry 0x.
P-256 signatures are ECDSA over SHA-256 of the message, raw r‖s (64); allow records are Ed25519 (64).
"""
import hashlib, hmac, json, socket

SOCKET = '/var/run/dsmack.sock'
SDK = 'dsmack-sdk/v1'
TAGS = ('ed25519', 'secp256k1', 'p256', 'raw')
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
RUNNER_DOMAIN = 'dsmack-sdk-runner/1'


def b(h):
    return bytes.fromhex(h.removeprefix('0x'))


def b32(h):
    x = b(h)
    if len(x) != 32:
        raise ValueError('bytes32 width')
    return x


def word(n):
    return n.to_bytes(32, 'big')


def address_word(a):
    x = b(a)
    if len(x) != 20:
        raise ValueError('address width')
    return bytes(12) + x


def hkdf(ikm, salt, info, n=32):
    prk = hmac.new(salt or bytes(32), ikm, hashlib.sha256).digest()
    out, t, i = b'', b'', 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out, i = out + t, i + 1
    return out[:n]


def lp(x):
    return len(x).to_bytes(4, 'big') + x


def context(chain_id, registry, scope, key_epoch, app_id):
    return word(chain_id) + address_word(registry) + b32(scope) + word(key_epoch) + b32(app_id)


def app_root(group_scalar, chain_id, registry, scope, key_epoch, app_id):
    """In the node: G's scalar to the app root; nothing node-specific enters."""
    return hkdf(group_scalar, context(chain_id, registry, scope, key_epoch, app_id), b'dsmack-sdk/v1/app')


def app_signer(root):
    """Scalar of the per-app P-256 key app_pub: HKDF(app_root, "dsmack-sdk/v1/app-pub") mod n, refused if zero."""
    k = int.from_bytes(hkdf(root, b'', b'dsmack-sdk/v1/app-pub'), 'big') % P256_N
    if k == 0:
        raise ValueError('derived scalar is zero')
    return k


def split_purpose(purpose):
    tag, sep, _ = purpose.partition(':')
    if not sep or tag not in TAGS:
        raise ValueError(f'purpose must start with one of {", ".join(t + ":" for t in TAGS)}')
    return tag


def leaf(root, path, purpose):
    """In the runner: the app root to the key for (path, purpose)."""
    split_purpose(purpose)
    return hkdf(root, b'', b'dsmack-sdk/v1/key' + lp(path.encode()) + lp(purpose.encode()))


def app_statement(chain_id, registry, scope, key_epoch, app_id, compose_hash, block, m, app_pub):
    """Chain link 1, signed by G."""
    return b'dsmack-sdk/app/1' + context(chain_id, registry, scope, key_epoch, app_id) + b32(compose_hash) + word(block) + b32(m) + b(app_pub)


def key_statement(path, purpose, public_key):
    """Chain link 2, signed by app_pub."""
    return b'dsmack-sdk/key/1' + lp(path.encode()) + lp(purpose.encode()) + lp(b(public_key))


def evidence_statement(report_data):
    return b'dsmack-sdk/evidence/1' + report_data


def allow_message(chain_id, registry, app_id, compose_hash, scope, until):
    """Interim allow record, signed (Ed25519) by the sponsor key compiled into the node."""
    return b'dsmack-sdk/allow/1' + word(chain_id) + address_word(registry) + b32(app_id) + b32(compose_hash) + b32(scope) + word(until)


def canonical(obj):
    """Swift JSONSerialization [.sortedKeys, .withoutEscapingSlashes] for the node's request objects."""
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def runner_data(challenge, request):
    """What the runner's App Attest assertion covers for one node request (runner_evidence removed)."""
    return f'{RUNNER_DOMAIN}|0x{b(challenge).hex()}|0x{hashlib.sha256(canonical(request)).hexdigest()}'


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
