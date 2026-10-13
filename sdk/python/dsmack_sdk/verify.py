"""Verifies get_key replies and evidence bundles offline against G (needs `cryptography`), and (group_on_chain) that
G is the registry's committed sharedKeys(scope) for the statement's key epoch. That compose_hash is allowed under app_id
at block is the verifier's own AppRegistry read."""
import json, time, urllib.request
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from . import b, evidence_statement, key_statement, split_purpose


class Invalid(Exception):
    pass


def require(ok, why):
    if not ok:
        raise Invalid(why)


CURVES = {'secp256k1': ec.SECP256K1(), 'p256': ec.SECP256R1()}
ORDERS = {'secp256k1': 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
          'p256': 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551}


def p256_verify(pub_hex, message, sig_hex):
    sig = b(sig_hex)
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b(pub_hex))
    pub.verify(encode_dss_signature(int.from_bytes(sig[:32], 'big'), int.from_bytes(sig[32:], 'big')), message, ec.ECDSA(hashes.SHA256()))


def scalar(tag, key):
    k = int.from_bytes(key, 'big') % ORDERS[tag]
    if k == 0:
        raise ValueError('derived scalar is zero')
    return k


def public_key(purpose, key):
    tag = split_purpose(purpose)
    if tag == 'raw':
        return None
    if tag == 'ed25519':
        return ed25519.Ed25519PrivateKey.from_private_bytes(key).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    return ec.derive_private_key(scalar(tag, key), CURVES[tag]).public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint).hex()


def app_link(link, group_public):
    """Checks link 1 is G's; returns app_pub (last 65 bytes of the statement)."""
    require(b(link['signer']) == b(group_public), 'link 1 is not signed by the group key')
    message = b(link['message'])
    require(message.startswith(b'dsmack-sdk/app/1'), 'link 1 domain')
    p256_verify(group_public, message, link['signature'])
    return message[-65:].hex()


def key_reply(reply, path, purpose, group_public):
    """A get_key reply: public key matches key, both links verify. Returns the app statement."""
    require(reply['public_key'] == public_key(purpose, b(reply['key'])), 'public_key does not match key')
    app_link_, key_link = reply['chain']
    app_pub = app_link(app_link_, group_public)
    require(b(key_link['signer']) == b(app_pub), 'link 2 is not signed by app_pub')
    require(b(key_link['message']) == key_statement(path, purpose, reply['public_key']), 'link 2 message')
    p256_verify(app_pub, b(key_link['message']), key_link['signature'])
    return b(app_link_['message'])


def statement_fields(m):
    """Link 1's message: "dsmack-sdk/app/1" ‖ chain_id ‖ registry ‖ app_registry ‖ scope ‖ key_epoch ‖ app_id ‖
    compose_hash ‖ block ‖ M (32-byte words) ‖ app_pub (65)."""
    require(len(m) == 16 + 9 * 32 + 65 and m.startswith(b'dsmack-sdk/app/1'), 'statement layout')
    w = [m[16 + 32 * i:48 + 32 * i] for i in range(9)]
    n = lambda x: int.from_bytes(x, 'big')
    return {'chain_id': n(w[0]), 'registry': '0x' + w[1][12:].hex(), 'app_registry': '0x' + w[2][12:].hex(), 'scope': w[3].hex(),
            'key_epoch': n(w[4]), 'app_id': w[5].hex(), 'compose_hash': w[6].hex(), 'block': n(w[7]), 'M': w[8].hex(), 'app_pub': m[-65:].hex()}


def evidence(bundle, report_data, group_public):
    app_pub = app_link(bundle['statement'], group_public)
    require(b(bundle['report']['signer']) == b(app_pub) and b(bundle['report']['message']) == evidence_statement(report_data), 'report link')
    p256_verify(app_pub, evidence_statement(report_data), bundle['report']['signature'])
    return b(bundle['statement']['message'])


KEY_EPOCHS, SHARED_KEYS = '0xd71779d9', '0xd5b7abaf'   # keyEpochs(bytes32), sharedKeys(bytes32) selectors


def rpc(url, method, params):
    time.sleep(0.05)   # at most 20 calls a second: sepolia.base.org refuses more than 25 (code -32007)
    req = urllib.request.Request(url, json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode(),
                                 {'content-type': 'application/json', 'user-agent': 'dsmack-sdk'})  # sepolia.base.org refuses urllib's
    r = json.loads(urllib.request.urlopen(req, timeout=30).read())
    require('error' not in r, f'RPC error {r.get("error")}')
    return r['result']


def key_epoch_at(url, registry, scope, at):
    r = b(rpc(url, 'eth_call', [{'to': registry, 'data': KEY_EPOCHS + b(scope).hex()}, at if at == 'latest' else hex(at)]))
    return int.from_bytes(r, 'big') if r else 0   # empty: no registry code yet at that block, so no epoch started


def epoch_end(url, registry, scope, key_epoch, block):
    """The last block of key_epoch, which had ended by `block`: galloping back and bisecting keyEpochs(scope) over block
    numbers (eth_call at past blocks; no log ranges, which public RPCs cap at a few hundred blocks)."""
    epoch = lambda at: key_epoch_at(url, registry, scope, at)
    require(epoch(block) > key_epoch, f'key epoch {key_epoch} had not ended at block {block}')
    hi, step, lo = block, 1, block - 1      # epoch(hi) > key_epoch throughout
    while lo > 0 and epoch(lo) > key_epoch:
        hi, step = lo, step * 2
        lo = max(hi - step, 0)
    while hi - lo > 1:
        mid = (lo + hi) // 2
        lo, hi = (lo, mid) if epoch(mid) > key_epoch else (mid, hi)
    return lo


def group_on_chain(url, registry, scope, key_epoch, group_public, block, previous=False):
    """G (group_public) is the registry's committed sharedKeys(scope) for key_epoch, and key_epoch is the registry's
    current epoch now, or, with previous=True (an explicit get_key(epoch=prev) during the rotation), the one directly
    before it. G is read at `block` if key_epoch was current there, else at key_epoch's last block (epoch_end).
    Returns the block G was read at."""
    now = key_epoch_at(url, registry, scope, 'latest')
    require(key_epoch == now or (previous and key_epoch == now - 1),
            f'key epoch {key_epoch} is not the current key epoch {now}' + (' or the one before it' if previous else ''))
    at = block if key_epoch_at(url, registry, scope, block) == key_epoch else epoch_end(url, registry, scope, key_epoch, block)
    k = b(rpc(url, 'eth_call', [{'to': registry, 'data': SHARED_KEYS + b(scope).hex()}, hex(at)]))
    require(key_epoch_at(url, registry, scope, at) == key_epoch and len(k) == 128 and k[127] == 1 and b'\x04' + k[:64] == b(group_public),
            f'group key is not sharedKeys(scope) for key epoch {key_epoch} at block {at}')
    return at


__all__ = ['group_on_chain', 'epoch_end', 'key_epoch_at', 'statement_fields', 'key_reply', 'evidence', 'public_key', 'p256_verify', 'InvalidSignature', 'Invalid']
