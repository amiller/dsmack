"""Verifies get_key replies and evidence bundles offline against G (needs `cryptography`).
The on-chain half (G is sharedKeys(scope) or the epoch's Bootstrapped key; compose_hash is
isAllowed under app_id at block) is the verifier's own chain read; this checks the signatures."""
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from . import evidence_statement, key_statement, split_purpose

class Invalid(Exception):
    pass


def require(ok, why):
    if not ok:
        raise Invalid(why)


CURVES = {'secp256k1': ec.SECP256K1(), 'p256': ec.SECP256R1()}
ORDERS = {'secp256k1': 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
          'p256': 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551}


def p256_verify(pub_hex, message, sig_hex):
    sig = bytes.fromhex(sig_hex)
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(pub_hex))
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
    require(link['signer'] == group_public, 'link 1 is not signed by the group key')
    message = bytes.fromhex(link['message'])
    require(message.startswith(b'dsmack-sdk/app/1'), 'link 1 domain')
    p256_verify(group_public, message, link['signature'])
    return message[-65:].hex()


def key_reply(reply, path, purpose, group_public):
    """A get_key reply: public key matches key, both links verify. Returns the app statement."""
    require(reply['public_key'] == public_key(purpose, bytes.fromhex(reply['key'])), 'public_key does not match key')
    app_link_, key_link = reply['chain']
    app_pub = app_link(app_link_, group_public)
    require(key_link['signer'] == app_pub, 'link 2 is not signed by app_pub')
    require(bytes.fromhex(key_link['message']) == key_statement(path, purpose, reply['public_key']), 'link 2 message')
    p256_verify(app_pub, bytes.fromhex(key_link['message']), key_link['signature'])
    return bytes.fromhex(app_link_['message'])


def evidence(bundle, report_data, group_public):
    app_pub = app_link(bundle['statement'], group_public)
    require(bundle['report']['signer'] == app_pub and bytes.fromhex(bundle['report']['message']) == evidence_statement(report_data), 'report link')
    p256_verify(app_pub, evidence_statement(report_data), bundle['report']['signature'])
    return bytes.fromhex(bundle['statement']['message'])


__all__ = ['key_reply', 'evidence', 'public_key', 'p256_verify', 'InvalidSignature', 'Invalid']
