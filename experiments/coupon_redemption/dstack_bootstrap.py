"""Protected launcher-pipe bootstrap; no provider credential or approval read.

Node consumes the seed on an anonymous pipe and prints public metadata only.
Do not attach this module's stdout to a public log or operator terminal.
"""
import hashlib
import json

from eth_keys import keys
from .dstack_issuer_identity import DstackIssuerIdentity
from .live_worker import NOISE_KEY_PATH, GUARD_KEY_PATH


def bootstrap():
    collector = DstackIssuerIdentity.from_socket('/var/run/dstack.sock')
    client = collector._client
    info = client.info()
    seed = client.get_key(NOISE_KEY_PATH, purpose='coupon encrypted peer identity', algorithm='ed25519').decode_key()
    guard = client.get_key(GUARD_KEY_PATH, purpose='coupon irreversible issuance attempt', algorithm='secp256k1').decode_key()
    if type(seed) is not bytes or len(seed) != 32:
        raise ValueError('invalid SDK identity')
    public = collector.public_key_hex()
    return {'noise_seed_hex': seed.hex(), 'issuer_public_key_hex': public,
        'issuer_public_key_sha256': hashlib.sha256(bytes.fromhex(public)).hexdigest(),
        'guard_issuer_address': '0x' + keys.PrivateKey(guard).public_key.to_canonical_address().hex(),
        'app_id': info.app_id, 'compose_hash': info.compose_hash,
        'app_compose': info.tcb_info.app_compose, 'guest_version': client.version().version}


if __name__ == '__main__':
    try:
        print(json.dumps(bootstrap()), flush=True)
    except Exception:
        raise SystemExit('SDK bootstrap unavailable') from None
