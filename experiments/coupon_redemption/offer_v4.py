"""Policy-bound first-bearer offers; quote acceptance is not issuance approval."""
import hashlib
import re

from .offer_v2 import canonical, POLICY
from .offer_v3 import validate_offer_v3, delivery_aad_v3
from .spike import RedemptionError

PROTOCOL_V4 = '/dsmack/coupon/4'
ISSUER_PROTOCOL = '/dsmack/coupon/issuer/2'
ISSUER_POLICY = 'dstack-tdx-coupon-v1'


def validate_issuer(value):
    fields = {'peer_id', 'policy', 'identity_policy_sha256', 'issuance_policy_sha256', 'issuer_public_key_sha256'}
    if (type(value) is not dict or set(value) != fields or value['policy'] != ISSUER_POLICY
            or type(value['peer_id']) is not str or not re.fullmatch(r'[A-Za-z0-9]{16,128}', value['peer_id'])
            or any(type(value[k]) is not str or not re.fullmatch(r'[0-9a-f]{64}', value[k])
                   for k in fields - {'peer_id', 'policy'})):
        raise RedemptionError('invalid v4 issuer binding')
    return value


def validate_offer_v4(value):
    if type(value) is not dict or type(value.get('version')) is not int or value['version'] != 4:
        raise RedemptionError('invalid v4 offer')
    issuer = validate_issuer(value.get('issuer'))
    reference = {**value, 'version': 3, 'issuer': {'peer_id': issuer['peer_id'], 'policy': POLICY}}
    validate_offer_v3(reference)
    return value


def offer_hash_v4(value):
    return hashlib.sha256(b'dsmack-coupon-offer-v4\0' + canonical(validate_offer_v4(value))).hexdigest()


def peer_hash(peer):
    if type(peer) is not str or not re.fullmatch(r'[A-Za-z0-9]{1,200}', peer):
        raise RedemptionError('invalid recipient peer identity')
    return hashlib.sha256(b'dsmack-coupon-recipient-peer-v4\0' + peer.encode('ascii')).hexdigest()


def recipient_subject(peer):
    return 'recipient-peer:' + peer_hash(peer)


def delivery_aad_v4(coupon_digest, key_id, recipient, accepted_offer_hash, peer):
    import json
    value = json.loads(delivery_aad_v3(coupon_digest, key_id, recipient, accepted_offer_hash, peer))
    value.update(domain='dsmack-coupon-delivery-v4', version=4, recipient_peer_sha256=peer_hash(peer))
    return canonical(value)
