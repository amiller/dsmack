"""Synthetic accountless first-authenticated-bearer offer/delivery contract."""
import hashlib
import re

from .offer_v2 import canonical, validate_offer
from .spike import RedemptionError

PROTOCOL_V3 = '/dsmack/coupon/3'
OFFER_DOMAIN = b'dsmack-coupon-offer-v3\0'


def validate_offer_v3(value):
    if (not isinstance(value, dict) or 'recipient_subject' in value
            or type(value.get('version')) is not int or value['version'] != 3
            or value.get('claim_policy') != 'first-authenticated-bearer'):
        raise RedemptionError('invalid v3 offer')
    reference = dict(value)
    reference.pop('claim_policy')
    reference['version'] = 2
    reference['recipient_subject'] = 'recipient:unbound'
    validate_offer(reference)
    return value


def offer_hash_v3(value):
    return hashlib.sha256(OFFER_DOMAIN + canonical(validate_offer_v3(value))).hexdigest()


def peer_hash(peer):
    if not isinstance(peer, str) or not re.fullmatch(r'[A-Za-z0-9]{1,200}', peer):
        raise RedemptionError('invalid recipient peer identity')
    return hashlib.sha256(b'dsmack-coupon-recipient-peer-v3\0' + peer.encode('ascii')).hexdigest()


def recipient_subject(peer):
    return 'recipient-peer:' + peer_hash(peer)


def delivery_aad_v3(coupon_digest, key_id, recipient, accepted_offer_hash, peer):
    if not isinstance(key_id, str) or not re.fullmatch(r'[A-Za-z0-9:_./-]{1,200}', key_id):
        raise RedemptionError('invalid provider key identity')
    return canonical({'domain': 'dsmack-coupon-delivery-v3', 'version': 3,
                      'offer_hash': accepted_offer_hash, 'coupon_digest': coupon_digest,
                      'key_id': key_id, 'recipient_key_sha256': hashlib.sha256(recipient).hexdigest(),
                      'recipient_peer_sha256': peer_hash(peer)})
