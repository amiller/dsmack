"""Exact ASCII offer contract for the experimental pre-bound session-only v2."""
import hashlib
import json
import re
from datetime import datetime, timezone

from .spike import RedemptionError

PROTOCOL_V2 = '/dsmack/coupon/2'
POLICY = 'experimental-local-unattested'
OFFER_DOMAIN = b'dsmack-coupon-offer-v2\0'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def expiry(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z', value):
        raise RedemptionError('canonical UTC expiry required')
    return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)


def amount(value):
    if (not isinstance(value, str) or not re.fullmatch(r'[1-9][0-9]{0,18}', value)
            or int(value) > 2**63 - 1):
        raise RedemptionError('canonical positive uint63 amount required')
    return int(value)


def validate_offer(value):
    fields = {'version', 'coupon_digest', 'issuer', 'provider', 'recipient_subject',
              'delivery_profile', 'budget_nano_usd', 'cap_semantics', 'claim_expires_at',
              'provider_expires_at', 'sponsor_powers'}
    if not isinstance(value, dict) or set(value) != fields or type(value['version']) is not int or value['version'] != 2:
        raise RedemptionError('invalid offer')
    issuer, provider = value['issuer'], value['provider']
    if (not isinstance(issuer, dict) or set(issuer) != {'peer_id', 'policy'}
            or not isinstance(issuer['peer_id'], str) or not re.fullmatch(r'[A-Za-z0-9]{1,200}', issuer['peer_id'])
            or issuer['policy'] != POLICY or not isinstance(provider, dict)
            or set(provider) != {'id', 'scope_commitment'} or provider['id'] not in ('near', 'synthetic-near')
            or not isinstance(value['recipient_subject'], str)
            or not re.fullmatch(r'[A-Za-z0-9:_./-]{1,200}', value['recipient_subject'])
            or value['delivery_profile'] != 'x25519-aesgcm-session-only'
            or value['cap_semantics'] != 'nominal-provider-limit'
            or value['provider_expires_at'] is not None
            or value['sponsor_powers'] != ['revoke', 'change_limits']):
        raise RedemptionError('invalid offer policy')
    for item in (value['coupon_digest'], provider['scope_commitment']):
        if not isinstance(item, str) or not re.fullmatch(r'[0-9a-f]{64}', item):
            raise RedemptionError('invalid offer commitment')
    amount(value['budget_nano_usd'])
    expiry(value['claim_expires_at'])
    return value


def offer_hash(value):
    return hashlib.sha256(OFFER_DOMAIN + canonical(validate_offer(value))).hexdigest()


def delivery_aad(coupon_digest, key_id, recipient, accepted_offer_hash):
    if not isinstance(key_id, str) or not re.fullmatch(r'[A-Za-z0-9:_./-]{1,200}', key_id):
        raise RedemptionError('invalid provider key identity')
    return canonical({'domain': 'dsmack-coupon-delivery-v2', 'version': 2,
                      'offer_hash': accepted_offer_hash, 'coupon_digest': coupon_digest,
                      'key_id': key_id, 'recipient_key_sha256': hashlib.sha256(recipient).hexdigest()})
