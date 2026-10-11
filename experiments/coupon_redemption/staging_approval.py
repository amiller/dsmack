"""Independent signed authorization for explicitly operator-readable staging.

This is not quote verification or private-custody qualification. The approval
root is compiled into the measured image; it is never taken from the payload.
"""
import hashlib
import json
import re
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .offer_v2 import amount, expiry
from .spike import RedemptionError
from .transport import _unique_object, _reject_constant

APPROVAL_DOMAIN = 'dsmack-coupon-staging-approval-v1'
CONFIG_DOMAIN = 'dsmack-coupon-staging-config-v1'
POWERS = ['operator-secret-access', 'application-exec', 'debugger', 'host-clock']


def canonical(value):
    def check(item):
        if type(item) is str:
            item.encode('ascii')
        elif type(item) in (bool, int) or item is None:
            pass
        elif type(item) is list:
            for child in item:
                check(child)
        elif type(item) is dict:
            for key, child in item.items():
                if type(key) is not str:
                    raise ValueError()
                key.encode('ascii')
                check(child)
        else:
            raise ValueError()
    check(value)
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def payload_hash(domain, payload):
    return hashlib.sha256(domain.encode('ascii') + b'\0' + canonical(payload)).hexdigest()


def signed_payload(raw, domain, trusted_public_key):
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= 65536:
            raise ValueError()
        envelope = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
        if (type(envelope) is not dict or set(envelope) != {'domain', 'payload', 'signature_hex'}
                or envelope['domain'] != domain or type(envelope['payload']) is not dict
                or type(envelope['signature_hex']) is not str
                or not re.fullmatch(r'[0-9a-f]{128}', envelope['signature_hex'])
                or type(trusted_public_key) is not bytes or len(trusted_public_key) != 32):
            raise ValueError()
        Ed25519PublicKey.from_public_bytes(trusted_public_key).verify(
            bytes.fromhex(envelope['signature_hex']), domain.encode('ascii') + b'\0' + canonical(envelope['payload']))
        return envelope['payload']
    except Exception:
        raise RedemptionError('signed staging authorization refused') from None


def approval(raw, trusted_public_key, *, now=None):
    payload = signed_payload(raw, APPROVAL_DOMAIN, trusted_public_key)
    return validate_approval_payload(payload, now=now)


def validate_approval_payload(payload, *, now=None, mac=False):
    fields = {'version', 'profile', 'app_id', 'compose_hash', 'identity_policy_sha256',
              'issuance_policy_sha256', 'issuer_public_key_sha256', 'provider_scope_commitment',
              'guard', 'powers', 'prompt_policy', 'max_coupon_nano_usd', 'max_total_nano_usd',
              'expires_at', 'generation'}
    try:
        # 'generation' is coordination metadata: shape-checked here, never
        # enforced monotonic (see staging-deployment.md section 4).
        if mac:
            fields |= {'issuer_profile', 'cdhash'}
        if (set(payload) != fields or type(payload['version']) is not int or payload['version'] != (2 if mac else 1)
                or payload['profile'] != 'debug-staging' or payload['powers'] != POWERS
                or payload['prompt_policy'] != 'synthetic-only'
                or type(payload['generation']) is not int or not 1 <= payload['generation'] <= 2**53-1
                or type(payload['app_id']) is not str
                or not re.fullmatch(r'[A-Za-z0-9_.:|/-]{1,200}' if mac else r'[0-9a-f]{40}', payload['app_id'])
                or (mac and (payload['issuer_profile'] != 'mac-appattest-coupon-v1'
                    or type(payload['cdhash']) is not str or not re.fullmatch(r'[0-9a-f]{64}', payload['cdhash'])))):
            raise ValueError()
        for field in ('compose_hash', 'identity_policy_sha256', 'issuance_policy_sha256',
                      'issuer_public_key_sha256', 'provider_scope_commitment'):
            if type(payload[field]) is not str or not re.fullmatch(r'[0-9a-f]{64}', payload[field]):
                raise ValueError()
        guard = payload['guard']
        from .issuance_guard import BASE_CONFIRMATION
        base = type(guard) is dict and guard.get('chain_id') == 8453
        if (type(guard) is not dict or set(guard) != ({'chain_id', 'address', 'code_hash', 'issuer_address', 'confirmation'}
                    if base else {'chain_id', 'address', 'code_hash', 'issuer_address'})
                or type(guard['chain_id']) is not int or guard['chain_id'] not in (11155111, 8453)
                or (base and (guard['confirmation'] != BASE_CONFIRMATION
                    or canonical(guard['confirmation']) != canonical(BASE_CONFIRMATION)
                    or amount(payload['max_total_nano_usd']) > 5000000000))
                or not re.fullmatch(r'0x[0-9a-f]{64}', guard['code_hash'])
                or any(not re.fullmatch(r'0x[0-9a-f]{40}', guard[k]) for k in ('address', 'issuer_address'))):
            raise ValueError()
        if amount(payload['max_coupon_nano_usd']) > amount(payload['max_total_nano_usd']):
            raise ValueError()
        if (now or datetime.now(timezone.utc)) >= expiry(payload['expires_at']):
            raise ValueError()
    except Exception:
        raise RedemptionError('staging approval policy refused') from None
    return payload


def _absolute_directory(value):
    # Precise operator state path: an absolute string with no empty, relative
    # or traversing segments and no NUL byte.
    return (type(value) is str and value.startswith('/') and '\0' not in value
            and all(part not in ('', '.', '..') for part in value[1:].split('/')))


def configuration(raw, trusted_public_key, approved):
    payload = signed_payload(raw, CONFIG_DOMAIN, trusted_public_key)
    return validate_configuration_payload(payload, approved)


def validate_configuration_payload(payload, approved, *, approval_domain=APPROVAL_DOMAIN):
    fields = {'version', 'approval_sha256', 'issuer_peer_id', 'state_dir', 'sponsor_subject',
              'observer_subject', 'peers', 'provider', 'scope_salt_hex', 'finality_profile',
              'gas_price_wei', 'job_deadline_seconds', 'max_active_jobs'}
    # Like approval(): any malformed member refuses with the named stable error
    # instead of leaking TypeError/ValueError from a regex or canonicalization.
    # state_dir must be a precise absolute path (the worker re-checks at use)
    # and issuer_peer_id must satisfy the same identity contract the node
    # enforces on bootstrap ([A-Za-z0-9]{16,128}); both previously crashed
    # downstream (TypeError at Path(), sqlite3.ProgrammingError at INSERT).
    try:
        if (set(payload) != fields or type(payload['version']) is not int or payload['version'] != 1
                or type(payload['approval_sha256']) is not str
                or payload['approval_sha256'] != payload_hash(approval_domain, approved)
                or not _absolute_directory(payload['state_dir'])
                or type(payload['issuer_peer_id']) is not str
                or not re.fullmatch(r'[A-Za-z0-9]{16,128}', payload['issuer_peer_id'])):
            raise ValueError()
    except Exception:
        raise RedemptionError('signed staging configuration refused') from None
    provider = payload['provider']
    try:
        if (type(provider) is not dict or set(provider) != {'workspace_id', 'organization_id', 'session_jwt', 'reporting_token'}
                or any(type(v) is not str or not v for v in provider.values())
                or type(payload['scope_salt_hex']) is not str
                or not re.fullmatch(r'[0-9a-f]{64}', payload['scope_salt_hex'])):
            raise ValueError()
    except Exception:
        raise RedemptionError('signed provider configuration refused') from None
    from uuid import UUID
    try:
        for key in ('workspace_id', 'organization_id'):
            if str(UUID(provider[key])) != provider[key]:
                raise ValueError()
    except Exception:
        raise RedemptionError('signed provider account refused') from None
    binding = {'mode': 'near', **{k: provider[k] for k in ('workspace_id', 'organization_id')}}
    from .offer_v2 import canonical as offer_canonical
    scope = hashlib.sha256(b'dsmack-coupon-scope-v2\0' + bytes.fromhex(payload['scope_salt_hex']) + offer_canonical(binding)).hexdigest()
    if scope != approved['provider_scope_commitment']:
        raise RedemptionError('provider account commitment refused')
    profile = payload['finality_profile']
    from .issuance_guard import validate_finality_profile
    try:
        # Complete exact checker schema before any credential use; the guard
        # re-validates independently before it owns an attempt.
        validate_finality_profile(profile)
    except ValueError:
        raise RedemptionError('signed guard configuration refused') from None
    if (profile['guard_address'] != approved['guard']['address']
            or profile['guard_code_hash'] != approved['guard']['code_hash']
            or profile['issuer_address'] != approved['guard']['issuer_address']
            or profile['chain_id'] != approved['guard']['chain_id']
            or profile['issuance_policy_hash'] != '0x' + approved['issuance_policy_sha256']
            or type(payload['gas_price_wei']) is not int or not 0 < payload['gas_price_wei'] < 2**64
            or type(payload['job_deadline_seconds']) is not int or not 60 <= payload['job_deadline_seconds'] <= 7200
            or type(payload['max_active_jobs']) is not int or not 1 <= payload['max_active_jobs'] <= 8):
        raise RedemptionError('signed guard configuration refused')
    return payload
