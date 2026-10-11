#!/usr/bin/env python3
"""Allowlisted public status from a deployment manifest and operator probe report.

This exporter does not verify a quote or authorize claims. The probe must be run
by the normal independently verifying client; its result remains an attributed
operator observation. No configuration, Store or operator-channel file is input.
"""
import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

HEX = re.compile(r'[0-9a-f]{64}')
PEER = re.compile(r'[A-Za-z0-9]{16,128}')
MANIFEST_FIELDS = {'version', 'network', 'environment', 'trust_profile', 'peer',
                   'bundle_url', 'bundle_sha256', 'source_revision', 'image_digest',
                   'app_id', 'compose_sha256', 'chain_id', 'guard_address', 'confirmation_profile',
                   'approval_expires_at', 'claiming_available_until'}
SUCCESS_FIELDS = {'publicPeerRouteVerified', 'issuerIdentityVerified', 'authenticatedPeer',
                  'compose', 'appId', 'approvalMatchesFreshIssuer', 'privateIssuanceQualified',
                  'rollbackQualified', 'providerAdmission', 'providerPolicy', 'providerReadiness',
                  'giftRead', 'bearerSent', 'providerEffects'}
REFUSAL_FIELDS = {'publicPeerOrIssuerRefused', 'code', 'giftRead', 'bearerSent', 'providerEffects'}


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate field')
        value[key] = item
    return value


def read_json(path):
    with Path(path).open('rb') as stream:
        raw = stream.read(65537)
    if not 0 < len(raw) <= 65536:
        raise ValueError('size refused')
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('number refused')))


def timestamp(value):
    if not isinstance(value, str) or not value.endswith('Z'):
        raise ValueError('timestamp refused')
    stamp = datetime.fromisoformat(value[:-1] + '+00:00')
    if stamp.tzinfo != timezone.utc:
        raise ValueError('timestamp refused')
    return stamp


def https_url(value):
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError('url refused')
    url = urlsplit(value)
    if (url.scheme != 'https' or not url.hostname or url.username or url.password
            or url.query or url.fragment or url.port not in (None, 443)):
        raise ValueError('url refused')
    return value


def status(manifest, probe, *, observed_at, now=None):
    now = now or datetime.now(timezone.utc)
    if type(manifest) is not dict or set(manifest) != MANIFEST_FIELDS:
        raise ValueError('manifest fields refused')
    if (type(manifest['version']) is not int or manifest['version'] != 1
            or manifest['environment'] != 'public-testnet'
            or manifest['trust_profile'] != 'operator-readable-debug'
            or type(manifest['chain_id']) is not int or manifest['chain_id'] != 8453
            or manifest['confirmation_profile'] != 'base-mainnet-rpc-safe-debug-v1'
            or not isinstance(manifest['guard_address'], str)
            or not re.fullmatch(r'0x[0-9a-f]{40}', manifest['guard_address'])
            or not isinstance(manifest['network'], str)
            or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', manifest['network'])
            or not isinstance(manifest['peer'], str)
            or not re.fullmatch(r'/dns4/[A-Za-z0-9.-]+/tcp/443/wss/p2p/[A-Za-z0-9]{16,128}', manifest['peer'])
            or not isinstance(manifest['source_revision'], str)
            or not re.fullmatch(r'[0-9a-f]{40}', manifest['source_revision'])
            or not isinstance(manifest['app_id'], str)
            or not re.fullmatch(r'[0-9a-f]{40}', manifest['app_id'])):
        raise ValueError('manifest values refused')
    for name in ('bundle_sha256', 'compose_sha256'):
        if not isinstance(manifest[name], str) or not HEX.fullmatch(manifest[name]):
            raise ValueError('hash refused')
    if (not isinstance(manifest['image_digest'], str)
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', manifest['image_digest'])):
        raise ValueError('image refused')
    https_url(manifest['bundle_url'])
    approval_end = timestamp(manifest['approval_expires_at'])
    claim_end = timestamp(manifest['claiming_available_until'])
    if claim_end > approval_end:
        raise ValueError('availability refused')
    observed = timestamp(observed_at)
    age = (now - observed).total_seconds()
    if age < -30:
        raise ValueError('future observation refused')
    if type(probe) is not dict or set(probe) not in (SUCCESS_FIELDS, REFUSAL_FIELDS):
        raise ValueError('probe fields refused')
    if probe['giftRead'] is not False or probe['bearerSent'] is not False or type(probe['providerEffects']) is not int or probe['providerEffects'] != 0:
        raise ValueError('effectful probe refused')
    successful = set(probe) == SUCCESS_FIELDS
    if successful:
        if (probe['publicPeerRouteVerified'] is not True
                or probe['issuerIdentityVerified'] != 'verified-intel-tdx-identity'
                or probe['approvalMatchesFreshIssuer'] is not True
                or probe['authenticatedPeer'] != manifest['peer'].split('/')[-1]
                or probe['compose'] != manifest['compose_sha256']
                or probe['appId'] != manifest['app_id']
                or probe['privateIssuanceQualified'] is not False
                or probe['rollbackQualified'] is not False
                or probe['providerAdmission'] is not False):
            raise ValueError('probe binding refused')
        if (probe['providerPolicy'] not in ('UpToDate', 'UpToDate-or-OutOfDate-with-warning')
                or not isinstance(probe['providerReadiness'], str)
                or len(probe['providerReadiness']) > 256):
            raise ValueError('provider metadata refused')
    elif (probe['publicPeerOrIssuerRefused'] is not True or probe['code'] not in
          ('staging_admission_refused', 'staging_approval_expired', 'issuer_identity_or_route_refused')):
        raise ValueError('refusal refused')
    state = ('stale' if age > 300 else 'expired' if now >= approval_end
             else 'refused' if not successful else 'issuer-reachable')
    return {'version': 1, **manifest, 'observed_at': observed_at,
            'observation_source': 'operator-supplied-normal-client-probe',
            'observation_max_age_seconds': 300, 'issuer_status': state,
            'claim_window_status': 'advertised-window-open' if now < claim_end else 'expired',
            'provider_model_status': 'unknown-requires-fresh-recipient-admission',
            'private_issuance_qualified': False, 'rollback_qualified': False,
            'deposit_release_authorized': False, 'l1_finality_verified': False,
            'independent_participant_count': None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--probe', required=True)
    parser.add_argument('--observed-at', required=True, help='UTC Z time recorded when the normal probe completed')
    args = parser.parse_args()
    try:
        result = status(read_json(args.manifest), read_json(args.probe), observed_at=args.observed_at)
    except Exception:
        parser.exit(2, 'Public status input refused; no input content printed.\n')
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    main()
