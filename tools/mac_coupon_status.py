#!/usr/bin/env python3
"""Project the installed coupon-free Mac admission probe to public issuer.json.

This is an operator report normalizer, not an attestation verifier. Only the
normal client verifies App Attest. This tool does not fetch, claim, or mutate.
"""
import argparse
import json
import re
from datetime import datetime, timezone
import sys
from pathlib import Path
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.coupon_testnet_status import dashboard, https_url, read_json, timestamp

MANIFEST_FIELDS = {'schema', 'network', 'peer', 'source_revision', 'trust_profile',
    'bundle_url', 'bundle_sha256', 'approval_expires_at', 'claiming_available_until',
    'identity_policy_sha256', 'issuance_policy_sha256', 'approval_sha256',
    'apple_app_id', 'cdhash', 'compose_sha256', 'runtime_app'}
PROBE_FIELDS = {'version', 'observed_at_unix', 'profile', 'evidenceStatus', 'peer',
    'appleAppId', 'cdhash', 'composeSha256', 'runtimeAppAttested',
    'identityPolicySha256', 'issuancePolicySha256', 'approvalSha256', 'custody',
    'privateIssuanceQualified', 'rollbackQualified', 'couponRead', 'bearerSent',
    'providerAdmitted', 'providerEffects'}
FALSE_FIELDS = {'privateIssuanceQualified', 'rollbackQualified', 'couponRead',
                'bearerSent', 'providerAdmitted', 'providerEffects'}


def matches(value, pattern):
    return isinstance(value, str) and re.fullmatch(pattern, value)


def status(manifest, probe, *, now=None):
    if type(manifest) is not dict or set(manifest) != MANIFEST_FIELDS:
        raise ValueError('manifest fields refused')
    if (manifest['schema'] != 'dsmack-mac-issuer-deployment-v1'
            or manifest['trust_profile'] != 'operator-readable-debug'
            or not matches(manifest['network'], r'[a-z0-9][a-z0-9-]{0,63}')
            or not matches(manifest['peer'], r'/dns4/[A-Za-z0-9.-]+/tcp/443/wss/p2p/[A-Za-z0-9]{16,128}')
            or not matches(manifest['source_revision'], r'[0-9a-f]{40}')
            or manifest['apple_app_id'] != 'DC9JH5DRMY.dev.dsmack.provider'):
        raise ValueError('manifest values refused')
    for key in ('bundle_sha256', 'identity_policy_sha256', 'issuance_policy_sha256',
                'approval_sha256', 'cdhash', 'compose_sha256'):
        if not matches(manifest[key], r'[0-9a-f]{64}'):
            raise ValueError('manifest pin refused')
    runtime = manifest['runtime_app']
    if runtime is not None and not matches(runtime, r'[A-Za-z0-9:_./|+-]{1,200}'):
        raise ValueError('runtime refused')
    https_url(manifest['bundle_url'])
    approval_end = timestamp(manifest['approval_expires_at'])
    claim_end = timestamp(manifest['claiming_available_until'])
    if claim_end > approval_end:
        raise ValueError('window refused')
    fields = PROBE_FIELDS | ({'runtimeApp'} if runtime is not None else set())
    if type(probe) is not dict or set(probe) != fields:
        raise ValueError('probe fields refused')
    if (type(probe['version']) is not int or probe['version'] != 1
            or type(probe['observed_at_unix']) is not int
            or not 0 <= probe['observed_at_unix'] <= 253402300799
            or probe['profile'] != 'mac-appattest-coupon-v1'
            or probe['evidenceStatus'] != 'verified-apple-appattest-issuer-identity'
            or probe['custody'] != 'operator-kms-readable'
            or any(probe[key] is not False for key in FALSE_FIELDS)
            or probe['runtimeAppAttested'] is not (runtime is not None)
            or (runtime is not None and probe['runtimeApp'] != runtime)):
        raise ValueError('probe qualification refused')
    bindings = {'appleAppId': 'apple_app_id', 'cdhash': 'cdhash',
        'composeSha256': 'compose_sha256', 'identityPolicySha256': 'identity_policy_sha256',
        'issuancePolicySha256': 'issuance_policy_sha256', 'approvalSha256': 'approval_sha256'}
    if (probe['peer'] != manifest['peer'].split('/')[-1]
            or any(probe[key] != manifest[target] for key, target in bindings.items())):
        raise ValueError('probe binding refused')
    observed = datetime.fromtimestamp(probe['observed_at_unix'], timezone.utc)
    now = now or datetime.now(timezone.utc)
    if type(now) is not datetime or now.tzinfo is None:
        raise ValueError('clock refused')
    age = (now - observed).total_seconds()
    if age < -30:
        raise ValueError('future observation refused')
    return dashboard({**manifest, 'identity_profile': probe['profile'],
        'observed_at': observed.isoformat().replace('+00:00', 'Z'),
        'issuer_status': 'stale' if age > 300 else 'expired' if now >= approval_end else 'issuer-reachable'})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--probe', required=True)
    args = parser.parse_args()
    try:
        result = status(read_json(args.manifest), read_json(args.probe))
    except Exception:
        parser.exit(2, 'Mac status input refused; no input content printed.\n')
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    main()
