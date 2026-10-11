"""Read-only provider runner. Never creates keys, purchases credits or infers."""
import argparse
import json
import os
import sys
from datetime import datetime
from uuid import UUID

from .near import Near
from .transport import NearHTTPS
from .spike import RedemptionError


def _secret(name):
    value = os.environ.get(name)
    if not value:
        raise RedemptionError('required credential environment variable is missing')
    return value


def _time(value):
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None:
        raise ValueError('timezone required')
    return result


def run(args, transport):
    if args.command == 'health':
        result = transport('GET', 'https://cloud-api.near.ai/v1/health', None, None)
        return {'mode': 'public-read-only', 'provider_response_received': isinstance(result, dict)}
    if args.command == 'preflight':
        profile = transport('GET', 'https://cloud-api.near.ai/v1/users/me', _secret('NEAR_SESSION_JWT'), None)
        # Minimize output: never dump profile or an unvalidated provider object.
        return {'mode': 'authenticated-read-only', 'authenticated': True,
                'organizations': [{'id': str(UUID(x['id']))} for x in profile.get('organizations', [])],
                'workspaces': [{'id': str(UUID(x['id'])), 'organization_id': str(UUID(x['organization_id']))}
                               for x in profile.get('workspaces', [])]}
    if _time(args.end) < _time(args.start):
        raise ValueError('invalid observation range')
    provider = Near(args.workspace, args.organization, None, _secret('NEAR_REPORTING_TOKEN'), transport)
    rows = provider.usage_rows(str(UUID(args.key)), args.start, args.end)
    # Raw rows may include sensitive metadata. Emit only validated count/cost.
    costs = []
    identities = set()
    for row in rows:
        cost = row.get('total_cost_nano_usd')
        identity = (row.get('source'), row.get('id'))
        if (type(cost) is not int or not 0 <= cost <= 2**63 - 1
                or identity[0] not in ('inference', 'service') or not isinstance(identity[1], str)
                or not identity[1] or identity in identities):
            raise RedemptionError('invalid or duplicate provider usage row')
        identities.add(identity)
        costs.append(cost)
    return {'mode': 'authenticated-read-only', 'evidence_status': 'unsigned_provider_observation',
            'key_id': str(UUID(args.key)), 'row_count': len(rows),
            'provider_reported_nano_usd': sum(costs), 'deposit_release_authorized': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('health')
    commands.add_parser('preflight')
    usage = commands.add_parser('usage')
    for name in ['workspace', 'organization', 'key', 'start', 'end']:
        usage.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(run(args, NearHTTPS()), sort_keys=True))
        return 0
    except Exception:
        # Never expose provider response bodies, secrets, or underlying errors.
        print('NEAR read-only check failed; verify credentials, scope and inputs.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
