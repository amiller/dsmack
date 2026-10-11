#!/usr/bin/env python3
"""Sanitized Mac preview operations manifest/status reader.

Reads one bounded, allowlisted local inventory JSON that the operator recorded
and derives an observation status. It opens no connection, probes no process,
reads no credential/config/JWT/path/secret/account field, guesses no peer
membership and mutates nothing. `inventory_observation_fresh` is an operator-attributed
observation that expires after 90 seconds. `claiming_available` additionally
requires inventory freshness, over 650 seconds of owner authorization, a valid
policy window, gas/provider readiness and observed absence of maintenance; this
schema carries no gas, provider or maintenance channel, so it fails closed.
"""
import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path

MAX_BYTES = 65536
MAX_AGE_SECONDS = 90
MAX_FUTURE_SECONDS = 30
MIN_OWNER_AUTH_SECONDS = 650
MAX_PID = 4194304
STAMP = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z')
HASH = re.compile(r'[0-9a-f]{64}')
PEER = re.compile(r'[A-Za-z0-9]{16,128}')
PREVIEW_FIELDS = {'environment', 'runner_pid', 'holder_pid', 'kms_pid', 'compose', 'peer',
                  'claim_deadline_utc', 'credential_expiry_utc', 'automatic_reboot_recovery_qualified'}
RELAY_FIELDS = {'pid', 'loopback_tcp', 'loopback_ws', 'cloudflare_pid', 'temporary_tunnel'}
DEV_FIELDS = {'native_dev_node_pid', 'runner_pid', 'current_independent_qualification'}
PILOT_FIELDS = {'runner_pid', 'broker_pid', 'kms_pid', 'managed_staging_qualified'}
SUPERSEDED_FIELDS = {'runner_pid', 'kms_pid', 'holder_pid'}
INVENTORY_FIELDS = {'observed_at_utc', 'qualified_preview', 'relay', 'private_dev_reference',
                    'historical_pilot', 'superseded_unused', 'idle_old_holder_pid',
                    'private_staging_qualified', 'production_deployed', 'project_cvms_allowed',
                    'runtime_mutations_authorized_by_task'}
# The reader supports exactly the supplied unqualified-preview world. Exporting a
# qualification it cannot observe would be fabrication; a changed world needs a
# reviewed schema change, not a field flip.
FALSE_FLAGS = (('qualified_preview', 'automatic_reboot_recovery_qualified'),
               ('private_dev_reference', 'current_independent_qualification'),
               ('historical_pilot', 'managed_staging_qualified'),
               (None, 'private_staging_qualified'), (None, 'production_deployed'),
               (None, 'project_cvms_allowed'), (None, 'runtime_mutations_authorized_by_task'))


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate field')
        value[key] = item
    return value


def read_inventory(path):
    with Path(path).open('rb') as stream:
        raw = stream.read(MAX_BYTES + 1)
    if not 0 < len(raw) <= MAX_BYTES:
        raise ValueError('size refused')
    data = json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('number refused')))
    return validate(data)


def stamp(value):
    if not isinstance(value, str) or not STAMP.fullmatch(value):
        raise ValueError('timestamp refused')
    return datetime.fromisoformat(value[:-1] + '+00:00')


def section(data, name, fields):
    value = data[name]
    if type(value) is not dict or set(value) != fields:
        raise ValueError(name + ' refused')
    return value


def pid(value):
    if type(value) is not int or not 1 <= value <= MAX_PID:
        raise ValueError('pid refused')


def validate(data):
    if type(data) is not dict or set(data) != INVENTORY_FIELDS:
        raise ValueError('inventory fields refused')
    stamp(data['observed_at_utc'])
    preview = section(data, 'qualified_preview', PREVIEW_FIELDS)
    dev = section(data, 'private_dev_reference', DEV_FIELDS)
    pilot = section(data, 'historical_pilot', PILOT_FIELDS)
    superseded = section(data, 'superseded_unused', SUPERSEDED_FIELDS)
    for owner, name in FALSE_FLAGS:
        value = (preview if owner == 'qualified_preview'
                 else dev if owner == 'private_dev_reference'
                 else pilot if owner == 'historical_pilot' else data)[name]
        if type(value) is not bool or value is not False:
            raise ValueError('qualification refused')
    pid(data['idle_old_holder_pid'])
    if (preview['environment'] != 'public-testnet-preview'
            or not isinstance(preview['compose'], str) or not HASH.fullmatch(preview['compose'])
            or not isinstance(preview['peer'], str) or not PEER.fullmatch(preview['peer'])):
        raise ValueError('preview refused')
    for name in ('runner_pid', 'holder_pid', 'kms_pid'):
        pid(preview[name])
    if stamp(preview['claim_deadline_utc']) > stamp(preview['credential_expiry_utc']):
        raise ValueError('policy window refused')
    relay = section(data, 'relay', RELAY_FIELDS)
    for name in ('pid', 'cloudflare_pid'):
        pid(relay[name])
    for name in ('loopback_tcp', 'loopback_ws'):
        if type(relay[name]) is not int or not 1 <= relay[name] <= 65535:
            raise ValueError('port refused')
    if relay['temporary_tunnel'] is not True:
        raise ValueError('relay refused')
    for candidates in (dev, pilot, superseded):
        for key, value in candidates.items():
            if key.endswith('_pid'):
                pid(value)
    return data


def status(inventory, *, now):
    if type(now) is not datetime or now.tzinfo is None:
        raise ValueError('caller time refused')
    now = now.astimezone(timezone.utc)
    preview = inventory['qualified_preview']
    age = (now - stamp(inventory['observed_at_utc'])).total_seconds()
    if age < -MAX_FUTURE_SECONDS:
        observation = 'unknown'
    elif age > MAX_AGE_SECONDS:
        observation = 'stale'
    else:
        observation = 'fresh'
    fresh = observation == 'fresh'
    owner_remaining = (stamp(preview['credential_expiry_utc']) - now).total_seconds()
    requirements = {
        'inventory_observation_fresh': fresh,
        'owner_authorization_remaining_over_650s': fresh and owner_remaining > MIN_OWNER_AUTH_SECONDS,
        'policy_claim_window_open': fresh and now < stamp(preview['claim_deadline_utc']),
        # No allowlisted gas, provider-readiness or maintenance channel exists in
        # this schema. Unobserved predicates block claiming; they are never assumed.
        'gas_and_provider_readiness_observed': False,
        'maintenance_absence_observed': False,
    }
    blockers = [name for name, held in requirements.items() if not held]
    return {
        'version': 1,
        'observation_source': 'operator-attributed-mac-inventory',
        'observed_at_utc': inventory['observed_at_utc'],
        'observation_age_seconds': int(age),
        'observation_max_age_seconds': MAX_AGE_SECONDS,
        'observation_max_future_seconds': MAX_FUTURE_SECONDS,
        'observation_status': observation,
        'inventory_observation_fresh': fresh,
        'issuer_environment': preview['environment'],
        'issuer_compose_sha256': preview['compose'],
        'issuer_peer': preview['peer'],
        'claim_window_open': requirements['policy_claim_window_open'],
        'claiming_available': not blockers,
        'claiming_requirements': requirements,
        'claiming_blockers': blockers,
        'automatic_reboot_recovery_qualified': False,
        'retirement_candidates': ['historical_pilot', 'superseded_unused', 'idle_old_holder'],
        'retirement_authorized': False,
        'environments': {'public_testnet_preview': 'historically-qualified-issuer-admission-redemption-paused',
                         'managed_private_staging': 'not-qualified',
                         'private_dev_reference': 'historically-observed-not-qualified',
                         'production': 'not-deployed'},
        'independent_participant_count': None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--inventory', required=True,
                        help='Bounded operator-recorded Mac preview inventory JSON (public metadata only)')
    parser.add_argument('--now', required=True,
                        help='Caller current UTC time, for example 2026-10-11T20:19:00Z')
    args = parser.parse_args()
    try:
        result = status(read_inventory(args.inventory), now=stamp(args.now))
    except Exception:
        parser.exit(2, 'Inventory or caller time refused; no input content printed.\n')
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    main()
