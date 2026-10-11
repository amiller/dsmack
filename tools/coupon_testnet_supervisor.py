#!/usr/bin/env python3
"""Single-controller scheduler for private operator renewal/rotation.

The separately reviewed adapter implements pinned-container inspect, idle barrier,
full private backup, JWT-only signing/rotation and fresh readiness verification.
No shell commands or credentials are accepted from a recipient. An ambiguous
mutation is durably blocked for operator reconciliation, never automatically retried.
"""
import argparse
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from coupon_owner_session import Refused, atomic_json, private_dir, private_json, renew

PLAN_FIELDS = {'version', 'owner_dir', 'state_dir', 'adapter', 'adapter_sha256', 'adapter_plan'}
INSPECT_FIELDS = {'ready', 'issuing_jobs', 'owner_expires_at_unix', 'approval_expires_at_unix',
                  'obligation_fingerprint', 'one_claim_reserve_ready'}


def load_plan(path):
    plan = private_json(path)
    if type(plan) is not dict or set(plan) != PLAN_FIELDS or type(plan['version']) is not int or plan['version'] != 1:
        raise Refused('plan')
    for key in ('owner_dir', 'state_dir'):
        if not Path(plan[key]).is_absolute(): raise Refused('path')
        private_dir(plan[key])
    private_json(plan['adapter_plan'])
    script = Path(plan['adapter'])
    st = script.stat(follow_symlinks=False)
    if (not script.is_absolute() or not stat.S_ISREG(st.st_mode)
            or st.st_mode & 0o022 or st.st_uid not in (0, os.geteuid())
            or not re.fullmatch(r'[0-9a-f]{64}', plan['adapter_sha256'])
            or hashlib.sha256(script.read_bytes()).hexdigest() != plan['adapter_sha256']):
        raise Refused('adapter')
    return plan


def run_adapter(plan, operation, *, timeout=180):
    if operation not in ('inspect', 'rotate', 'verify'): raise Refused('operation')
    # Recheck the reviewed entrypoint before every invocation. No shell or secret
    # argv. All secret-bearing output stays in an owner-only temporary file.
    script = Path(plan['adapter'])
    if hashlib.sha256(script.read_bytes()).hexdigest() != plan['adapter_sha256']:
        raise Refused('adapter_changed')
    state = private_dir(plan['state_dir'])
    fd, name = tempfile.mkstemp(prefix='adapter-', dir=state)
    try:
        with os.fdopen(fd, 'wb') as out:
            process = subprocess.run([sys.executable, str(script), operation,
                '--plan', plan['adapter_plan']], stdin=subprocess.DEVNULL, stdout=out,
                stderr=subprocess.DEVNULL, timeout=timeout,
                env={k: v for k, v in os.environ.items() if k in ('PATH', 'LANG', 'LC_ALL', 'SSH_AUTH_SOCK')})
        if process.returncode != 0: raise Refused('adapter_refused')
        with open(name, 'rb') as f: raw = f.read(65537)
        if not 0 < len(raw) <= 65536: raise Refused('adapter_size')
        return json.loads(raw)
    finally:
        # This temporary file is never a bearer delivery channel and is not
        # uploaded. Removing this owned throwaway result does not alter Store.
        os.unlink(name)


def inspection(value):
    if (type(value) is not dict or set(value) != INSPECT_FIELDS
            or type(value['ready']) is not bool or type(value['one_claim_reserve_ready']) is not bool
            or type(value['issuing_jobs']) is not int or value['issuing_jobs'] < 0
            or any(type(value[k]) is not int for k in ('owner_expires_at_unix', 'approval_expires_at_unix'))
            or not isinstance(value['obligation_fingerprint'], str)
            or not re.fullmatch(r'[0-9a-f]{64}', value['obligation_fingerprint'])):
        raise Refused('inspection')
    return value


def cycle(plan, *, adapter=run_adapter, renew_owner=renew, clock=time.time):
    state = private_dir(plan['state_dir'])
    marker = state / 'rotation.json'
    health = state / 'health.json'
    if marker.exists():
        previous = private_json(marker)
        if previous.get('stage') != 'complete':
            atomic_json(health, {'state': 'reconciliation-required', 'observed_at_unix': int(clock()),
                                 'claiming_available': False})
            return 'blocked'
    try:
        before = inspection(adapter(plan, 'inspect'))
    except Exception:
        atomic_json(health, {'state': 'unknown', 'observed_at_unix': int(clock()), 'claiming_available': False})
        return 'unknown'
    now = int(clock())
    available = (before['ready'] and before['one_claim_reserve_ready']
                 and before['owner_expires_at_unix'] - now > 650
                 and before['approval_expires_at_unix'] - now > 650)
    atomic_json(health, {'state': 'ready' if available else 'unavailable',
                         'observed_at_unix': now, 'claiming_available': available})
    if before['approval_expires_at_unix'] - now <= 1800:
        # A new authority/policy epoch is NOT an owner-token renewal. Never
        # auto-sign a longer approval, silently migrate or enlarge budgets here.
        atomic_json(health, {'state': 'approval-renewal-required', 'observed_at_unix': now,
                             'claiming_available': False})
        return 'approval-renewal-required'
    if before['owner_expires_at_unix'] - now > 1800: return 'ready' if available else 'unavailable'
    if before['issuing_jobs'] != 0:
        # Original process/intent survives. No token/config changes mid-issuance.
        return 'busy'
    if not before['ready'] or not before['one_claim_reserve_ready']: return 'unavailable'
    # Mutation intent is durable BEFORE refresh POST. Crash/timeout/failure at
    # any later stage blocks automatic replay of refresh or service rotation.
    atomic_json(marker, {'stage': 'refresh-started', 'started_at_unix': now,
                         'before_fingerprint': before['obligation_fingerprint']})
    atomic_json(health, {'state': 'maintenance', 'observed_at_unix': now, 'claiming_available': False})
    try:
        renewal = renew_owner(plan['owner_dir'])
        if (type(renewal) is not dict or renewal.get('renewed') is not True
                or renewal.get('same_owner_and_organization') is not True
                or renewal.get('seconds_remaining', 0) < 3500):
            raise Refused('renewal')
        atomic_json(marker, {'stage': 'rotation-started', 'started_at_unix': now,
                             'before_fingerprint': before['obligation_fingerprint']})
        changed = adapter(plan, 'rotate')
        if (type(changed) is not dict or set(changed) != {'rotated', 'before_fingerprint', 'after_fingerprint'}
                or changed['rotated'] is not True
                or changed['before_fingerprint'] != before['obligation_fingerprint']
                or changed['after_fingerprint'] != before['obligation_fingerprint']):
            raise Refused('retention')
        after = inspection(adapter(plan, 'verify'))
        if (after['issuing_jobs'] != 0 or not after['ready'] or not after['one_claim_reserve_ready']
                or after['obligation_fingerprint'] != before['obligation_fingerprint']
                or after['approval_expires_at_unix'] != before['approval_expires_at_unix']
                or after['owner_expires_at_unix'] - clock() < 3000):
            raise Refused('readiness')
        atomic_json(marker, {'stage': 'complete', 'completed_at_unix': int(clock()),
                             'before_fingerprint': before['obligation_fingerprint']})
        atomic_json(health, {'state': 'ready', 'observed_at_unix': int(clock()), 'claiming_available': True})
        return 'renewed'
    except Exception:
        atomic_json(health, {'state': 'reconciliation-required', 'observed_at_unix': int(clock()),
                             'claiming_available': False})
        return 'blocked'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', required=True)
    parser.add_argument('--once', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        plan = load_plan(args.plan)
        lock = os.open(Path(plan['state_dir']) / 'supervisor.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        st = os.fstat(lock)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077 or st.st_nlink != 1:
            raise Refused('lock')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        while True:
            cycle(plan)
            if args.once: break
            time.sleep(30)
    except Exception:
        parser.exit(2, 'Supervisor refused; no input content printed.\n')


if __name__ == '__main__': main()
