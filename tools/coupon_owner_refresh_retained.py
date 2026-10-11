#!/usr/bin/env python3
"""One-shot owner renewal with disk allocation before the irreversible POST.

The complete returned rotation is saved in a preallocated private file before
checking token shape, expiry or owner scope. A failed/ambiguous run is never
automatically repeated; the retained response is operator reconciliation input.
"""
import argparse
import json
import os
import shutil
import time
import urllib.request
from pathlib import Path

import coupon_owner_session as owner

RESERVATION = 2 * owner.LIMIT
MIN_FREE = 16 * owner.LIMIT


def directory_sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def raw_post(token, ua):
    req = urllib.request.Request('https://cloud-api.near.ai/v1/users/me/access-tokens',
        data=b'', method='POST', headers={'Authorization': 'Bearer ' + token,
        'User-Agent': ua, 'Accept': 'application/json'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), owner.NoRedirect())
    with opener.open(req, timeout=25) as response:
        # Return bytes, including the sentinel byte for oversized responses.
        # Parsing/size refusal happens only after durable private retention.
        return response.read(owner.LIMIT + 1)


def renew(directory, *, call=None, clock=time.time,
          free_bytes=lambda p: shutil.disk_usage(p).free,
          allocate=os.posix_fallocate):
    directory = owner.private_dir(directory)
    old = owner.private_json(directory / 'owner-session.json')
    refresh = owner.private_json(directory / 'owner-refresh.json')
    ua = refresh.get('refresh_user_agent')
    if (not isinstance(ua, str) or not 1 <= len(ua) <= 1024
            or ua != old.get('refresh_user_agent')
            or not isinstance(refresh.get('refresh_token'), str)
            or not refresh['refresh_token'].startswith('rt_')):
        raise owner.Refused('recorded_user_agent')
    if free_bytes(directory) < MIN_FREE:
        raise owner.Refused('disk_space')
    # Refuse even a partial previous run. No POST has happened if allocation
    # fails, but only an operator may clear these durable reconciliation files.
    for name in ('refresh-started.json', 'rotation-response.json'):
        if os.path.lexists(directory / name):
            raise owner.Refused('previous_attempt')
    fd = os.open(directory / 'rotation-response.json',
                 os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        allocate(fd, 0, RESERVATION)
        os.fsync(fd)
        directory_sync(directory)
        marker = os.open(directory / 'refresh-started.json',
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(marker, 'w') as f:
            json.dump({'version': 1, 'started_at_unix': int(clock()),
                       'automatic_retry': False}, f)
            f.flush()
            os.fsync(f.fileno())
        directory_sync(directory)
        returned = (raw_post(refresh['refresh_token'], ua) if call is None else
                    call('/v1/users/me/access-tokens', token=refresh['refresh_token'],
                         user_agent=ua, post=True))
        # Injected dict calls are fixture-only. Production receives bounded raw
        # bytes and saves them before JSON parsing or token validation.
        raw = (returned if isinstance(returned, bytes) else
               json.dumps(returned, separators=(',', ':'), ensure_ascii=True).encode('ascii'))
        if len(raw) >= RESERVATION:
            raise owner.Refused('fixture_response_size')
        # Do not truncate the allocated slot: writes use already reserved blocks.
        payload = raw + b'\n' + b' ' * (RESERVATION - len(raw) - 1)
        offset = 0
        while offset < len(payload):
            n = os.pwrite(fd, payload[offset:], offset)
            if n <= 0:
                raise owner.Refused('response_retention')
            offset += n
        os.fsync(fd)
        directory_sync(directory)
        if len(raw) > owner.LIMIT:
            raise owner.Refused('response_size')
        result = json.loads(raw)
        access, rotated = result['access_token'], result['refresh_token']
        if (not isinstance(rotated, str) or not rotated.startswith('rt_')
                or len(rotated) > 16384):
            raise owner.Refused('rotation_result')
        owner.atomic_json(directory / 'owner-refresh.json', {
            'version': 1, 'refresh_token': rotated, 'refreshed_at_unix': int(clock()),
            'refresh_token_expiration': result['refresh_token_expiration'],
            'refresh_user_agent': ua})
        if owner.jwt_exp(access) - clock() < 3500:
            raise owner.Refused('rotation_result')
        me = (owner.request if call is None else call)('/v1/users/me', token=access, user_agent=ua)
        org = old['discovered_account']['organization_id']
        if (me['id'] != old['owner_profile']['id'] or me['is_active'] is not True
                or not any(item['id'] == org and item['is_active'] is True
                           for item in me['organizations'])):
            raise owner.Refused('owner_scope')
        old.update(session_jwt=access, owner_profile=me,
                   refreshed_at_unix=int(clock()), refresh_user_agent=ua)
        owner.atomic_json(directory / 'owner-session.json', old)
        return {'renewed': True, 'rotation_response_retained': True,
                'same_owner_and_organization': True,
                'seconds_remaining': int(owner.jwt_exp(access) - clock()),
                'credentials_logged': False, 'automatic_retry': False}
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-dir', required=True, type=Path)
    args = parser.parse_args()
    try:
        result = renew(args.private_dir)
    except Exception:
        parser.exit(2, 'Renewal refused; preserve private response and marker; do not retry automatically.\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
