#!/usr/bin/env python3
"""Protected NEAR session renewal for a trusted coupon operator, never a client.

Fixed official host, original login user-agent, rotated refresh saved first.
There is no provider-key operation and no automatic POST retry. Scope and secret
paths are supplied through one owner-only input file, not values in argv/env.
"""
import argparse
import base64
import json
import os
import stat
import time
import urllib.request
from pathlib import Path

LIMIT = 1048576


class Refused(Exception):
    pass


def private_dir(path):
    path = Path(path)
    st = path.stat(follow_symlinks=False)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
        raise Refused('private_directory')
    return path


def private_json(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid()
                or st.st_nlink != 1 or st.st_mode & 0o077):
            raise Refused('private_file')
        with os.fdopen(fd, 'rb', closefd=False) as f:
            raw = f.read(LIMIT + 1)
        if not 0 < len(raw) <= LIMIT:
            raise Refused('file_size')
        return json.loads(raw)
    finally:
        os.close(fd)


def atomic_json(path, value):
    path = Path(path)
    private_dir(path.parent)
    if os.path.lexists(path): private_json(path)
    temp = path.with_name(path.name + '.rotating')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(value, f, separators=(',', ':')); f.write('\n'); f.flush(); os.fsync(f.fileno())
    os.replace(temp, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def jwt_exp(token):
    try:
        if not isinstance(token, str) or len(token) > 32768: raise ValueError()
        value = json.loads(base64.urlsafe_b64decode(token.split('.')[1] + '==='))['exp']
        if type(value) is not int: raise ValueError()
        return value
    except Exception:
        raise Refused('expiry') from None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise Refused('redirect')


def request(path, *, token, user_agent, post=False):
    # All callers supply one of the two fixed paths below; no configurable host.
    if path not in ('/v1/users/me/access-tokens', '/v1/users/me'): raise Refused('route')
    req = urllib.request.Request('https://cloud-api.near.ai' + path,
        data=b'' if post else None, method='POST' if post else 'GET',
        headers={'Authorization': 'Bearer ' + token, 'User-Agent': user_agent,
                 'Accept': 'application/json'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(req, timeout=25) as response:
        raw = response.read(LIMIT + 1)
        if response.status != 200 or len(raw) > LIMIT: raise Refused('response')
        return json.loads(raw)


def renew(directory, *, call=request, clock=time.time):
    directory = private_dir(directory)
    old = private_json(directory / 'owner-session.json')
    refresh = private_json(directory / 'owner-refresh.json')
    ua = refresh['refresh_user_agent']
    if (not isinstance(ua, str) or not 1 <= len(ua) <= 1024
            or ua != old['refresh_user_agent']
            or not isinstance(refresh['refresh_token'], str)
            or not refresh['refresh_token'].startswith('rt_')):
        raise Refused('recorded_user_agent')
    result = call('/v1/users/me/access-tokens', token=refresh['refresh_token'], user_agent=ua, post=True)
    access = result['access_token']; rotated = result['refresh_token']
    if (not isinstance(rotated, str) or not rotated.startswith('rt_') or len(rotated) > 16384
):
        raise Refused('rotation_result')
    # Save even if the following read-only identity check fails: never lose rotation.
    atomic_json(directory / 'owner-refresh.json', {'version': 1, 'refresh_token': rotated,
        'refreshed_at_unix': int(clock()), 'refresh_token_expiration': result['refresh_token_expiration'],
        'refresh_user_agent': ua})
    if jwt_exp(access) - clock() < 3500: raise Refused('rotation_result')
    me = call('/v1/users/me', token=access, user_agent=ua)
    org = old['discovered_account']['organization_id']
    if (me['id'] != old['owner_profile']['id'] or me['is_active'] is not True
            or not any(item['id'] == org and item['is_active'] is True for item in me['organizations'])):
        raise Refused('owner_scope')
    old.update(session_jwt=access, owner_profile=me, refreshed_at_unix=int(clock()), refresh_user_agent=ua)
    atomic_json(directory / 'owner-session.json', old)
    return {'renewed': True, 'seconds_remaining': int(jwt_exp(access) - clock()),
            'same_owner_and_organization': True, 'credentials_logged': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-dir', required=True)
    args = parser.parse_args()
    try: result = renew(args.private_dir)
    except Exception:
        parser.exit(2, 'Owner renewal refused; automatic retry disabled; no input content printed.\n')
    print(json.dumps(result))


if __name__ == '__main__': main()
