"""Measured container profiles; callers select names rather than security options."""
import hashlib
import os
import stat
from pathlib import Path

PROFILE = 'browser-sandbox-v1'
AGENT_PROFILE = 'agent-sandbox-v1'
AGENT_SOCKET_TARGET = '/root/dstack.sock'
# A dev session runs its own rootless container engine; the per-run VM is the isolation boundary (ADR 0010).
DEV_PROFILE = 'dev-session-v1'
ENGINE_TARGET = '/var/lib/dsmack-engine'
ENGINE_HOST_ROOT = '/var/lib/docker/dsmack-engine'
POLICY_DIR = '/usr/local/lib/dsmack/compose-runner/lib/dsmack_compose_contract/'
POLICIES = {PROFILE: ('cc3e61cabda6bbc1e53e54d27ba4d55a9d3be829b6dd1a596f4a7b31b1cc7849', 12997),
            DEV_PROFILE: ('bc9b12c0526d1514aa690d34ea8e30b76dcf39b5e8205438b5f7068d9d1090e8', 11713)}
POLICY_SHA256 = POLICIES[PROFILE][0]
POLICY_PATH = POLICY_DIR + PROFILE + '.json'


def verify_policy(profile=PROFILE):
    digest, size = POLICIES[profile]
    path = Path(__file__).with_name(profile + '.json')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size != size:
            raise ValueError('%s policy type/size refused' % profile)
        data = os.read(fd, size + 1)
        if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
            raise ValueError('%s policy digest refused' % profile)
    finally:
        os.close(fd)


def service_user(profile):
    return '0:0' if profile == AGENT_PROFILE else '1000:1000'


def preset_fields(profile=PROFILE):
    if profile == AGENT_PROFILE:
        return {
            'user': service_user(profile),
            'cap_drop': ['ALL'],
            'cap_add': ['CHOWN', 'FOWNER', 'DAC_OVERRIDE', 'SETUID', 'SETGID', 'KILL'],
            'security_opt': ['no-new-privileges:true'],
            'tmpfs': ['/workspace:rw,nosuid,nodev,size=268435456,uid=1000,gid=1000,mode=0700'],
            'shm_size': 67108864,
            'pids_limit': 128,
            'mem_limit': 2147483648,
        }
    if profile == DEV_PROFILE:
        verify_policy(profile)
        return {
            'cap_drop': ['ALL'],
            'cap_add': [],
            'security_opt': ['no-new-privileges:true', 'seccomp:' + POLICY_DIR + profile + '.json', 'systempaths=unconfined'],
            'tmpfs': ['/workspace:rw,nosuid,nodev,size=268435456,uid=1000,gid=1000,mode=0700'],
            'shm_size': 67108864,
            'pids_limit': 1024,
            'mem_limit': 2147483648,
        }
    verify_policy()
    return {
        'cap_drop': ['ALL'],
        'cap_add': ['SYS_CHROOT'],
        'security_opt': ['no-new-privileges:true', 'seccomp:' + POLICY_PATH],
        'tmpfs': ['/tmp:rw,nosuid,nodev,size=268435456,mode=1777'],
        'shm_size': 268435456,
        'pids_limit': 256,
        'mem_limit': 2147483648,
    }


def require_selection(service, manifest):
    profile = service.get('security_profile')
    if 'security_profile' not in service:
        return None
    if profile in (AGENT_PROFILE, DEV_PROFILE):
        if manifest.get('credentials', {}).get('required'):
            raise ValueError('%s refuses credential broker' % profile)
        if profile == DEV_PROFILE:
            verify_policy(profile)
        return profile
    if profile != PROFILE:
        raise ValueError('unknown security profile')
    if manifest.get('network', {}).get('mode') != 'none':
        raise ValueError('browser preset requires network none')
    if manifest.get('credentials', {}).get('required'):
        raise ValueError('browser preset refuses credential broker')
    verify_policy()
    return profile


def validate_normalized(service, profile=PROFILE):
    """Validate Docker Compose normalized values, never caller declarations."""
    fields = preset_fields(profile)
    for name in ('cap_drop', 'cap_add'):
        if sorted(service.get(name) or []) != sorted(fields[name]):
            raise ValueError('browser normalized capability drift')
    opts = service.get('security_opt') or []
    # Compose accepts colon input and may normalize no-new-privileges to '='.
    normalized = [x.replace('no-new-privileges=', 'no-new-privileges:') for x in opts]
    if sorted(normalized) != sorted(fields['security_opt']):
        raise ValueError('browser normalized security options drift')
    if service.get('tmpfs') != fields['tmpfs']:
        raise ValueError('browser normalized tmpfs drift')
    for name in ('shm_size', 'pids_limit', 'mem_limit'):
        value = service.get(name)
        # Actual Compose JSON emits byte limits as decimal strings. Admit
        # only the exact canonical decimal or actual integer, never bool/float.
        if not ((type(value) is int and value == fields[name]) or
                (type(value) is str and value == str(fields[name]))):
            raise ValueError('browser normalized resource drift: ' + name)
    if service.get('user') != service_user(profile):
        raise ValueError('normalized profile user drift')
    if ((profile == PROFILE and service.get('network_mode') != 'none') or
            service.get('read_only') is not True or service.get('privileged')):
        raise ValueError('browser normalized isolation drift')
