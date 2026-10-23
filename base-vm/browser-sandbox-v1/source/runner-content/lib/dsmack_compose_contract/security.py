"""Closed measured browser preset; no caller supplied security options."""
import hashlib
import os
import stat
from pathlib import Path

PROFILE = 'browser-sandbox-v1'
POLICY_SHA256 = 'cc3e61cabda6bbc1e53e54d27ba4d55a9d3be829b6dd1a596f4a7b31b1cc7849'
POLICY_PATH = '/usr/local/lib/dsmack/compose-runner/lib/dsmack_compose_contract/browser-sandbox-v1.json'


def verify_policy():
    path = Path(__file__).with_name('browser-sandbox-v1.json')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size != 12997:
            raise ValueError('browser policy type/size refused')
        data = os.read(fd, 12998)
        if len(data) != 12997 or hashlib.sha256(data).hexdigest() != POLICY_SHA256:
            raise ValueError('browser policy digest refused')
    finally:
        os.close(fd)


def preset_fields():
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
    if profile != PROFILE:
        raise ValueError('unknown security profile')
    if manifest.get('network', {}).get('mode') != 'none':
        raise ValueError('browser preset requires network none')
    if manifest.get('credentials', {}).get('required'):
        raise ValueError('browser preset refuses credential broker')
    verify_policy()
    return profile


def validate_normalized(service):
    """Validate Docker Compose normalized values, never caller declarations."""
    fields = preset_fields()
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
    if service.get('network_mode') != 'none' or service.get('read_only') is not True or service.get('privileged'):
        raise ValueError('browser normalized isolation drift')
