"""Measured public envelope channel for credential-free browser-sandbox-v1 only.

This transports public task data. Existing private credentials remain on vde.
It is not authorization or the separate bounty public-input audit.
"""
import json
import os
from pathlib import Path
import stat
import sys
from dsmack_compose_contract.runtime_inputs import validate_runtime_inputs_bytes


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate public input key')
        value[key] = item
    return value


def read_regular(path, cap):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > cap:
            raise ValueError('public input type/size')
        value = bytearray()
        while len(value) <= cap:
            chunk = os.read(fd, min(1048576, cap + 1 - len(value)))
            if not chunk:
                break
            value.extend(chunk)
        if len(value) > cap:
            raise ValueError('public input byte cap')
        return bytes(value)
    finally:
        os.close(fd)


def choose(public_dir, manifest_path, private_dir):
    public_dir, manifest_path, private_dir = map(Path, (public_dir, manifest_path, private_dir))
    if not public_dir.exists() and not public_dir.is_symlink():
        return ''
    if public_dir.is_symlink() or not public_dir.is_dir():
        raise ValueError('public input channel type')
    # Supervisor already rejects static symlinks anywhere on the measured disk.
    # Here enforce the finite channel namespace against the actual manifest set.
    names = {p.name[:-len('.app-compose.json')] for p in manifest_path.parent.glob('*.app-compose.json')}
    if any(p.is_symlink() or not p.is_file() or p.name not in {n + '.envelope.json' for n in names}
           for p in public_dir.iterdir()):
        raise ValueError('unadmitted public envelope')
    name = manifest_path.name[:-len('.app-compose.json')]
    path = public_dir / (name + '.envelope.json')
    if not path.exists():
        return ''
    competing = private_dir / 'envelopes' / path.name
    if competing.exists() or competing.is_symlink():
        raise ValueError('competing private/public envelope')
    manifest_bytes = read_regular(manifest_path, 1048576)
    manifest = json.loads(manifest_bytes, object_pairs_hook=unique)
    compose = json.loads(manifest['docker_compose_file'], object_pairs_hook=unique)
    services = compose.get('services')
    if not isinstance(services, dict) or not services or any(
            service.get('security_profile') != 'browser-sandbox-v1'
            for service in services.values()):
        raise ValueError('public envelope requires browser preset')
    if manifest['network']['mode'] != 'none' or manifest.get('credentials', {}).get('required'):
        raise ValueError('public browser input requires credential-free network-none manifest')
    if manifest['allowed_envs'] or manifest['required_envs'] or any(
            entry.get('audience') != 'workload' for entry in manifest['allowed_files']):
        raise ValueError('public envelope refuses env/broker declarations')
    raw = read_regular(path, 33554432)
    envelope = json.loads(raw, object_pairs_hook=unique)
    if set(envelope) not in ({'runtime_input_version', 'manifest_sha256', 'files'},
                             {'runtime_input_version', 'manifest_sha256', 'files', 'commitments'}):
        raise ValueError('public envelope permits file values only')
    # The existing validator remains the only schema/digest authority. New
    # public commitments may cover ALL required workload files, never secrets
    # or an ambiguous selected subset. Legacy omission remains unchanged.
    validate_runtime_inputs_bytes(manifest_bytes, raw)
    if 'commitments' in envelope:
        slots = manifest['allowed_files']
        expected_scope = {'include': ['files'],
                          'file_slots': sorted(entry['slot'] for entry in slots)}
        commitment = envelope['commitments']
        if (not isinstance(commitment, dict) or not slots
                or any(entry.get('required') is not True for entry in slots)
                or commitment['alg'] != 'dsmack.task-commitment/3'
                or commitment['scope'] != expected_scope):
            raise ValueError('public commitment requires all required workload files only')
    return str(path)


def main():
    if len(sys.argv) != 4:
        raise ValueError('public input arguments')
    print(choose(*sys.argv[1:]))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        sys.stderr.write('DSMACK_PUBLIC_INPUTS_REFUSED\n')
        raise SystemExit(1)
