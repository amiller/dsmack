#!/usr/bin/env python3
"""Prepare, but never publish, a release-owner-qualified native update recommendation."""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import plistlib
import re
import zipfile


def recommendation(archive, tag, expiry, previous, rollback, evidence, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    if not re.fullmatch(r'native-v[0-9][A-Za-z0-9._-]{0,63}', tag):
        raise ValueError('tag must be an immutable native-v release tag')
    if not re.fullmatch(r'[A-Za-z0-9._-]+\.zip', archive.name):
        raise ValueError('archive must have a plain ZIP filename')
    expires = dt.datetime.fromisoformat(expiry.replace('Z', '+00:00'))
    if expires.tzinfo is None or not now < expires <= now + dt.timedelta(days=7):
        raise ValueError('recommendation must expire within seven days')
    if not evidence.startswith('https://github.com/amiller/dsmack/') or '?' in evidence or '#' in evidence:
        raise ValueError('evidence must identify the public release review in amiller/dsmack')
    if not previous or len(previous) > 32 or len(rollback) > 32 or len(set(previous)) != len(previous) or len(set(rollback)) != len(rollback):
        raise ValueError('previous and rollback build lists must be bounded and unique')
    size = archive.stat().st_size
    if not 0 < size <= 250_000_000:
        raise ValueError('archive size is outside the native updater limit')
    with zipfile.ZipFile(archive) as z:
        def read(name):
            entries = [entry for entry in z.infolist() if entry.filename == name]
            if len(entries) != 1 or not 0 < entries[0].file_size <= 65536:
                raise ValueError('missing, duplicate or oversized release metadata')
            return z.read(entries[0])
        metadata = json.loads(read('Node.app/Contents/Resources/dsmack-release.json'))
        info = plistlib.loads(read('Node.app/Contents/Info.plist'))
    if metadata.get('format') != 1 or metadata.get('profile') != 'native-v2':
        raise ValueError('unsupported native profile')
    build, version = metadata['build'], metadata['version']
    if type(build) is not int or not 0 < build <= 2147483647 or not re.fullmatch(r'[0-9][A-Za-z0-9._-]{0,63}', version):
        raise ValueError('invalid version or build')
    if info.get('CFBundleVersion') != str(build) or info.get('CFBundleShortVersionString') != version:
        raise ValueError('bundle version differs from sealed metadata')
    if any(type(n) is not int or not 0 <= n < build for n in previous + rollback):
        raise ValueError('prior builds must be lower than the new build')
    keys = {'chainId', 'registry', 'category', 'protocolVersion', 'relay', 'rpc', 'peer', 'badges', 'accountFactory'}
    if set(metadata['network']) != keys or not all(isinstance(v, str) for v in metadata['network'].values()):
        raise ValueError('incomplete network profile')
    h = hashlib.sha256()
    with archive.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    digest = h.hexdigest()
    return {'format': 1, 'tag': tag, 'version': version, 'build': build,
            'archive': f'https://github.com/amiller/dsmack/releases/download/{tag}/{archive.name}',
            'sha256': digest, 'bytes': size, 'expires': expires.isoformat(timespec='seconds').replace('+00:00', 'Z'),
            'network': metadata['network'], 'previousBuilds': previous, 'rollbackBuilds': rollback,
            'qualification': 'release-owner-qualified', 'evidence': evidence}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--archive', required=True, type=Path)
    p.add_argument('--tag', required=True)
    p.add_argument('--expires', required=True)
    p.add_argument('--previous-build', action='append', type=int, required=True)
    p.add_argument('--rollback-build', action='append', type=int, default=[])
    p.add_argument('--evidence', required=True)
    p.add_argument('--owner-qualified', action='store_true', required=True,
                   help='assert exact signed artifact/admission/upgrade acceptance was reviewed; this tool does not perform it')
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    result = recommendation(a.archive, a.tag, a.expires, a.previous_build, a.rollback_build, a.evidence)
    with a.output.open('x') as f:
        json.dump(result, f, indent=2, sort_keys=True)
        f.write('\n')


if __name__ == '__main__':
    main()
