#!/usr/bin/env python3
"""Record exact bundle bytes and public signing metadata on the build Mac.

This is a local build record, NOT a remotely attested code measurement.
"""
import argparse
import base64
import hashlib
import json
import plistlib
import subprocess
import tempfile
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('app', type=Path)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
app = args.app.resolve()
if not app.is_dir():
    parser.error('app bundle does not exist')

def run(*command):
    result = subprocess.run(command, capture_output=True, check=True)
    return (result.stdout + result.stderr).decode(errors='replace')

files = []
for path in sorted(app.rglob('*')):
    if path.is_symlink():
        raise SystemExit(f'Refusing symlink in evidence manifest: {path.relative_to(app)}')
    if path.is_file():
        files.append({'path': str(path.relative_to(app)), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                      'size': path.stat().st_size})
info = plistlib.loads((app / 'Info.plist').read_bytes())
certificates = []
with tempfile.TemporaryDirectory(prefix='appattest-signers-') as directory:
    prefix = str(Path(directory) / 'signer-')
    subprocess.run(['codesign', '-d', '--extract-certificates=' + prefix, str(app)],
                   capture_output=True, check=True)
    for certificate in sorted(Path(directory).glob('signer-*')):
        raw = certificate.read_bytes()
        certificates.append({'index': int(certificate.name.split('-')[-1]),
                             'sha256': hashlib.sha256(raw).hexdigest(),
                             'der_base64': base64.b64encode(raw).decode()})
profile = {}
if (app / 'embedded.mobileprovision').exists():
    raw = subprocess.check_output(['security', 'cms', '-D', '-i', str(app / 'embedded.mobileprovision')])
    decoded = plistlib.loads(raw)
    # Deliberately omit ProvisionedDevices and other personal/device details.
    profile = {k: decoded.get(k) for k in ('Name', 'UUID', 'TeamIdentifier', 'ApplicationIdentifierPrefix', 'ExpirationDate')}
    profile['entitlements'] = decoded.get('Entitlements', {})
record = {'format': 'ios-app-attest-build-manifest/v1', 'evidence_origin': 'local_build_unattested',
          'bundle_id': info.get('CFBundleIdentifier'), 'bundle_version': info.get('CFBundleVersion'),
          'files': files, 'codesign': run('codesign', '-d', '--verbose=4', str(app)),
          'signed_entitlements': run('codesign', '-d', '--entitlements', ':-', str(app)),
          'signing_certificates': certificates,
          'profile': profile, 'xcode': run('xcodebuild', '-version')}
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(json.dumps(record, indent=2, sort_keys=True, default=str) + '\n')
print(args.output)
