#!/usr/bin/env python3
"""Export public iOS provisioning metadata without registered device identifiers."""
import argparse
import hashlib
import json
import plistlib
import subprocess
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('profile', type=Path)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
raw = args.profile.read_bytes()
p = plistlib.loads(subprocess.check_output(['security', 'cms', '-D', '-i', str(args.profile)]))
record = {
    'scope': 'local_provisioning_metadata_not_device_attestation',
    'profile_sha256': hashlib.sha256(raw).hexdigest(),
    'name': p.get('Name'), 'uuid': p.get('UUID'),
    'team': p.get('TeamIdentifier'), 'app_id_prefix': p.get('ApplicationIdentifierPrefix'),
    'platform': p.get('Platform'), 'created': p.get('CreationDate'),
    'expires': p.get('ExpirationDate'), 'entitlements': p.get('Entitlements'),
    'provisioned_device_count': len(p.get('ProvisionedDevices', [])),
    'provisions_all_devices': p.get('ProvisionsAllDevices', False),
    'developer_certificates': [
        {'sha1': hashlib.sha1(c).hexdigest(), 'sha256': hashlib.sha256(c).hexdigest()}
        for c in p.get('DeveloperCertificates', [])
    ],
}
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(json.dumps(record, indent=2, sort_keys=True, default=str) + '\n')
print(args.output)
