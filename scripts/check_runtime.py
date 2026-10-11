#!/usr/bin/env python3
"""Check installed runtime and OpenSSL using an independent historical fixture.

This is not a new device capture. Run from the ios-app-attest directory.
"""
import json
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from verifier.core import Policy, unb64, verify_attestation
from verifier.server import ROOT, create_app

root = Path(__file__).resolve().parents[1]
fixture = json.loads((root / 'tests/fixtures/uebelack-development.json').read_text())
policy = Policy('V8H6LQ9448.io.uebelacker.AppAttestExample')
verify_attestation(unb64(fixture['attestation']), fixture['keyId'], unb64(fixture['challenge']),
                   policy, ROOT.read_bytes(),
                   at_time=datetime(2024, 6, 1, tzinfo=timezone.utc).timestamp())
with tempfile.TemporaryDirectory() as directory:
    response = create_app(policy, Path(directory) / 'smoke.sqlite').test_client().get('/health')
    assert response.status_code == 200
    assert response.get_json()['evidence_origin'] == 'apple_root'
    assert response.get_json()['fixed_code_verified'] is False
print(json.dumps({'python': sys.version.split()[0],
                  'openssl': subprocess.check_output(['openssl', 'version'], text=True).strip(),
                  'historical_fixture_verified': True, 'service_smoke_passed': True,
                  'fresh_device_capture': False}, indent=2))
