#!/usr/bin/env python3
"""Run pre-signed probe: Apple APIs only, no dsmack/provider participation."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[2]
source = root / 'scripts/release/signed-app-attest-probe.enc.b64'
expected = (root / 'scripts/release/signed-app-attest-probe.sha256').read_text().strip()
version = subprocess.check_output(['sw_vers', '-productVersion'], text=True).strip()
if int(version.split('.')[0]) < 27:
    print(json.dumps({'result': 'unsupported_os', 'macOS27Required': True}))
    sys.exit(0)
if not os.environ.get('DSMACK_PROBE_TRANSPORT_KEY'):
    raise SystemExit('Temporary diagnostic transport key is missing')
out = root / 'local-data/signed-app-attest-probe'
out.mkdir(parents=True, exist_ok=False)
out.chmod(0o700)
archive = out / 'Probe.zip'
encrypted = out / 'Probe.enc'
encrypted.write_bytes(base64.b64decode(source.read_bytes(), validate=False))
subprocess.run(['openssl', 'enc', '-d', '-aes-256-cbc', '-pbkdf2', '-iter', '200000',
                '-pass', 'env:DSMACK_PROBE_TRANSPORT_KEY', '-in', str(encrypted),
                '-out', str(archive)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
os.environ.pop('DSMACK_PROBE_TRANSPORT_KEY', None)
if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
    raise SystemExit('Signed diagnostic archive hash mismatch')
subprocess.run(['sw_vers'], check=True)
subprocess.run(['uname', '-m'], check=True)
subprocess.run(['ditto', '-x', '-k', str(archive), str(out)], check=True)
app = out / 'Probe.app'
subprocess.run(['codesign', '--verify', '--strict', str(app)], check=True)
result = subprocess.run([str(app / 'Contents/MacOS/Probe'), '--attest', str(out / 'evidence')], timeout=120)
print(json.dumps({'stage': 'signed_probe_exit', 'returncode': result.returncode,
                  'networkEnrollmentSubmitted': False, 'archiveSHA256': expected}), flush=True)
sys.exit(0 if result.returncode == 0 else 1)
