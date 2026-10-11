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
if result.returncode != 0:
    # Read only narrowly targeted launch diagnostics; emit enums, never log text,
    # profile identifiers, private device identifiers or unrelated runner events.
    predicate = ('eventMessage CONTAINS "Probe" AND '
                 '(process == "amfid" OR process == "kernel" OR process == "taskgated-helper")')
    try:
        diagnostic = subprocess.run(['log', 'show', '--last', '1m', '--style', 'json',
                                     '--predicate', predicate], capture_output=True, text=True, timeout=20)
    except subprocess.TimeoutExpired:
        diagnostic = subprocess.CompletedProcess([], 124, stdout='')
    findings = set()
    try:
        events = json.loads(diagnostic.stdout) if diagnostic.returncode == 0 else []
        for event in events:
            message = str(event.get('eventMessage', '')).lower()
            if 'provision' in message or 'profile' in message:
                findings.add('provisioning_mentioned')
            if 'signature' in message or 'codesign' in message or 'code sign' in message:
                findings.add('code_signing_mentioned')
            if 'launch constraint' in message:
                findings.add('launch_constraint_mentioned')
            if 'sip' in message or 'system integrity' in message:
                findings.add('system_integrity_mentioned')
    except (ValueError, AttributeError):
        findings.add('diagnostic_parse_unavailable')
    print(json.dumps({'stage': 'targeted_launch_diagnostic',
                      'findings': sorted(findings) or ['unknown'],
                      'diagnosticReturncode': diagnostic.returncode}), flush=True)
print(json.dumps({'stage': 'signed_probe_exit', 'returncode': result.returncode,
                  'networkEnrollmentSubmitted': False, 'archiveSHA256': expected}), flush=True)
sys.exit(0 if result.returncode == 0 else 1)
