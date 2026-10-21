#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / 'app-attest/contracts/fixtures/local-data/mutations'


def reason(encoded):
    b = bytes.fromhex(encoded.removeprefix('0x'))
    if b[:4] == bytes.fromhex('08c379a0'):
        size = int.from_bytes(b[36:68], 'big')
        return b[68:68+size].decode()
    return encoded


def solidity():
    env = dict(os.environ, FOUNDRY_TEST='../corpus/test')
    command = ['forge', 'test', '--offline', '--use', os.environ['SOLC'], '--gas-limit', '6000000000', '-vv']
    with (DATA/'forge.log').open('w') as log:
        subprocess.run(command, cwd=ROOT/'app-attest/contracts', env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
    verdicts = {}
    for line in (DATA/'forge.log').read_text().splitlines():
        m = re.search(r'VERDICT\|([^|]+)\|(ACCEPT|REJECT)\|(.*)', line)
        if m:
            ident, verdict, encoded = m.groups()
            assert ident not in verdicts, ident
            verdicts[ident] = dict(verdict=verdict, reason=reason(encoded.strip()) if encoded.strip() else '')
    cases = json.loads((DATA/'manifest.json').read_text())['cases']
    assert set(verdicts) == {c['id'] for c in cases}
    (DATA/'solidity.json').write_text(json.dumps(verdicts, indent=2)+'\n')
    print(f'Solidity: {len(verdicts)} verdicts, verdicts recorded', flush=True)


def circuit(checker, only, output):
    cases = json.loads((DATA/'manifest.json').read_text())['cases']
    cases = [c for c in cases if c['stage'] == 'leaf']
    if only:
        selected = set(only.split(','))
        cases = [c for c in cases if c['id'] in selected]
        assert {c['id'] for c in cases} == selected
    source = checker/'app-attest/circuit'
    files = sorted(list((source/'core').rglob('*.nr')) + list((source/'leaf/src').rglob('*.nr')) + [source/'check-leaf.sh',source/'prepare-leaf.py'])
    digest = lambda: hashlib.sha256(b''.join(str(p.relative_to(source)).encode()+b'\0'+p.read_bytes() for p in files)).hexdigest()
    fingerprint = digest()
    revision = subprocess.check_output(['git','rev-parse','HEAD'],cwd=checker,text=True).strip()
    (DATA/(Path(output).stem+'-run.json')).write_text(json.dumps(dict(revision=revision,source_sha256=fingerprint),indent=2)+'\n')
    compiled_fingerprint = None
    verdicts = {}
    (DATA/output).write_text('{}\n')
    failures = 0
    for case in cases:
        assert digest() == fingerprint, 'Checker sources changed during circuit run; rerun against a stable checker'
        ident = case['id']
        command = [str(source/'check-leaf.sh'), str(DATA/case['fixture'])]
        start = time.monotonic()
        with (DATA/(ident+'.circuit.log')).open('w') as log:
            run = subprocess.run(command, cwd=checker, stdout=log, stderr=subprocess.STDOUT)
        log = (DATA/(ident+'.circuit.log')).read_text()
        fingerprints = re.findall(r'CHECKER_TREE_SHA256=([0-9a-f]{64})', log)
        if fingerprints:
            assert len(fingerprints) == 1
            if compiled_fingerprint is None: compiled_fingerprint = fingerprints[0]
            assert fingerprints[0] == compiled_fingerprint, 'Compiled checker tree changed'
            (DATA/(Path(output).stem+'-run.json')).write_text(json.dumps(dict(revision=revision,source_sha256=fingerprint,compiled_tree_sha256=compiled_fingerprint),indent=2)+'\n')
        phase = 'witness'
        verdict = 'ACCEPT' if run.returncode == 0 else 'REJECT'
        if run.returncode:
            if 'Assertion failed:' in log and fingerprints:
                pass
            elif ident in ('cert-size','auth-long') and 'assert len(leaf) <= 4096 and len(auth) <= 1024' in log:
                phase = 'preparation capacity'
            else:
                phase, verdict = 'infrastructure', 'ERROR'
        sites = re.findall(r'┌─ core/src/([^:]+):(\d+):', log)
        message = re.search(r'Assertion failed: ([^\n]+)', log)
        site = [sites[0][0], int(sites[0][1]), message.group(1).strip()] if sites and message else None
        verdicts[ident] = dict(site=site, verdict=verdict, phase=phase, exit=run.returncode, seconds=round(time.monotonic()-start, 3))
        (DATA/output).write_text(json.dumps(verdicts,indent=2)+'\n')
        print(f"Circuit {ident}: {verdicts[ident]['verdict']} (exit {run.returncode})", flush=True)
        failures = failures + 1 if verdict == 'ERROR' else 0
        if failures == 3:
            raise RuntimeError('Three consecutive infrastructure failures; see ignored circuit logs')
    assert digest() == fingerprint, 'Checker sources changed during circuit run'



def main():
    p = argparse.ArgumentParser()
    p.add_argument('stage', choices=['solidity', 'circuit'])
    p.add_argument('--only')
    p.add_argument('--output',default='circuit.json')
    p.add_argument('--checker', type=Path, default=ROOT)
    a = p.parse_args()
    if a.stage == 'solidity': solidity()
    else: circuit(a.checker.resolve(), a.only, a.output)


if __name__ == '__main__':
    main()
