#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
root=$(cd ../../.. && pwd)
work=$(mktemp -d /tmp/dsmack-staging-controls.XXXXXXXX)
# Retain fixtures: uncertain application names are never automatically removed.
python3 make_repro.py "$root" "$work/main.swift"
swiftc "$work/main.swift" -o "$work/staging-controls"
python3 - "$work" <<'PY'
import json, subprocess, sys
from pathlib import Path
work=Path(sys.argv[1])
for case in ['partial','length','digest','readback','readthrow','sync']:
    dest=work/case
    p=subprocess.run([str(work/'staging-controls'),case,str(dest)],capture_output=True,text=True)
    print(p.stdout,end=''); print(p.stderr,end='',file=sys.stderr)
    assert p.returncode == 0, (case,p.returncode)
    records=[json.loads(line) for line in p.stderr.splitlines()]
    assert records and all(r['schema']=='dsmack-host-residue/1' and r['status']=='deferred-unconfirmed' and r['residue_free_confirmed'] is False and str(dest/'staged') in r['possible_paths'] for r in records), records
print('STAGING FAULT CONTROLS ALL PASS; retained fixtures:',work)
PY
