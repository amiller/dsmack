#!/usr/bin/env python3
import copy
import json
import subprocess
from pathlib import Path
from runpy import run_path

base = Path(__file__).resolve().parent
prepare = run_path(str(base / 'prepare-leaf.py'))['prepare']
fixture = json.loads((base / 'proofs/leaf/real-apple.json').read_text())
w = prepare(fixture)
public = [int(v) for v in w['public']]
cases = {}
for index, name in [(0, 'public-rp'), (10, 'leaf-before'), (11, 'leaf-after'),
                    (16, 'key-binding-x'), (19, 'key-binding-y'), (22, 'subject-hash')]:
    f = copy.deepcopy(fixture)
    f['public_inputs'] = public.copy()
    f['public_inputs'][index] ^= 1
    cases[name] = f
# Use the negated CA point: a valid P384 point, bound consistently to public fields.
f = copy.deepcopy(fixture)
y = int.from_bytes(bytes(w['intermediate_y']), 'big')
p = int('fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff', 16)
y = (p-y).to_bytes(48, 'big')
f['intermediate_y'] = y.hex()
f['public_inputs'] = public.copy()
f['public_inputs'][19:22] = [int.from_bytes(y[i:i+16], 'big') for i in range(0, 48, 16)]
cases['wrong-intermediate-key'] = f
out = base / 'proofs/leaf/negative'
out.mkdir(parents=True, exist_ok=True)
for name, f in cases.items():
    path = out / (name + '.json')
    path.write_text(json.dumps(f))
    r = subprocess.run([str(base / 'check-leaf.sh'), str(path)], capture_output=True, text=True)
    log = r.stdout + r.stderr
    (out / (name + '.log')).write_text(log)
    assert r.returncode != 0 and 'error: Assertion failed:' in log and 'Failed assertion' in log, (name, r.returncode, log[-2000:])
    print(name, 'rejected', flush=True)
