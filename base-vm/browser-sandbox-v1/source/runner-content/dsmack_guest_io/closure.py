"""Trusted supervisor publication closure; no console-derived facts are admitted."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

PREFIX = b'DSMACK_RESULT_CLOSED_V1 '

def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode('ascii')

def unique(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError('duplicate key')
        out[key] = value
    return out

def selector(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', value) or value in ('.', '..'):
        raise ValueError('selector')
    return value

def context(path, manifests):
    with open(path, "rb") as stream:
        raw = stream.read(8193)
    return context_bytes(raw, manifests)

def context_bytes(raw, manifests):
    if len(raw) > 8192:
        raise ValueError('context bound')
    value = json.loads(raw, object_pairs_hook=unique)
    if set(value) != {'schema', 'attempt_id', 'selectors'} or value['schema'] != 'dsmack-result-closure-context/1':
        raise ValueError('context schema')
    if not isinstance(value['attempt_id'], str) or not re.fullmatch('[0-9a-f]{32}', value['attempt_id']):
        raise ValueError('attempt_id')
    names = value['selectors']
    if not isinstance(names, list) or not 1 <= len(names) <= 32 or names != sorted(set(selector(x) for x in names)):
        raise ValueError('selectors')
    actual = sorted(p.name[:-len('.app-compose.json')] for p in Path(manifests).glob('*.app-compose.json'))
    if actual != names or raw != canonical(value):
        raise ValueError('context manifest binding/canonical bytes')
    return {'attempt_context_sha256': hashlib.sha256(raw).hexdigest(), 'expected': names, 'selectors': []}

def collect(state, root, name, run_id):
    selector(name)
    if name not in state['expected'] or any(x['selector'] == name for x in state['selectors']):
        raise ValueError('unexpected/duplicate export')
    if not isinstance(run_id, str) or not re.fullmatch(r'[\x21-\x7e]{1,128}', run_id):
        raise ValueError('run_id')
    base = Path(root) / name
    if (base / 'outputs/EXPORT-COMPLETE').read_bytes() != b'dsmack-export/1\n':
        raise ValueError('marker')
    receipt = (base / 'receipt.json').read_bytes()
    parsed = json.loads(receipt, object_pairs_hook=unique)
    if parsed.get('run_id') != run_id:
        raise ValueError('receipt run_id')
    index = (base / 'outputs/index.json').read_bytes()
    state['selectors'].append(dict(selector=name, run_id=run_id, receipt_sha256=hashlib.sha256(receipt).hexdigest(), index_sha256=hashlib.sha256(index).hexdigest()))

def frame(state):
    entries = sorted(state['selectors'], key=lambda x: x['selector'])
    if [x['selector'] for x in entries] != state['expected']:
        raise ValueError('missing selector')
    result = PREFIX + canonical(dict(schema='dsmack-result-closure/1', attempt_context_sha256=state['attempt_context_sha256'], result_device='vdd', closure='synced-unmounted', selectors=entries)) + b'\n'
    if len(result) > 16384:
        raise ValueError('frame bound')
    return result

def close(state, mountpoint, run=subprocess.run):
    result = frame(state)  # build before closing, emit only after ALL checked steps
    run(['/bin/busybox', 'sync'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    run(['/bin/busybox', 'umount', mountpoint], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    run(['/bin/busybox', 'sync'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return result

def diagnostic(stream, output):
    # Each chunk is independently encoded BEFORE framing; partial reads/writes,
    # CR, Unicode separators and NUL cannot introduce a raw trusted prefix.
    while True:
        chunk = stream.read(1024)
        if not chunk:
            return
        output.write(b'DSMACK_DIAGNOSTIC hex=' + chunk.hex().encode('ascii') + b'\n')
        output.flush()

def main():
    mode, *args = sys.argv[1:]
    if mode == 'diagnostic':
        diagnostic(sys.stdin.buffer, sys.stdout.buffer)
        return
    statefile = Path(args[0])
    if mode == 'prepare':
        state = context(args[1], args[2])
    else:
        state = json.loads(statefile.read_bytes(), object_pairs_hook=unique)
        if mode == 'collect':
            collect(state, *args[1:])
        elif mode == 'close':
            sys.stdout.buffer.write(close(state, args[1]))
            sys.stdout.buffer.flush()
            return
        else:
            raise ValueError('mode')
    statefile.write_bytes(canonical(state))

if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Never relay exception details or untrusted values to console.
        sys.stderr.write('DSMACK_CLOSURE_REFUSED\n')
        sys.exit(1)
