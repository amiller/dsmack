#!/usr/bin/env python3
"""Internal stdin bridge AFTER Node authenticates original report/output bytes.

Not a verifier endpoint or accepted external evidence format. No file paths,
commands, imports or success callbacks come from stdin. No authority files read.
"""
import base64
import importlib.util
import json
from pathlib import Path
import sys

path = Path(__file__).resolve().parents[1] / 'bounty-judges' / 'closure.py'
spec = importlib.util.spec_from_file_location('bounty_closed_join', path)
c = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = c
# -B prevents cache writes, not reads. Execute the selected source bytes rather
# than allowing a timestamp-valid preexisting .pyc to replace the reviewed join.
source = path.read_bytes()
exec(compile(source, str(path), 'exec'), c.__dict__)


def main():
    raw = sys.stdin.buffer.read(192*1024*1024+1)
    c.require(len(raw) <= 192*1024*1024, 'internal join input size')
    value = json.loads(raw)
    c.keys(value, {'expected', 'results_b64', 'outputs'})
    results = base64.b64decode(value['results_b64'], validate=True)
    outputs = value['outputs']
    c.require(type(outputs) is dict and set(outputs) == set(c.STAGES), 'closed internal outputs')

    def original(pin, evidence_digest):
        output = outputs[pin['stage_id']]
        c.keys(output, {'manifest_b64', 'files', 'workload_status', 'report_sha256'})
        c.require(output['report_sha256'] == evidence_digest, 'original report digest')
        return c.VerifiedOutputs(base64.b64decode(output['manifest_b64'], validate=True),
                                 {k: base64.b64decode(v, validate=True)
                                  for k, v in output['files'].items()},
                                 output['workload_status'])

    result = c.join(results, value['expected'], original)
    sys.stdout.buffer.write(c.canonical(result))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Never forward private paths, source contents or arbitrary check text.
        sys.stderr.write('closed acceptance join refused\n')
        sys.exit(2)
