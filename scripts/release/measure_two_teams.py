#!/usr/bin/env python3
"""Measure signed executables and require one M for honest builds, another for the modified one.
M is scripts/release/measure.py."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cd_args import args as cd_args  # noqa: E402
from measure import measure  # noqa: E402


def measure_args(a):
    h = lambda k: bytes.fromhex(a[k][2:])
    return '0x' + measure(h('cd'), h('page0'), h('ent'), a['linkeditCmd'], a['codeSigCmd']).hex()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--one', metavar='EXECUTABLE', help='print the measurement and CDHash of one signed executable')
    p.add_argument('--out', type=Path, help='directory for one JSON vector per build')
    p.add_argument('builds', nargs='*', metavar='NAME=EXECUTABLE', help='honest-a, honest-b, modified[, other-runner]')
    a = p.parse_args()
    if a.one:
        vector = cd_args(a.one)
        print('M      ' + measure_args(vector) + '\nCDHash ' + vector['cdhash'])
        return
    if not a.out or len(a.builds) not in (3, 4):
        p.error('--out and three or four NAME=EXECUTABLE builds are required')
    a.out.mkdir(parents=True, exist_ok=True)
    result = {}
    for spec in a.builds:
        name, path = spec.split('=', 1)
        vector = cd_args(path)
        vector['M'] = measure_args(vector)
        (a.out / f'{name}.json').write_text(json.dumps(vector, indent=1) + '\n')
        result[name] = {'M': vector['M'], 'cdhash': vector['cdhash']}
    (a.out / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
    (a.out / 'outputs.txt').write_text(''.join(f"{k.lower()}_{n.replace('-', '_')}={v[k]}\n"
                                               for n, v in result.items() for k in ('M', 'cdhash')))
    print(json.dumps(result, indent=2))
    ha, hb, mod = (result[k] for k in ('honest-a', 'honest-b', 'modified'))
    if not (ha['M'] == hb['M'] != mod['M']):
        raise SystemExit('Expected M(honest-a) == M(honest-b) != M(modified)')
    if len({ha['cdhash'], hb['cdhash'], mod['cdhash']}) != 3:
        raise SystemExit('Expected three different CDHashes')
    if 'other-runner' in result and result['other-runner']['M'] == ha['M']:
        raise SystemExit('Expected the compiled-in SDK runner CDHash to change M')
    print('measure-two-teams: pass')


if __name__ == '__main__':
    main()
