#!/usr/bin/env python3
"""Update the measured compose runtime while retaining an existing guest kernel."""
import argparse
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--builder', default='dsmack-builder')
    args = parser.parse_args()
    base, out = args.base.resolve(), args.out.resolve()
    out.mkdir(mode=0o700)
    with (out/'build.log').open('wb') as log:
        subprocess.run(['docker', 'run', '--rm', '--cpus', '4', '--memory', '4g',
            '--network', 'none', '--mount', f'type=bind,src={out},dst=/w',
            '--mount', f'type=bind,src={HERE}/source,dst=/w/source,readonly',
            '--mount', f'type=bind,src={HERE}/update-runtime.sh,dst=/update.sh,readonly',
            '--mount', f'type=bind,src={base},dst=/prior-image,readonly',
            '--mount', f'type=bind,src={base},dst=/selected-templates,readonly',
            args.builder, 'bash', '/update.sh'], check=True, stdout=log,
            stderr=subprocess.STDOUT, timeout=900)
    print(out/'build/legs/diagnostic/files')


if __name__ == '__main__':
    main()
