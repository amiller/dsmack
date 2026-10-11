#!/usr/bin/env python3
"""Rebuild in two isolated source paths and compare every unsigned bundle byte."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gui', action='store_true')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    dest = args.out.resolve()
    dest.mkdir(parents=True, exist_ok=False)
    manifests = []
    with tempfile.TemporaryDirectory(prefix='attest-repro-') as tmp:
        for name in ('short', 'a-deliberately-different-length-checkout'):
            tree = Path(tmp) / name
            # A local clone handles ordinary checkouts and Git worktrees alike.
            # Overlay current build inputs so uncommitted edits are measured too.
            subprocess.run(['git', 'clone', '--quiet', '--no-hardlinks', str(ROOT), str(tree)], check=True)
            for item in ('node/shared', 'node/mac', 'scripts/release', 'release'):
                shutil.copytree(ROOT / item, tree / item,
                                dirs_exist_ok=True,
                                ignore=shutil.ignore_patterns('build', '__pycache__', 'entitlements.plist'))
            build = dest / name
            subprocess.run([sys.executable, str(tree / 'scripts/release/build_mac.py'),
                            '--out', str(build), *(['--gui'] if args.gui else [])], check=True)
            manifests.append(json.loads((build / 'build-manifest.json').read_text()))
    same = manifests[0]['files'] == manifests[1]['files']
    report = {'schema': 1, 'unsigned_bundle_identical': same,
              'scope': 'two isolated source paths and module caches on one host; not independent builders',
              'files': manifests[0]['files'], 'toolchain': manifests[0]['toolchain']}
    (dest / 'reproducibility.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps(report, indent=2))
    if not same:
        raise SystemExit('Unsigned builds differ; release gate failed')


if __name__ == '__main__':
    main()
