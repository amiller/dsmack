#!/usr/bin/env python3
"""Project already admitted, immutable base bytes into public generator inputs.

No Git fetch, candidate, install, model call or credential operation. The outer
admitter must supply a stable read-only base export, exact full tree manifest
and independently pinned specification digest. Output contains ONLY base/spec.
"""
import argparse
from pathlib import Path
import sys

from generate import canonical, sha, require, read_regular, MAX_INPUT, PUBLIC_NAMES, load_snapshot

# Trusted repository module, never selected from the source under inspection.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'bounty-recipes'))
from protocol import parse_json, tree_digest, scan_tree

SELECTED = ('apps/board/index.html', 'apps/board/logic.js', 'apps/board/ui.js')


def prepare(base, manifest, spec, expected_tree, expected_spec, output):
    admitted = parse_json(read_regular(manifest, 2*1024*1024), maximum=2*1024*1024)
    require(tree_digest(admitted) == expected_tree, 'independently pinned base tree')
    require(scan_tree(base) == admitted, 'base export differs from admitted manifest')
    spec_bytes = read_regular(spec, 65536)
    require(sha(spec_bytes) == expected_spec, 'independently pinned specification')
    spec_bytes.decode('utf-8', errors='strict')
    rows = {row['path']: row for row in admitted}
    selected = []
    for name in SELECTED:
        require(name in rows, 'missing admitted board asset')
        raw = read_regular(base/name, MAX_INPUT)
        require(len(raw) == rows[name]['bytes'] and sha(raw) == rows[name]['sha256'], 'base projection changed')
        selected.append({'path': name, 'content': raw.decode('utf-8', errors='strict')})
    base_bytes = canonical({'schema': 'dsmack-bounty-base-snapshot/1', 'files': selected})
    require(len(base_bytes)+len(spec_bytes) <= MAX_INPUT, 'projected public input bound')
    snapshot = {'schema': 'dsmack-bounty-generator-input/1', 'base_tree_sha256': expected_tree,
                'files': [{'name': name, 'size': len(raw), 'sha256': sha(raw)}
                          for name, raw in zip(PUBLIC_NAMES, (base_bytes, spec_bytes))]}
    # Exactly two files; the admission report is a sibling, outside the mount.
    output.mkdir(parents=True, exist_ok=False)
    (output/'base.json').write_bytes(base_bytes)
    (output/'spec.txt').write_bytes(spec_bytes)
    result = {'schema': 'dsmack-bounty-generation-preparation/1',
              'base_tree_sha256': expected_tree, 'spec_sha256': expected_spec,
              'snapshot_sha256': sha(canonical(snapshot)), 'selected_base_paths': list(SELECTED)}
    load_snapshot(output, result['snapshot_sha256'], expected_tree)
    output.with_name(output.name+'.preparation.json').write_bytes(canonical(result))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('base', 'manifest', 'spec', 'output'):
        parser.add_argument('--'+name, required=True, type=Path)
    parser.add_argument('--base-tree-sha256', required=True)
    parser.add_argument('--spec-sha256', required=True)
    args = parser.parse_args()
    print(canonical(prepare(args.base, args.manifest, args.spec, args.base_tree_sha256,
                            args.spec_sha256, args.output)).decode())


if __name__ == '__main__':
    main()
