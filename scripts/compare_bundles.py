#!/usr/bin/env python3
"""Compare exact bytes of two local bundles; this is not an attestation claim."""
import argparse
import hashlib
import json
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('first', type=Path)
parser.add_argument('second', type=Path)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()

def manifest(folder):
    if not folder.is_dir():
        parser.error(f'Bundle missing: {folder}')
    result = {}
    for path in sorted(folder.rglob('*')):
        if path.is_symlink():
            parser.error(f'Symlink requires explicit comparison policy: {path}')
        if path.is_file():
            result[str(path.relative_to(folder))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result

first, second = manifest(args.first), manifest(args.second)
differences = [p for p in sorted(first.keys() | second.keys()) if first.get(p) != second.get(p)]
result = {'scope': 'local_bundle_byte_comparison_only', 'first': first, 'second': second,
          'different_files': differences, 'byte_identical': not differences}
args.output.write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({'files_compared': len(first), 'byte_identical': not differences,
                  'different_files': differences}, indent=2))
