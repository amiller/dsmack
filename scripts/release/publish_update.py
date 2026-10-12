#!/usr/bin/env python3
"""Write updates.json for a node release ZIP: {version, tag, url, sha256, M, notes}.
M is measured from Node.app/Contents/MacOS/node inside the ZIP (scripts/release/measure.py).
Publishes nothing; attach the output to the node-vX.Y.Z release beside the ZIP."""
import argparse, hashlib, json, plistlib, re, sys, tempfile, zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from measure import inputs, measure  # noqa: E402

REPOSITORY = 'amiller/dsmack'


def feed(archive, tag, notes):
    m = re.fullmatch(r'node-v([0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4})', tag)
    if not m: raise ValueError('tag must be node-vX.Y.Z')
    if not re.fullmatch(r'[A-Za-z0-9._-]+\.zip', archive.name): raise ValueError('archive must have a plain .zip name')
    with zipfile.ZipFile(archive) as z, tempfile.TemporaryDirectory() as tmp:
        version = plistlib.loads(z.read('Node.app/Contents/Info.plist'))['CFBundleShortVersionString']
        if version != m.group(1): raise ValueError(f'Info.plist version {version} does not match {tag}')
        exe = Path(tmp) / 'node'; exe.write_bytes(z.read('Node.app/Contents/MacOS/node'))
        M = '0x' + measure(**inputs(exe)).hex()
    return {'version': version, 'tag': tag, 'url': f'https://github.com/{REPOSITORY}/releases/download/{tag}/{archive.name}',
            'sha256': hashlib.sha256(archive.read_bytes()).hexdigest(), 'M': M, 'notes': notes}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--archive', type=Path, required=True, help='Node ZIP from tools/native_update_archive.py')
    p.add_argument('--tag', required=True)
    p.add_argument('--notes', default='')
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    result = feed(a.archive, a.tag, a.notes)
    a.output.write_text(json.dumps(result, indent=1, sort_keys=True) + '\n')
    print(json.dumps(result, indent=1, sort_keys=True))


if __name__ == '__main__':
    main()
