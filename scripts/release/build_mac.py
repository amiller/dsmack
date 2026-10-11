#!/usr/bin/env python3
"""Build the Mac peer without credentials; record exact inputs and unsigned outputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCES = ['node/shared/Protocol.swift', 'node/shared/PersonalAccount.swift', 'node/shared/BadgeClaim.swift', 'node/shared/Upgrade.swift', 'node/shared/Chain.swift',
           'node/shared/NativeAttestation.swift', 'node/shared/Node.swift', 'node/mac/main.swift',
           'node/mac/GUI.swift', 'node/mac/NetworkConfig.swift']


def output(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gui', action='store_true', help='Build the persistent menu-bar participant')
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--bundle-id', default='dev.dsmack.provider')
    parser.add_argument('--version', default='0.1.0')
    parser.add_argument('--build-number', default='3')
    args = parser.parse_args()
    lock = json.loads((ROOT / 'release/toolchain.json').read_text())
    actual = {'xcode': output('xcodebuild', '-version'),
              'sdk_version': output('xcrun', '--sdk', 'macosx', '--show-sdk-version'),
              'sdk_build': output('xcrun', '--sdk', 'macosx', '--show-sdk-build-version'),
              'swift': output('xcrun', 'swiftc', '--version').split('\nTarget:')[0]}
    for key in actual:
        if actual[key] != lock[key]:
            raise SystemExit(f'Toolchain mismatch for {key}: {actual[key]!r}; expected {lock[key]!r}')
    dest = args.out.resolve()
    dest.mkdir(parents=True, exist_ok=False)
    app = dest / 'Node.app'
    executable = app / 'Contents/MacOS/node'
    executable.parent.mkdir(parents=True)
    info = plistlib.loads((ROOT / 'node/mac/Info.plist').read_bytes())
    info.update(CFBundleIdentifier=args.bundle_id, CFBundleShortVersionString=args.version,
                CFBundleVersion=args.build_number)
    (app / 'Contents/Info.plist').write_bytes(plistlib.dumps(info, sort_keys=True))
    artwork_inputs = ['artwork/fold/token-1.png', 'artwork/fold/gabe-token-2.png'] if args.gui else []
    if args.gui:
        resources = app / 'Contents/Resources'
        resources.mkdir()
        for number, source in enumerate(artwork_inputs, 1):
            shutil.copyfile(ROOT / source, resources / f'fold-token-{number}.png')
    sdk = output('xcrun', '--sdk', 'macosx', '--show-sdk-path')
    # Stable module name, relative source names and path remapping. No debug data,
    # provisioning profile or developer signature belongs in this comparison.
    flags = ['-O', '-whole-module-optimization', '-module-name', 'AttestNode',
             '-target', 'arm64-apple-macos27.0', '-framework', 'DeviceCheck', '-D', 'HONEST',
             '-file-prefix-map', f'{ROOT}=/src', '-debug-prefix-map', f'{ROOT}=/src',
             '-Xlinker', '-no_adhoc_codesign']
    if args.gui:
        flags += ['-D', 'GUI', '-framework', 'AppKit']
    with tempfile.TemporaryDirectory(prefix='attest-module-cache-') as cache:
        subprocess.run(['xcrun', 'swiftc', '-sdk', sdk, '-module-cache-path', cache,
                        *flags, *SOURCES, '-o', str(executable)], cwd=ROOT, check=True,
                       env={**os.environ, 'LC_ALL': 'C', 'TZ': 'UTC'})
    tracked_inputs = SOURCES + ['node/mac/Info.plist', 'scripts/release/build_mac.py',
                               'release/toolchain.json'] + artwork_inputs
    record = {'schema': 1, 'kind': 'unsigned-build', 'flavor': 'gui' if args.gui else 'cli', 'toolchain': actual,
              'source_commit': output('git', 'rev-parse', 'HEAD'),
              'dirty_build_inputs': bool(output('git', 'status', '--porcelain', '--untracked-files=normal', '--', *tracked_inputs)),
              'inputs': {p: digest(ROOT / p) for p in tracked_inputs},
              'compiler_flags': [v.replace(str(ROOT), '/src') for v in flags],
              'bundle_id': args.bundle_id, 'version': args.version, 'build_number': args.build_number,
              'files': {str(p.relative_to(app)): digest(p) for p in sorted(app.rglob('*')) if p.is_file()}}
    (dest / 'build-manifest.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
    print(json.dumps(record['files'], indent=2))


if __name__ == '__main__':
    main()
