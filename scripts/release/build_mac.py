#!/usr/bin/env python3
"""Build the Mac peer without credentials; record exact inputs and unsigned outputs.
--sdk-runner compiles a signed runner's CDHash (runner/sign.sh <out>/cdhash.txt) into the node in place of the empty
node/shared/SDKRunners.swift, so M covers which runner may take app roots. Sign the runner first."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCES = ['node/shared/Protocol.swift', 'node/shared/NativeDirectory.swift', 'node/shared/PersonalAccount.swift', 'node/shared/BadgeClaim.swift', 'node/shared/Upgrade.swift', 'node/shared/Chain.swift',
           'node/shared/NativeAttestation.swift', 'node/shared/Node.swift', 'node/shared/SDK.swift', 'node/shared/SDKRunners.swift', 'node/shared/AppAttestVerify.swift', 'node/shared/Measure.swift', 'node/mac/main.swift',
           'node/mac/GUI.swift', 'node/mac/NetworkConfig.swift', 'node/mac/UpdatePolicy.swift',
           'node/mac/UpdateArchive.swift', 'node/mac/NativeUpdater.swift']


def output(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sdk_runners_source(cdhashes):
    if not all(re.fullmatch(r'[0-9a-f]{64}', c) for c in cdhashes):
        raise SystemExit('--sdk-runner takes a full SHA-256 CDHash, 64 lowercase hex')
    committed = (ROOT / 'node/shared/SDKRunners.swift').read_text()
    return committed.replace('let compiledSDKRunners: [String] = []', f'let compiledSDKRunners: [String] = {json.dumps(cdhashes)}')


def entitlements(team, bundle_id):
    if not re.fullmatch(r'[A-Z0-9]{10}', team) or not re.fullmatch(r'[A-Za-z0-9.-]+', bundle_id):
        raise SystemExit('Team ID must be 10 uppercase letters or digits; bundle ID letters, digits, dots, hyphens')
    template = (ROOT / 'node/mac/Entitlements.template.plist').read_text()
    return template.replace('TEAM_ID', team).replace('BUNDLE_ID', bundle_id)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gui', action='store_true', help='Build the persistent menu-bar participant')
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--bundle-id', default='dev.dsmack.provider')
    parser.add_argument('--team', help='Also write entitlements.plist for this Apple Team ID beside Node.app')
    parser.add_argument('--modified', action='store_true', help='Negative control: build the MODIFIED variant')
    parser.add_argument('--version', default='0.3.0')
    parser.add_argument('--build-number', default='6')
    parser.add_argument('--sdk-runner', action='append', default=[], metavar='CDHASH',
                        help='Admit this signed runner to the SDK port (compiled in; without it the SDK stays off)')
    args = parser.parse_args()
    lock = json.loads((ROOT / 'node/mac/toolchain.json').read_text())
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
    artwork_inputs = ['node/mac/assets/fold-token-1.png', 'node/mac/assets/fold-token-2.png'] if args.gui else []
    if args.gui:
        resources = app / 'Contents/Resources'
        resources.mkdir()
        network_source = (ROOT / 'node/mac/NetworkConfig.swift').read_text()
        network_match = re.search(r'#"""\s*(\{.*?\})\s*"""#', network_source, re.S)
        if not network_match:
            raise SystemExit('Release network metadata is missing')
        network_settings = json.loads(network_match.group(1))
        network_keys = ('chainId', 'registry', 'category', 'protocolVersion', 'relay',
                        'rpc', 'peer', 'badges', 'accountFactory', 'measurementRegistry')
        # Resource sealing authenticates these pins alongside the executable.
        release_metadata = {'format': 1, 'profile': 'native-v2', 'build': int(args.build_number),
                            'version': args.version, 'sourceCommit': output('git', 'rev-parse', 'HEAD'),
                            'network': {key: str(network_settings[key]) for key in network_keys},
                            'sdkRunners': args.sdk_runner}
        (resources / 'dsmack-release.json').write_text(json.dumps(release_metadata, sort_keys=True) + '\n')
        for number, source in enumerate(artwork_inputs, 1):
            shutil.copyfile(ROOT / source, resources / f'fold-token-{number}.png')
    sdk = output('xcrun', '--sdk', 'macosx', '--show-sdk-path')
    # Stable module name, relative source names and path remapping. No debug data,
    # provisioning profile or developer signature belongs in this comparison.
    flags = ['-O', '-whole-module-optimization', '-module-name', 'AttestNode',
             '-target', 'arm64-apple-macos27.0', '-framework', 'DeviceCheck', '-D', 'MODIFIED' if args.modified else 'HONEST',
             '-file-prefix-map', f'{ROOT}=/src', '-debug-prefix-map', f'{ROOT}=/src',
             '-Xlinker', '-no_adhoc_codesign']
    if args.gui:
        flags += ['-D', 'GUI', '-framework', 'AppKit']
    runners_source = sdk_runners_source(args.sdk_runner)
    with tempfile.TemporaryDirectory(prefix='attest-module-cache-') as cache, tempfile.TemporaryDirectory(prefix='attest-sdk-runners-') as gen:
        # The generated file compiles under the committed file's remapped path, so the builder's temp path never matters.
        generated = Path(gen) / 'SDKRunners.swift'
        generated.write_text(runners_source)
        sources = [str(generated) if p == 'node/shared/SDKRunners.swift' else p for p in SOURCES]
        subprocess.run(['xcrun', 'swiftc', '-sdk', sdk, '-module-cache-path', cache,
                        *flags, '-file-prefix-map', f'{gen}=/src/node/shared', '-debug-prefix-map', f'{gen}=/src/node/shared',
                        *sources, '-o', str(executable)], cwd=ROOT, check=True,
                       env={**os.environ, 'LC_ALL': 'C', 'TZ': 'UTC'})
    if args.team:
        (dest / 'entitlements.plist').write_text(entitlements(args.team, args.bundle_id))
    tracked_inputs = SOURCES + ['node/mac/Info.plist', 'node/mac/Entitlements.template.plist', 'scripts/release/build_mac.py',
                               'node/mac/toolchain.json'] + artwork_inputs
    record = {'schema': 1, 'kind': 'unsigned-build', 'flavor': 'gui' if args.gui else 'cli', 'toolchain': actual,
              'source_commit': output('git', 'rev-parse', 'HEAD'),
              'dirty_build_inputs': bool(output('git', 'status', '--porcelain', '--untracked-files=normal', '--', *tracked_inputs)),
              'inputs': {p: digest(ROOT / p) for p in tracked_inputs},
              'sdk_runners': args.sdk_runner, 'compiled_sdk_runners_sha256': hashlib.sha256(runners_source.encode()).hexdigest(),
              'compiler_flags': [v.replace(str(ROOT), '/src') for v in flags],
              'bundle_id': args.bundle_id, 'team': args.team, 'version': args.version, 'build_number': args.build_number,
              'files': {str(p.relative_to(app)): digest(p) for p in sorted(app.rglob('*')) if p.is_file()}}
    (dest / 'build-manifest.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
    print(json.dumps(record['files'], indent=2))


if __name__ == '__main__':
    main()
