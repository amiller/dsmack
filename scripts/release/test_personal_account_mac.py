#!/usr/bin/env python3
"""Run personal-account crypto vectors and a signed, isolated Mac Keychain test.
Unlock your signing keychain separately. No password argument or secret export.
The profile/entitlements must authorize the supplied bundle identifier.
"""
import argparse
import json
from pathlib import Path
import plistlib
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--identity', required=True)
    p.add_argument('--keychain', type=Path, required=True)
    p.add_argument('--profile', type=Path, required=True)
    p.add_argument('--entitlements', type=Path, required=True)
    p.add_argument('--bundle-id', required=True)
    args = p.parse_args()
    dest = args.out.resolve()
    dest.mkdir(parents=True, exist_ok=False)
    common = [str(ROOT / 'node/shared/Protocol.swift'), str(ROOT / 'node/shared/PersonalAccount.swift')]
    vectors = dest / 'vectors'
    subprocess.run(['xcrun', 'swiftc', '-O', *common,
                    str(ROOT / 'node/tests/PersonalAccountVectors.swift'), '-o', str(vectors)], check=True)
    vector_result = json.loads(subprocess.check_output([str(vectors)], text=True))
    app = dest / 'KeychainTest.app'
    binary = app / 'Contents/MacOS/test'
    binary.parent.mkdir(parents=True)
    subprocess.run(['xcrun', 'swiftc', '-O', *common,
                    str(ROOT / 'node/tests/PersonalAccountKeychain.swift'), '-o', str(binary)], check=True)
    (app / 'Contents/Info.plist').write_bytes(plistlib.dumps({
        'CFBundleIdentifier': args.bundle_id, 'CFBundleExecutable': 'test',
        'CFBundleName': 'Personal Account Keychain Test', 'CFBundlePackageType': 'APPL'}))
    shutil.copy2(args.profile, app / 'Contents/embedded.provisionprofile')
    subprocess.run(['codesign', '--force', '--options', 'runtime', '--sign', args.identity,
                    '--keychain', str(args.keychain), '--entitlements', str(args.entitlements),
                    '--generate-entitlement-der', '--timestamp=none', str(app)], check=True)
    subprocess.run(['codesign', '--verify', '--strict', str(app)], check=True)
    keychain_result = subprocess.check_output([str(binary)], text=True).strip()
    report = {'crypto_vectors': vector_result, 'keychain_test': keychain_result,
              'scope': 'Mac crypto interoperability and signed Keychain persistence; not a live NFT journey'}
    (dest / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
