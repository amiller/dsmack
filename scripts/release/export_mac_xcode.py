#!/usr/bin/env python3
"""Export/notarize a signed Mac candidate using Xcode's saved account or API key.

This uses Apple's managed distribution signing, so a local Developer ID private
key is not required. The explicit App ID/capability must already exist.
"""
import argparse
import datetime
import os
from pathlib import Path
import plistlib
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--team', required=True)
    parser.add_argument('--submit-notarization', action='store_true')
    args = parser.parse_args()
    app = args.app.resolve()
    subprocess.run(['codesign', '--verify', '--strict', str(app)], check=True)
    details = subprocess.check_output(['codesign', '-d', '--verbose=4', str(app)], stderr=subprocess.STDOUT).decode()
    team = re.search(r'^TeamIdentifier=(.+)$', details, re.M)
    identity = re.search(r'^Authority=(.+)$', details, re.M)
    if not team or team.group(1) != args.team or not identity:
        raise SystemExit('Input must already be signed under the requested team')
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    archive = out / 'Node.xcarchive'
    products = archive / 'Products/Applications'
    products.mkdir(parents=True)
    subprocess.run(['ditto', str(app), str(products / app.name)], check=True)
    bundle = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
    properties = {'ApplicationPath': 'Applications/' + app.name,
                  'SigningIdentity': identity.group(1), 'Team': args.team, 'Architectures': ['arm64']}
    for key in ('CFBundleIdentifier', 'CFBundleShortVersionString', 'CFBundleVersion'):
        properties[key] = bundle[key]
    metadata = {'ArchiveVersion': 2, 'Name': 'Node', 'SchemeName': 'Node',
                'CreationDate': datetime.datetime.now(datetime.timezone.utc), 'ApplicationProperties': properties}
    (archive / 'Info.plist').write_bytes(plistlib.dumps(metadata))
    options = out / 'export-options.plist'
    options.write_bytes(plistlib.dumps({'method': 'developer-id', 'signingStyle': 'automatic',
                                       'destination': 'upload' if args.submit_notarization else 'export',
                                       'teamID': args.team}))
    command = ['xcodebuild', '-exportArchive', '-archivePath', str(archive),
               '-exportOptionsPlist', str(options), '-exportPath', str(out / 'export'), '-allowProvisioningUpdates']
    # Paths and IDs only; the private key stays in its protected file.
    auth = ('ASC_KEY_PATH', 'ASC_KEY_ID', 'ASC_ISSUER_ID')
    if any(os.environ.get(key) for key in auth):
        if not all(os.environ.get(key) for key in auth):
            raise SystemExit('Set all of ASC_KEY_PATH, ASC_KEY_ID and ASC_ISSUER_ID, or none')
        for flag, key in zip(('-authenticationKeyPath', '-authenticationKeyID', '-authenticationKeyIssuerID'), auth):
            command += [flag, os.environ[key]]
    with (out / 'export.log').open('w') as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
    if result.returncode:
        raise SystemExit(f'Xcode export failed; inspect {out / "export.log"}')
    if args.submit_notarization:
        print('Uploaded for notarization; approval is not yet established.')
        print(f'When processing completes: xcodebuild -exportNotarizedApp -archivePath "{archive}" -exportPath "{out / "notarized"}"')
    else:
        print(out / 'export')


if __name__ == '__main__':
    main()
