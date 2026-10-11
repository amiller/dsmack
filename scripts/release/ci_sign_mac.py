#!/usr/bin/env python3
"""Ephemeral GitHub-hosted runner signing; never invoked for pull requests."""
import base64
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile


def main():
    required = ['MAC_CERTIFICATE_P12_BASE64', 'MAC_CERTIFICATE_PASSWORD', 'MAC_PROFILE_BASE64',
                'APPLE_TEAM_ID', 'MAC_SIGNING_IDENTITY', 'ASC_KEY_P8_BASE64', 'ASC_KEY_ID', 'ASC_ISSUER_ID']
    missing = [key for key in required if not os.environ.get(key)]
    if missing:
        raise SystemExit('Missing signing configuration: ' + ', '.join(missing))
    def run(*args):
        subprocess.run([str(a) for a in args], check=True, stdout=subprocess.DEVNULL)
    with tempfile.TemporaryDirectory(prefix='attest-sign-') as directory:
        tmp = Path(directory)
        os.chmod(tmp, 0o700)
        keychain = tmp / 'release.keychain-db'
        password = secrets.token_urlsafe(32)
        for name, key in [('certificate.p12', 'MAC_CERTIFICATE_P12_BASE64'),
                          ('profile.provisionprofile', 'MAC_PROFILE_BASE64'),
                          ('notary.p8', 'ASC_KEY_P8_BASE64')]:
            path = tmp / name
            path.write_bytes(base64.b64decode(os.environ[key], validate=True))
            path.chmod(0o600)
        try:
            run('security', 'create-keychain', '-p', password, keychain)
            run('security', 'set-keychain-settings', '-lut', '3600', keychain)
            run('security', 'unlock-keychain', '-p', password, keychain)
            run('security', 'import', tmp / 'certificate.p12', '-P', os.environ['MAC_CERTIFICATE_PASSWORD'],
                '-k', keychain, '-T', '/usr/bin/codesign')
            run('security', 'set-key-partition-list', '-S', 'apple-tool:,apple:,codesign:', '-s', '-k', password, keychain)
            run('xcrun', 'notarytool', 'store-credentials', 'attest-release', '--key', tmp / 'notary.p8',
                '--key-id', os.environ['ASC_KEY_ID'], '--issuer', os.environ['ASC_ISSUER_ID'], '--keychain', keychain)
            # sign_mac passes the explicit keychain to both codesign and notarytool.
            run(sys.executable, 'scripts/release/sign_mac.py', '--build', 'build/unsigned',
                '--out', 'build/signed', '--profile', tmp / 'profile.provisionprofile',
                '--identity', os.environ['MAC_SIGNING_IDENTITY'], '--team', os.environ['APPLE_TEAM_ID'],
                '--channel', 'developer-id', '--keychain', keychain, '--notary-profile', 'attest-release')
        finally:
            subprocess.run(['security', 'delete-keychain', str(keychain)], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
