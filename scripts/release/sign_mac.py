#!/usr/bin/env python3
"""Sign an existing unsigned build. Developer ID mode also notarizes and staples it."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import plistlib
import subprocess
from verify_signed_payload import verify


def run(*args):
    subprocess.run([str(a) for a in args], check=True)


def validate_profile(profile, bundle_id, team, channel):
    ent = profile['Entitlements']
    if profile['ExpirationDate'] <= datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None):
        raise ValueError('Provisioning profile has expired')
    if team not in profile.get('TeamIdentifier', []):
        raise ValueError('Wrong profile team')
    app_id = ent.get('com.apple.application-identifier')
    prefixes = profile.get('ApplicationIdentifierPrefix', [])
    if not any(app_id == prefix + '.' + bundle_id for prefix in prefixes):
        raise ValueError('Profile must explicitly grant this bundle ID')
    if ent.get('com.apple.developer.devicecheck.app-attest-opt-in') != ['CDhash']:
        raise ValueError('Profile does not grant the CDhash App Attest capability')
    if channel == 'developer-id' and (not profile.get('ProvisionsAllDevices') or profile.get('ProvisionedDevices')):
        raise ValueError('Developer ID requires an all-devices profile, without registered-device identifiers')
    # Do not copy arbitrary profile capabilities or a debugging entitlement.
    result = {'com.apple.application-identifier': app_id,
              'com.apple.developer.team-identifier': team,
              'com.apple.developer.devicecheck.app-attest-opt-in': ['CDhash']}
    if 'keychain-access-groups' in ent:
        result['keychain-access-groups'] = [app_id]
    environment = ent.get('com.apple.developer.devicecheck.appattest-environment')
    if environment is not None:
        if environment != 'production':
            raise ValueError('Production App Attest entitlement required when present')
        result['com.apple.developer.devicecheck.appattest-environment'] = environment
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--profile', type=Path, required=True)
    p.add_argument('--identity', required=True)
    p.add_argument('--team', required=True)
    p.add_argument('--keychain', type=Path)
    p.add_argument('--channel', choices=['development', 'developer-id'], required=True)
    p.add_argument('--notary-profile')
    args = p.parse_args()
    if args.channel == 'developer-id':
        if not args.identity.startswith('Developer ID Application:') or not args.notary_profile:
            p.error('Developer ID mode requires a Developer ID Application identity and --notary-profile')
    elif not args.identity.startswith('Apple Development:'):
        p.error('Development mode requires an Apple Development identity')
    original = args.build.resolve() / 'Node.app'
    manifest = json.loads((args.build / 'build-manifest.json').read_text())
    files = {str(f.relative_to(original)): hashlib.sha256(f.read_bytes()).hexdigest()
             for f in original.rglob('*') if f.is_file()}
    if files != manifest['files']:
        raise SystemExit('Unsigned input does not match build manifest')
    profile = plistlib.loads(subprocess.check_output(['security', 'cms', '-D', '-i', str(args.profile)]))
    ent = validate_profile(profile, manifest['bundle_id'], args.team, args.channel)
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    app = out / 'Node.app'
    run('ditto', original, app)
    (app / 'Contents/embedded.provisionprofile').write_bytes(args.profile.read_bytes())
    ent_path = out / 'entitlements.plist'
    ent_path.write_bytes(plistlib.dumps(ent))
    command = ['codesign', '--force', '--options', 'runtime', '--sign', args.identity,
               '--entitlements', ent_path, '--generate-entitlement-der',
               '--timestamp' if args.channel == 'developer-id' else '--timestamp=none']
    if args.keychain:
        command.extend(['--keychain', args.keychain])
    run(*command, app)
    run('codesign', '--verify', '--strict', '--verbose=2', app)
    payload = verify((original / 'Contents/MacOS/node').read_bytes(),
                     (app / 'Contents/MacOS/node').read_bytes())
    for relative, expected in manifest['files'].items():
        if relative != 'Contents/MacOS/node' and hashlib.sha256((app / relative).read_bytes()).hexdigest() != expected:
            raise SystemExit('Signing changed an original app resource: ' + relative)
    (out / 'payload-verification.json').write_text(json.dumps(payload, indent=2) + '\n')
    detail = subprocess.check_output(['codesign', '-d', '--verbose=4', str(app)], stderr=subprocess.STDOUT)
    (out / 'codesign.txt').write_bytes(detail)
    if args.channel == 'developer-id':
        submission = out / 'notary-submission.zip'
        run('ditto', '-c', '-k', '--keepParent', app, submission)
        notary = ['xcrun', 'notarytool', 'submit', str(submission),
                  '--keychain-profile', args.notary_profile, '--wait', '--output-format', 'json']
        if args.keychain:
            notary.extend(['--keychain', str(args.keychain)])
        result = json.loads(subprocess.check_output(notary))
        (out / 'notarization.json').write_text(json.dumps(result, indent=2) + '\n')
        if result.get('status') != 'Accepted':
            raise SystemExit('Notarization did not succeed; no distributable package produced')
        run('xcrun', 'stapler', 'staple', app)
        run('xcrun', 'stapler', 'validate', app)
        run('codesign', '--verify', '--strict', app)
        run('spctl', '--assess', '--type', 'execute', '--verbose=2', app)
        submission.unlink()
    archive = out / ('Node-macOS-arm64.zip' if args.channel == 'developer-id' else 'Node-development-private.zip')
    run('ditto', '-c', '-k', '--keepParent', app, archive)
    (out / 'SHA256SUMS').write_text(hashlib.sha256(archive.read_bytes()).hexdigest() + '  ' + archive.name + '\n')
    (out / 'unsigned-build-manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    print(archive)


if __name__ == '__main__':
    main()
