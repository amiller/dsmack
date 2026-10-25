#!/usr/bin/env python3
"""Operator side of the Mac transport, run on zed /data: the agent-turns image and its signed release,
per-attempt workload admissions, and verification of the Mac's run evidence.

The admission signer runs here with the release key for now; it moves into a dstack app that holds the key.
"""
import argparse
import base64
import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tarfile

TURNS = Path(__file__).resolve().parent
ROOT = TURNS.parents[1]
GUEST = ROOT/'base-vm/browser-sandbox-v1/source'
PILOT = ROOT/'applications/pilot-client'
sys.path[:0] = [str(GUEST/'runner-content/lib'), str(PILOT/'workload')]
from dsmack_compose_contract.manifest import validate_manifest_bytes
from dsmack_compose_contract.runtime_inputs import TASK_COMMITMENT_ALG, compute_commitment

SELECTOR = 'agent-turns-edit-v1'
REPO = 'agent-turns'
SLOTS = {'inputs': 16 << 20, 'turn': 1 << 20}
ARTIFACTS = ['patch', 'run-1-transcript', 'run-1-stderr', 'verdict']
PYTHON = '304aa87a76ebb13fd22d253ac157f14980ff2cdb23e6274f3b045571405e07dc'
# The qualified 0.7.1.broker-timeout-v1 base (rootfs c62f6746) and its guest-input builder.
BUILD = Path('/data/amiller/dsmack/broker-timeout-v1-20261022/build-2')
BASE = BUILD/'build/legs/diagnostic/files'
KEY_ID = 'dsmack-alpha-20261022-86473863'
RELEASE_KEY = Path('/data/amiller/dsmack/alpha-release-authority-20261022/864738631abef8cc88c98597/release-signing-key.pem')
POLICY = '/data/amiller/dsmack/arcade-pilot-runtime-20261023/PUBLIC-OPERATOR-POLICY.json'
CORE, EXTRACTOR = ('13214b3711f2c69e145a11eee22c3f1c522d7d63f535bcf1ba5f5f9804ea8cb5',
                   'd8d3959fe11b32233f4291b795cb4ce2b8b8e6cbd2a467eebecedfe943a6dcd2')
# Pilot-client files a release ships at the same relative path.
SHIPPED = ['alpha-profile.mjs', 'alpha-release.mjs', 'alpha-release-cli.mjs', 'alpha_coordinator.py',
           'alpha_signing_policy.py', 'alpha_stage.py', 'public_task.py', 'coordinator/coordinator.py',
           *(f'coordinator/modulepack/{n}.py' for n in ('approved_run', 'native_helper', 'session_parser', 'signing_policy'))]


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def file_sha(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def stamp(moment):
    return moment.isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def private_write(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)


def sign(schema, raw, key=RELEASE_KEY):
    message = schema.encode() + b'\0' + raw
    return subprocess.run(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', str(key), '-in', '/dev/stdin'],
                          input=message, capture_output=True, check=True).stdout


def image(args):
    """Build the image from the qualified Claude Code parent and write it as a gzip OCI layout."""
    out = args.out
    out.mkdir()
    tag = f'{REPO}:mac-{out.name}'
    subprocess.run(['docker', 'build', '-q', '--build-arg', 'QUALIFIED_CLAUDE_REPOSITORY=' + args.qualified,
                    '-t', tag, str(TURNS)], env=os.environ | {'DOCKER_BUILDKIT': '0'}, check=True)
    with open(out/'image.tar', 'wb') as saved:
        subprocess.run(['docker', 'save', tag], stdout=saved, check=True)
    subprocess.run(['docker', 'rmi', tag], check=True, capture_output=True)
    blobs = out/'oci-layout/blobs/sha256'
    blobs.mkdir(parents=True)

    def blob(raw):
        digest = sha(raw)
        (blobs/digest).write_bytes(raw)
        return {'digest': 'sha256:' + digest, 'size': len(raw)}
    layers = []
    with tarfile.open(out/'image.tar') as tar:
        entry, = json.load(tar.extractfile('manifest.json'))
        config = blob(tar.extractfile(entry['Config']).read())
        for name in entry['Layers']:
            temp = out/'layer.tmp'
            with tar.extractfile(name) as src, gzip.GzipFile(temp, 'wb', compresslevel=6, mtime=0) as gz:
                shutil.copyfileobj(src, gz, 1 << 20)
            digest = file_sha(temp)
            size = temp.stat().st_size
            temp.rename(blobs/digest)
            layers.append({'mediaType': 'application/vnd.oci.image.layer.v1.tar+gzip',
                           'digest': 'sha256:' + digest, 'size': size})
    (out/'image.tar').unlink()
    manifest = {'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                'config': {'mediaType': 'application/vnd.oci.image.config.v1+json', **config}, 'layers': layers}
    top = blob(canonical(manifest))
    index = {'schemaVersion': 2, 'manifests': [{'mediaType': manifest['mediaType'], **top,
             'platform': {'architecture': 'arm64', 'os': 'linux'},
             'annotations': {'org.opencontainers.image.ref.name': REPO}}]}
    (out/'oci-layout/index.json').write_bytes(canonical(index))
    (out/'oci-layout/oci-layout').write_text('{"imageLayoutVersion":"1.0.0"}')
    print(top['digest'])


def compose_manifest(reference, digest):
    m = dict(reference, name=SELECTOR)
    m['allowed_files'] = [{'slot': s, 'target': '/workspace/inputs/' + s, 'mode': 'ro', 'audience': 'workload',
                           'required': True, 'max_bytes': n} for s, n in SLOTS.items()]
    m['harness'] = {'name': 'python-application', 'path': '/usr/bin/python3.11', 'sha256': PYTHON,
                    'version': 'agent-turns-1'}
    service = {'image': f'127.0.0.1:5005/{REPO}@{digest}', 'read_only': True,
               'command': ['--spec', '/workspace/inputs/turn', '--inputs', '/workspace/inputs/inputs',
                           '--output', '/workspace/artifacts'],
               'environment': {'TMPDIR': '/workspace/state'},
               'volumes': [f'{s}:/workspace/inputs/{s}:ro' for s in SLOTS]
               + ['state:/workspace/state:rw', 'artifacts:/workspace/artifacts:rw']}
    m['docker_compose_file'] = canonical({'services': {'agent': service}}).decode()
    m['limits'] = dict(m['limits'], workspace_max_bytes=256 << 20)
    m['outputs'] = {'capture': ['stdout', 'stderr'],
                    'artifacts': [{'name': n, 'path': '/workspace/artifacts/' + n} for n in ARTIFACTS]}
    raw = canonical(m)
    validate_manifest_bytes(raw)
    return raw


def release(args):
    """Sign a release that is a prior private-develop release with the agent-turns profile and current sources."""
    out = args.out
    stage = out/'stage'
    stage.mkdir(parents=True)
    base = json.loads(args.base_inventory.read_bytes())
    with tarfile.open(args.base_archive) as tar:
        tar.extractall(stage)
    old, = base['profiles']
    profile = json.loads((stage/old['descriptor_path']).read_bytes())
    reference = json.loads((stage/profile['roles']['compose_manifest']).read_bytes())
    for path in (old['descriptor_path'], profile['roles']['compose_manifest']):
        (stage/path).unlink()
    shutil.rmtree(stage/'auxiliary')
    for path in SHIPPED:
        shutil.copyfile(PILOT/path, stage/path)
    index = json.loads((args.oci/'index.json').read_bytes())
    manifest = compose_manifest(reference, index['manifests'][0]['digest'])
    compose_path = f'public/{SELECTOR}.app-compose.json'
    (stage/compose_path).write_bytes(manifest)
    profile['profile_id'] = SELECTOR
    profile['execution_profile'].update(profile_id=SELECTOR, workload_id=SELECTOR, compose_manifest_sha256=sha(manifest))
    profile['roles']['compose_manifest'] = compose_path
    profile_raw = canonical(profile)
    profile_path = f'profiles/{SELECTOR}.json'
    (stage/profile_path).write_bytes(profile_raw)
    modes = {f['path']: f['mode'] for f in base['files']}
    files = [{'path': str(p.relative_to(stage)), 'bytes': p.stat().st_size, 'sha256': file_sha(p),
              'mode': modes.get(str(p.relative_to(stage)), 0o600)}
             for p in sorted(stage.rglob('*')) if p.is_file()]
    archive = out/'release.tar.gz'
    with tarfile.open(archive, 'w:gz', format=tarfile.USTAR_FORMAT) as tar:
        for f in files:
            info = tar.gettarinfo(stage/f['path'], f['path'])
            info.mode, info.mtime, info.uid, info.gid, info.uname, info.gname = f['mode'], 0, 0, 0, '', ''
            with open(stage/f['path'], 'rb') as stream:
                tar.addfile(info, stream)
    now = datetime.datetime.now(datetime.timezone.utc)
    inventory = {k: base[k] for k in ('schema', 'key_id', 'channel', 'platform', 'app', 'provenance_sha256',
                                      'verification_policy')}
    inventory.update(release_id=f'agent-turns-mac-{out.name}', sequence=args.sequence, issued_at=stamp(now),
                     expires_at=stamp(now + datetime.timedelta(days=7)), files=files,
                     profiles=[{'profile_id': SELECTOR, 'descriptor_path': profile_path, 'descriptor_sha256': sha(profile_raw)}],
                     archive={'format': 'tar+gzip', 'bytes': archive.stat().st_size, 'sha256': file_sha(archive)})
    raw = canonical(inventory)
    (out/'release.json').write_bytes(raw)
    (out/'release.sig').write_bytes(sign(inventory['schema'], raw))
    print(json.dumps({'inventory_sha256': sha(raw), 'manifest_sha256': sha(manifest), 'sequence': args.sequence}))


def public_disk(out, manifest_raw, projection, context, oci):
    """The measured workload disk: manifest, base bundle, commitment declaration, closure context and image."""
    from transport_loader import execute, load, raw
    transport = load(GUEST/'smoke/launch_vm_dstack_arm64.py')
    package = sys.modules['dsmack_guest_io']
    for name in ('closure', 'oci_publish'):
        path = GUEST/'runner-content/dsmack_guest_io'/(name + '.py')
        setattr(package, name, execute('dsmack_guest_io.' + name, path, raw(path)))
    builder = BUILD/'source/build/make_guest_inputs.py'
    guest_inputs = execute('make_guest_inputs', builder, raw(builder))
    manifest = json.loads(manifest_raw)
    tree = out/'public-tree'
    for name in ('manifests', 'admission', 'base-bundle', 'commitments', 'closure-context'):
        (tree/name).mkdir(parents=True)
    (tree/'manifests'/(SELECTOR + '.app-compose.json')).write_bytes(manifest_raw)
    for name in ('Image', 'initramfs.cpio.gz', 'rootfs.squashfs.verity', 'metadata.json', 'sha256sum.txt'):
        shutil.copyfile(BASE/name, tree/'base-bundle'/name)
    (tree/'admission/base-admission.json').write_bytes(
        canonical({'admission_version': 1, 'allowed_os_image_hashes': [manifest['base_vm']['os_image_hash']]}))
    guest_inputs.emit_commitment_declaration(str(tree), SELECTOR, projection, sha(manifest_raw))
    (tree/'closure-context/context.json').write_bytes(context)
    (tree/'WORKLOAD').write_text(SELECTOR + '\n')
    delivery = guest_inputs.stage_oci_layout(str(tree), str(oci), repo_name=REPO)
    service, = json.loads(manifest['docker_compose_file'])['services'].values()
    assert delivery['refs'][REPO] == service['image'], 'manifest image is not the staged layout'
    transport.start_overall_deadline(300)
    transport.build_workload_disk(None, str(tree), str(out/'workload.img'), 1 << 30)
    shutil.rmtree(tree)
    return {'bytes': (out/'workload.img').stat().st_size, 'sha256': file_sha(out/'workload.img')}


def verifier(authority, *argv):
    result = subprocess.run(['/usr/bin/python3', '-I', '-B', str(PILOT/'verifier-browser/verify.py'), *map(str, argv)],
                            capture_output=True, env={'HOME': str(Path.home()), 'PATH': '/usr/bin:/bin'})
    sys.stderr.write(result.stderr.decode())
    assert result.returncode in (0, 3), f'verifier refused {argv[:2]}: exit {result.returncode}'
    return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]


def admit(args):
    """Mint one attempt: projection, measured disk, checker context, signed admission and a fresh challenge."""
    out, authority = args.out, args.authority
    out.mkdir()
    inventory_raw = (args.release/'release.json').read_bytes()
    manifest_raw = (args.release/'stage/public'/(SELECTOR + '.app-compose.json')).read_bytes()
    manifest = json.loads(manifest_raw)
    files = {'inputs': args.inputs_tar.read_bytes(), 'turn': args.request.read_bytes()}
    projection = {'runtime_input_version': 4, 'manifest_sha256': sha(manifest_raw),
                  'files': [{'slot': s, 'content_base64': base64.b64encode(files[s]).decode()} for s in SLOTS],
                  'commitments': {'alg': TASK_COMMITMENT_ALG,
                                  'scope': {'include': ['files'], 'file_slots': ['turn']}, 'inputs_sha256': '0'*64}}
    projection['commitments']['inputs_sha256'] = compute_commitment(projection, manifest)
    (out/'preparation').mkdir()
    (out/'preparation/compose-manifest.json').write_bytes(manifest_raw)
    (out/'preparation/public-file-projection.json').write_bytes(canonical(projection))
    attempt = secrets.token_hex(16)
    closure = {'schema': 'dsmack-result-closure-context/1', 'attempt_id': attempt, 'selectors': [SELECTOR]}
    (out/'closure-context.json').write_bytes(canonical(closure))
    disk = public_disk(out, manifest_raw, projection, canonical(closure), args.oci)
    key_id = (authority/'keyId.txt').read_text().strip()
    challenge = secrets.token_bytes(32)
    (out/'challenge.bin').write_bytes(challenge)
    (out/'keyId.txt').write_text(key_id)
    report = json.loads((authority/'report.json').read_bytes())
    expected = {'app_id': 'DC9JH5DRMY.dev.dsmack.provider', 'team_id': 'DC9JH5DRMY', 'environment': 'production',
                'enrollment_class': 'apple-appattest-production', 'challenge': challenge.hex(),
                'closure_context': closure, 'key_id_b64': key_id, 'manifest_sha256': sha(manifest_raw),
                'receipt_selector': SELECTOR, 'receipt_environment': 'vm', 'workload_status': 'completed', 'exit_code': 0}
    expected['selector_manifests'] = {SELECTOR: {k: expected[k] for k in ('manifest_sha256', 'workload_status',
                                                                           'exit_code', 'receipt_environment')}}
    checker = {'schema': 'dsmack.runresult-checker-context/3', 'verifier_id': 'dsmack-runresult-verifier',
               'verifier_version': '2', 'core_sha256': CORE, 'extractor_tool_sha256': EXTRACTOR,
               'report_key_id': report['key_id'], 'report_verify_key_b64': report['public_b64'], 'expected': expected}
    (out/'checker-context.json').write_bytes(canonical(checker))
    now = datetime.datetime.now(datetime.timezone.utc)
    admission = {'schema': 'dsmack-alpha-workload-admission/1', 'key_id': KEY_ID,
                 'release_inventory_sha256': sha(inventory_raw), 'profile_id': SELECTOR,
                 'compose_manifest_sha256': sha(manifest_raw), 'attempt_id': attempt,
                 'closure_context_sha256': sha(canonical(closure)), 'workload_disk': disk,
                 'issued_at': stamp(now), 'expires_at': stamp(now + datetime.timedelta(hours=2))}
    raw = canonical(admission)
    (out/'workload-admission.json').write_bytes(raw)
    (out/'workload.sig').write_bytes(sign(admission['schema'], raw))
    verifier(authority, 'operator', 'issue-challenge', '--replay', authority/'replay.sqlite', '--key-id', key_id,
             '--manifest-sha256', sha(manifest_raw), '--ttl', 7200, '--challenge', challenge.hex())
    print(json.dumps({'attempt_id': attempt, 'workload_disk': disk}))


def authorize(args):
    """Create an operator authority (secret, report key, stores) and enroll the Mac's App Attest key in it."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    a = args.authority
    a.mkdir(mode=0o700)
    seed = secrets.token_bytes(32)
    private_write(a/'operator-secret', secrets.token_bytes(32))
    private_write(a/'report-key.raw', seed)
    public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    (a/'report.json').write_bytes(canonical({'key_id': 'agent-turns-mac-report-1', 'public_b64': base64.b64encode(public).decode()}))
    for name in ('attestation.cbor', 'clientData.bin', 'keyId.txt'):
        shutil.copyfile(args.registration/name, a/name)
    rows = verifier(a, 'operator', 'enroll', '--policy', POLICY, '--secret-file', a/'operator-secret',
                    '--store', a/'enrollment.sqlite', '--attestation', a/'attestation.cbor', '--key-id-file', a/'keyId.txt',
                    '--challenge', a/'clientData.bin', '--out', a/'enrollment.json', '--replay', a/'replay.sqlite',
                    '--min-counter', 0)
    print(json.dumps(rows[-1]))


def verify(args):
    """Full verification of the Mac's original evidence; leaves retained/receipt.json and retained/outputs."""
    a, job = args.authority, args.job
    report = json.loads((a/'report.json').read_bytes())
    context = args.attempt/'checker-context.json'
    verifier(a, 'prepare', 'prepare', '--app-out', args.evidence, '--enrollment', a/'enrollment.json',
             '--context', context, '--bundle', job/'bundle')
    rows = verifier(a, 'prepare', 'verify', '--bundle', job/'bundle', '--context', context, '--retained', job/'retained',
                    '--policy', POLICY, '--secret-file', a/'operator-secret', '--signing-key-file', a/'report-key.raw',
                    '--report-key-id', report['key_id'], '--store', a/'enrollment.sqlite', '--replay', a/'replay.sqlite',
                    '--work-root', job, '--extractor-sha256', EXTRACTOR)
    full = rows[-1]
    assert full.get('checked') is True and full.get('verification_level') == 'full', 'evidence is not fully verified'
    (job/'verification.json').write_bytes(canonical(full))
    print(json.dumps({k: full.get(k) for k in ('evidence_valid', 'verification_level', 'task_success')}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(required=True)
    p = sub.add_parser('image')
    p.add_argument('--qualified', default='127.0.0.1:39685/dsmack-claude-harness')
    p.add_argument('--out', type=Path, required=True)
    p.set_defaults(func=image)
    p = sub.add_parser('release')
    p.add_argument('--base-inventory', type=Path, required=True)
    p.add_argument('--base-archive', type=Path, required=True)
    p.add_argument('--oci', type=Path, required=True)
    p.add_argument('--sequence', type=int, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.set_defaults(func=release)
    p = sub.add_parser('authorize')
    p.add_argument('--authority', type=Path, required=True)
    p.add_argument('--registration', type=Path, required=True, help='attestation.cbor, clientData.bin, keyId.txt')
    p.set_defaults(func=authorize)
    p = sub.add_parser('admit')
    for name in ('release', 'oci', 'authority', 'request', 'inputs-tar', 'out'):
        p.add_argument('--' + name, type=Path, required=True)
    p.set_defaults(func=admit)
    p = sub.add_parser('verify')
    for name in ('authority', 'attempt', 'evidence', 'job'):
        p.add_argument('--' + name, type=Path, required=True)
    p.set_defaults(func=verify)
    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
