#!/usr/bin/env python3
"""Operator side of the Mac transport, run once per image on the operator host: build the agent-turns image and pack
it with the turn's compose manifest into the measured workload disk the Mac boots for every turn.

The manifest has two services on one image. `agent` runs find.py with no network beyond the guest's service bridge;
`sentinel` (sentinel_env.py) holds the Claude credential and alone reaches api.anthropic.com. Per-turn values (the
request, the snapshot, the credential and a fresh sentinel token) travel on the private input disk the Mac writes, so
nothing per turn is built or admitted here.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

TURNS = Path(__file__).resolve().parent
ROOT = TURNS.parents[1]
SELECTOR = 'agent-turns-edit-v1'
REPO = 'agent-turns'
ARTIFACTS = ['patch', 'run-1-transcript', 'verdict', 'attestation']
# The request and the gzipped snapshot travel as env values: file slots crash the 8783a3be runner (KeyError 'slot'
# in lifecycle.parser_validate). Linux caps one env string at 128 KiB, so the snapshot is split over TREE_0..TREE_7;
# the guest caps all env values at 1 MiB in total.
TREE_PARTS = 8
ENVS = {'TURN': 'agent', **{f'TREE_{i}': 'agent' for i in range(TREE_PARTS)},
        'SENTINEL_ENDPOINT': 'agent', 'SENTINEL_TOKEN': 'sentinel', 'SENTINEL_CREDENTIAL': 'sentinel'}
REQUIRED = ['TURN', 'TREE_0', 'SENTINEL_ENDPOINT', 'SENTINEL_TOKEN', 'SENTINEL_CREDENTIAL']
PARENT = 'sha256:dedc08251681f537d3c4fc8d3e9a3bc70f666bf979946e6daadee35178f0c418'  # qualified Claude Code 2.1.187
PYTHON = '304aa87a76ebb13fd22d253ac157f14980ff2cdb23e6274f3b045571405e07dc'  # /usr/bin/python3.11 in PARENT
# The runner block of the browser-sandbox-v1 bases (runc in the verity root).
RUNNER = {'compose_tool': {'name': 'docker-compose', 'version': '2.26.1-4'}, 'container_runtime': 'runc', 'kind': 'oci-compose',
          'runtime_closure': {'components': [{'name': 'runc', 'path': '/usr/bin/runc', 'registration_args': [],
                                              'sha256': '6a8bd8a019e7b10a8d30a9fa85656f795d5957ab7269e5579f438a065b753332'}]},
          'runtime_name': 'runc', 'runtime_version': '1.1.15+ds1'}
# api.anthropic.com (Anthropic's published 160.79.104.0/23) and gvproxy's resolver.
SENTINEL_EGRESS = [{'destination': '160.79.104.0/23', 'protocol': 'tcp', 'port': 443},
                   {'destination': '192.168.127.1/32', 'protocol': 'udp', 'port': 53},
                   {'destination': '192.168.127.1/32', 'protocol': 'tcp', 'port': 53}]


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def file_sha(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def image(args):
    """Build the image on the qualified Claude Code parent (an OCI layout) and write it as an OCI layout."""
    out = args.out
    out.mkdir()
    subprocess.run(['docker', 'buildx', 'build', '--builder', args.builder, '--platform', 'linux/arm64',
                    '--provenance=false', '--sbom=false', '--build-arg', 'QUALIFIED_CLAUDE_REPOSITORY=qualified',
                    '--build-context', f'qualified@{PARENT}=oci-layout://{args.qualified}@{PARENT}',
                    '--output', f'type=oci,dest={out/"image.tar"},rewrite-timestamp=true', '-f', str(TURNS/'Dockerfile'), str(ROOT)],
                   env=os.environ | {'SOURCE_DATE_EPOCH': '0'}, check=True)
    with tarfile.open(out/'image.tar') as tar:
        tar.extractall(out/'oci-layout', filter='data')
    (out/'image.tar').unlink()
    index = json.loads((out/'oci-layout/index.json').read_bytes())
    entry, = index['manifests']
    entry['annotations'] = {'org.opencontainers.image.ref.name': REPO}
    (out/'oci-layout/index.json').write_bytes(canonical(index))
    print(entry['digest'])


def base_vm(base):
    """The compose manifest's base_vm fields for a guest image bundle (derive.py output or a release's base/)."""
    meta = json.loads((base/'metadata.json').read_bytes())
    root = dict(t.split('=', 1) for t in meta['cmdline'].split() if '=' in t)['dstack.rootfs_hash']
    return dict(architecture='aarch64', memory_mb=4096, vcpus=1, cmdline=meta['cmdline'],
                initrd_sha256=file_sha(base/'initramfs.cpio.gz'), kernel_sha256=file_sha(base/'Image'),
                metadata_sha256=file_sha(base/'metadata.json'), os_image_hash=file_sha(base/'sha256sum.txt'),
                rootfs_sha256=file_sha(base/'rootfs.squashfs.verity'), verity_root_hash=root)


def manifest(digest, base):
    image = f'127.0.0.1:5005/{REPO}@{digest}'
    python = ['/usr/bin/python3.11', '-B']
    services = {
        'agent': {'image': image, 'read_only': True, 'entrypoint': python + ['/opt/agent-turns/find.py'],
                  'command': ['--spec', '/workspace/state/turn', '--inputs', '/workspace/state/tree.tar',
                              '--output', '/workspace/artifacts', '--attest', '--from-env'],
                  'environment': {'TMPDIR': '/workspace/state'},
                  'volumes': ['state:/workspace/state:rw', 'artifacts:/workspace/artifacts:rw', '/var/run/dstack.sock:/var/run/dstack.sock:ro']},
        'sentinel': {'image': image, 'read_only': True, 'entrypoint': python + ['/opt/agent-turns/sentinel_env.py']}}
    return canonical({
        'manifest_version': 4, 'name': SELECTOR, 'runner': RUNNER, 'base_vm': base_vm(base),
        'harness': {'name': 'python-application', 'path': '/usr/bin/python3.11', 'sha256': PYTHON, 'version': 'agent-turns-2'},
        'image_platform': {'architecture': 'arm64', 'os': 'linux'},
        'docker_compose_file': canonical({'services': services}).decode(),
        'allowed_envs': [{'name': n, 'audience': 'workload', 'services': [s]} for n, s in ENVS.items()],
        'required_envs': REQUIRED,
        'allowed_files': [],
        'runtime_inputs': {'env': {'mode': 'inject'}, 'stdin': {'max_bytes': 0, 'mode': 'none'},
                           'user_config': {'max_bytes': 0, 'mode': 'none'}},
        'network': {'mode': 'nat', 'listen_ports': [], 'egress': [], 'service_egress': {'sentinel': SENTINEL_EGRESS}},
        'limits': {'output_max_bytes': 16 << 20, 'timeout_s': 550, 'workspace_max_bytes': 256 << 20},
        'outputs': {'completion_service': 'agent', 'capture': ['stdout', 'stderr'],
                    'artifacts': [{'name': n, 'path': '/workspace/artifacts/' + n} for n in ARTIFACTS]}})


def workload(args):
    """The compose manifest for the image on --base, packed with the image into OUT/workload.img."""
    digest = json.loads((args.image/'oci-layout/index.json').read_bytes())['manifests'][0]['digest']
    raw = manifest(digest, args.base)
    args.out.mkdir()
    (args.out/'compose-manifest.json').write_bytes(raw)
    sys.path.insert(0, str(ROOT/'dstack-compat'))
    import canary_workload
    canary_workload.pack(ROOT, args.base, args.image, args.out/'disk', SELECTOR, raw)
    shutil.move(args.out/'disk/workload.img', args.out/'workload.img')
    shutil.rmtree(args.out/'disk')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(required=True)
    p = sub.add_parser('image')
    p.add_argument('--qualified', type=Path, required=True, help='OCI layout holding the qualified parent ' + PARENT)
    p.add_argument('--builder', required=True, help='a docker-container buildx builder that can build linux/arm64')
    p.add_argument('--out', type=Path, required=True)
    p.set_defaults(func=image)
    p = sub.add_parser('workload')
    p.add_argument('--image', type=Path, required=True, help='the `image` output')
    p.add_argument('--base', type=Path, required=True,
                   help='guest image bundle: Image, initramfs.cpio.gz, rootfs.squashfs.verity, metadata.json, sha256sum.txt')
    p.add_argument('--out', type=Path, required=True)
    p.set_defaults(func=workload)
    args = parser.parse_args()
    for name, value in vars(args).items():
        if isinstance(value, Path):
            setattr(args, name, value.resolve())
    args.func(args)


if __name__ == '__main__':
    main()
