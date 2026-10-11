#!/usr/bin/env python3
"""Export only reviewed service files; no sibling checkout is needed at runtime."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parent.parent
PACKAGING = ROOT / 'packaging/coupon'
RUNTIME_FILES = ('__init__.py', 'evidence.py', 'near.py', 'offer_v2.py', 'offer_v3.py', 'offer_v4.py', 'dstack_issuer_identity.py', 'dstack_bootstrap.py', 'issuer_service.py', 'live_worker.py', 'staging_approval.py', 'issuance_guard.py', 'async_service_v4.py',
                 'peer_worker.py', 'service.py', 'service_v2.py', 'service_v3.py', 'service_v4.py',
                 'spike.py', 'transport.py')
DSMACK_FILES = ('node/coupon-node.mjs', 'node/coupon-live-node.mjs', 'packaging/coupon/approval-root.json',
               'runner/chain/ethereum-finality/Cargo.toml', 'runner/chain/ethereum-finality/Cargo.lock', 'runner/chain/ethereum-finality/src/main.rs', 'packaging/coupon/Dockerfile',
               'packaging/coupon/README.md', 'packaging/coupon/smoke.mjs',
               'packaging/coupon/paired-source.json', 'packaging/coupon/python-wheels.json',
               'packaging/coupon/install_python.py', 'packaging/coupon/python-worker',
               'experiments/coupon_redemption/peer_bridge.mjs',
               'experiments/coupon_redemption/fixtures/offer-v2.json',
               'experiments/coupon_redemption/fixtures/offer-v3.json') + tuple(
                   'experiments/coupon_redemption/' + name for name in RUNTIME_FILES)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii')


def paired_files(source):
    pin = json.loads((PACKAGING / 'paired-source.json').read_text())
    result = {}
    for name, expected in pin['files'].items():
        file = source / name
        if file.is_symlink() or not file.is_file():
            raise ValueError('paired source must contain regular allowlisted files')
        data = file.read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError('paired source differs from pinned revision: ' + name)
        result[name] = data
    return pin, result


def archive(output, files):
    if output.exists():
        raise ValueError('output already exists')
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('xb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', filename='', mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as tar:
            for name, data in sorted(files.items()):
                info = tarfile.TarInfo(name)
                info.size, info.mtime, info.uid, info.gid = len(data), 0, 0, 0
                info.mode = 0o755 if name.endswith('python-worker') else 0o644
                tar.addfile(info, io.BytesIO(data))


def dsmack_files(profile="tdx"):
    names = DSMACK_FILES
    if profile == "mac-base":
        names += tuple("experiments/coupon_redemption/" + name for name in ("mac_bootstrap.py", "mac_issuer_identity.py", "mac_live_worker.py", "mac_transport.py", "mac_init.py"))
        names += ('node/mac-coupon-control.mjs',)
        names += tuple("packaging/coupon/" + name for name in ("Dockerfile.mac-base", "python-wheels-mac-base.json", "install_python_mac_base.py", "mac-base.md"))
    files = {}
    for name in names:
        file = ROOT / name
        if file.is_symlink() or not file.is_file():
            raise ValueError('package input must be a regular file: ' + name)
        files[name] = file.read_bytes()
    return files


def build(source, output, export_pair=False, profile="tdx"):
    pin, paired = paired_files(source)
    if export_pair:
        archive(output, paired)
        return
    files = dsmack_files(profile)
    revision = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
    matches_revision = True
    for name, data in files.items():
        original = subprocess.run(['git', '-C', str(ROOT), 'show', revision + ':' + name], capture_output=True)
        if original.returncode != 0 or original.stdout != data:
            matches_revision = False
    files.update({'vendor/abalone/' + name: data for name, data in paired.items()})
    # Keep later accidental secrets out of COPY even if the exported directory
    # is used as a build context after an operator has added unrelated files.
    allowed = {'source-manifest.json', '.dockerignore'}
    for name in files:
        allowed.add(name)
        allowed.update(str(parent) + '/' for parent in Path(name).parents if str(parent) != '.')
    files['.dockerignore'] = ('*\n' + ''.join('!' + name + '\n' for name in sorted(allowed))).encode()
    hashes = {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())}
    files['source-manifest.json'] = canonical({'version': 1, 'dsmack_checkout_revision': revision,
        'dsmack_inputs_match_checkout_revision': matches_revision,
        'source_tree_sha256': hashlib.sha256(canonical(hashes)).hexdigest(), 'files': hashes,
        'abalone_revision': pin['revision'], 'profile': ('synthetic-linux-arm64-cpython311-node24' if profile == 'mac-base' else 'synthetic-linux-amd64-cpython311-node24'),
        'intended_issuer_profile': ('mac-appattest-coupon-v1' if profile == 'mac-base' else 'dstack-backed-dsmack-node'),
        'participant_profile': 'mac-app', 'attestation': 'local-unattested',
        'deposit_release_authorized': False}) + b'\n'
    archive(output, files)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--abalone-source', required=True, type=Path,
                        help='reviewed paired source tree; only pinned regular files are read')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--export-pair', action='store_true')
    parser.add_argument('--profile', choices=('tdx', 'mac-base'), default='tdx')
    args = parser.parse_args()
    build(args.abalone_source.resolve(), args.output, args.export_pair, args.profile)
    print(json.dumps({'output_sha256': hashlib.sha256(args.output.read_bytes()).hexdigest(),
                      'paired_revision': json.loads((PACKAGING / 'paired-source.json').read_text())['revision']}))


if __name__ == '__main__':
    main()
