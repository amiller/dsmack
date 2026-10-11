#!/usr/bin/env python3
"""Development staging authority for the coupon live service lane.

Holds one Ed25519 approval key inside an ignored local directory and produces
the two signed staging control files (approval/config envelopes) exactly as
the worker's measured approval root verifies them.

The private seed only ever lives in the ignored directory; it is never printed,
logged, exported or passed through argv or the environment. The public key is
the staging authority recorded for development builds via
COUPON_APPROVAL_PUBLIC_KEY; it is never a production approval root and grants
no private-issuance or rollback qualification.

Commands:
  generate --dir DIR                create a fresh authority (refuses overwrite)
  public-key --dir DIR              print the authority's public key (JSON)
  sign-approval --dir DIR --payload FILE [--out FILE]
  sign-config --dir DIR --payload FILE --approval FILE [--out FILE]
"""
import argparse
import json
import os
import stat
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from experiments.coupon_redemption.staging_approval import (APPROVAL_DOMAIN, CONFIG_DOMAIN,
                                                            approval, canonical, configuration,
                                                            payload_hash)

SEED_NAME = 'staging-authority.seed'
PUBLIC_NAME = 'staging-authority.pub'


def _protected_path(path):
    """A private regular file: no links, no group/world access, single link."""
    info = os.stat(path, follow_symlinks=False)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o077 or info.st_nlink != 1):
        raise SystemExit('protected authority file required')
    return path


def _read_private(path, limit=64):
    _protected_path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        with os.fdopen(fd, 'rb', closefd=False) as source:
            return source.read(limit)
    finally:
        os.close(fd)


def _write_private(path, data):
    if os.path.lexists(path):
        raise SystemExit(f'refusing to overwrite {path}')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def load_authority(directory):
    """Return (signing key, public hex); the seed bytes never escape."""
    seed = _read_private(directory / SEED_NAME)
    if len(seed) != 32:
        raise SystemExit('invalid authority seed')
    key = Ed25519PrivateKey.from_private_bytes(seed)
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return key, public.hex()


def sign(payload, domain, key):
    message = domain.encode('ascii') + b'\0' + canonical(payload)
    return canonical({'domain': domain, 'payload': payload,
                      'signature_hex': key.sign(message).hex()})


def generate(args):
    directory = Path(args.dir)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise SystemExit('protected authority directory required')
    if (directory / SEED_NAME).exists():
        raise SystemExit('refusing to overwrite an existing staging authority')
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                             serialization.NoEncryption())
    _write_private(directory / SEED_NAME, seed)
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    _write_private(directory / PUBLIC_NAME, public.hex().encode() + b'\n')
    note = ('Development staging authority only. This key signs debug-staging\n'
            'approval/config envelopes for the coupon live service lane; it is\n'
            'never a production approval root and grants no private-issuance or\n'
            'rollback qualification. The seed must stay in this ignored directory.\n')
    _write_private(directory / 'README.txt', note.encode())
    print(json.dumps({'public_key_hex': public.hex()}))


def public_key(args):
    """Publish only the recorded public half; the seed is not even read."""
    _protected_path(Path(args.dir) / PUBLIC_NAME)
    print(json.dumps({'public_key_hex': _read_private(Path(args.dir) / PUBLIC_NAME)
                      .decode().strip()}))


def sign_approval(args):
    key, public = load_authority(Path(args.dir))
    payload = json.loads(_read_private(Path(args.payload), limit=100_000))
    envelope = sign(payload, APPROVAL_DOMAIN, key)
    try:
        approved = approval(envelope, bytes.fromhex(public))  # policy check before writing
    except Exception as refusal:
        raise SystemExit(f'staging approval refused: {refusal}') from None
    _write_private(Path(args.out), envelope)
    print(json.dumps({'approval_sha256': payload_hash(APPROVAL_DOMAIN, approved)}))


def sign_config(args):
    key, public = load_authority(Path(args.dir))
    payload = json.loads(_read_private(Path(args.payload), limit=100_000))
    approved_payload = json.loads(_read_private(Path(args.approval), limit=100_000))
    envelope = sign(payload, CONFIG_DOMAIN, key)
    try:
        configuration(envelope, bytes.fromhex(public), approved_payload)
    except Exception as refusal:
        raise SystemExit(f'staging configuration refused: {refusal}') from None
    _write_private(Path(args.out), envelope)
    print(json.dumps({'config_written': str(Path(args.out))}))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('generate', 'public-key'):
        sub = commands.add_parser(name)
        sub.add_argument('--dir', required=True, help='ignored authority directory')
    sub = commands.add_parser('sign-approval')
    sub.add_argument('--dir', required=True)
    sub.add_argument('--payload', required=True, help='approval payload JSON file')
    sub.add_argument('--out', required=True, help='envelope output path')
    sub = commands.add_parser('sign-config')
    sub.add_argument('--dir', required=True)
    sub.add_argument('--payload', required=True, help='config payload JSON file')
    sub.add_argument('--approval', required=True, help='signed approval payload JSON file')
    sub.add_argument('--out', required=True)
    args = parser.parse_args(argv)
    {'generate': generate, 'public-key': public_key,
     'sign-approval': sign_approval, 'sign-config': sign_config}[args.command](args)


if __name__ == '__main__':
    main()
