"""Replay captured macOS evidence; never accepts a root from the evidence bundle."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from verifier.core import Policy, Reject, verify_attestation, verify_assertion
from cryptography import x509
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[1] / 'trust/apple-app-attestation-root.pem'
ROOT_SHA256 = '1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932'
APP_ID = 'DC9JH5DRMY.dev.dsmack.provider'


def code_directory_hash(binary):
    """Extract SHA256 CodeDirectory from the captured thin arm64 Mach-O.

    This identifies the CodeDirectory, not a source build. Its individual code
    page hashes are checked against the file rather than trusted as metadata.
    """
    def u32(offset, endian='<'):
        return struct.unpack_from(endian + 'I', binary, offset)[0]
    if u32(0) != 0xfeedfacf:
        raise ValueError('expected thin 64-bit Mach-O')
    offset = 32
    for _ in range(u32(16)):
        command, size = u32(offset), u32(offset + 4)
        if size < 8 or offset + size > len(binary):
            raise ValueError('invalid load command')
        if command == 0x1d:
            start, length = u32(offset + 8), u32(offset + 12)
            break
        offset += size
    else:
        raise ValueError('missing code signature')
    sig = binary[start:start + length]
    def be(offset):
        return struct.unpack_from('>I', sig, offset)[0]
    if len(sig) != length or be(0) != 0xfade0cc0:
        raise ValueError('invalid signature superblob')
    for index in range(be(8)):
        kind, offset = be(12 + 8 * index), be(16 + 8 * index)
        if kind == 0:
            cd = sig[offset:offset + be(offset + 4)]
            break
    else:
        raise ValueError('missing primary CodeDirectory')
    fields = struct.unpack_from('>9I4B', cd)
    magic, length, version, flags, hash_offset, ident_offset, special, count, limit, hash_size, hash_type, platform, page = fields
    if magic != 0xfade0c02 or length != len(cd) or hash_size != 32 or hash_type != 2 or not 12 <= page <= 16:
        raise ValueError('unsupported CodeDirectory')
    if limit > start or count != (limit + (1 << page) - 1) >> page:
        raise ValueError('invalid code page extent')
    for index in range(count):
        data = binary[index * (1 << page):min((index + 1) * (1 << page), limit)]
        expected = cd[hash_offset + index * 32:hash_offset + (index + 1) * 32]
        if hashlib.sha256(data).digest() != expected:
            raise ValueError('code page hash mismatch')
    return hashlib.sha256(cd).digest()


def root():
    pem = ROOT.read_bytes()
    der = x509.load_pem_x509_certificate(pem).public_bytes(serialization.Encoding.DER)
    if hashlib.sha256(der).hexdigest() != ROOT_SHA256:
        raise ValueError('trust anchor fingerprint mismatch')
    return pem


def policy(digest):
    return Policy(APP_ID, environment='production', cdhashes=(digest,), require_macos_acl=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--at-time', type=int, help='Explicit historical replay time; not fresh admission')
    args = parser.parse_args()
    folder = args.capture
    digest = code_directory_hash(args.binary.read_bytes())
    challenge = folder / 'clientData.bin'
    if not challenge.exists():
        challenge = folder / 'challenge.bin'
    result = verify_attestation((folder / 'attestation.cbor').read_bytes(),
        (folder / 'keyId.txt').read_text().strip(), challenge.read_bytes(), policy(digest), root(), args.at_time)
    result.pop('receipt')
    result.update(expected_cdhash=digest.hex(), root_sha256=ROOT_SHA256,
        verification_time=args.at_time or 'current', status='verified_capture_not_membership_admission')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
