"""Replay captured macOS evidence; never accepts a root from the evidence bundle."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from verifier.core import Policy, Reject, verify_attestation, verify_assertion
from cryptography import x509
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[2] / 'trust/apple-app-attestation-root.pem'
ROOT_SHA256 = '1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932'
APP_ID = 'DC9JH5DRMY.dev.dsmack.provider'
# macOS App Attest attestations carry apple_validation_category_01; every real Mac
# capture in evidence-20260916 reports 3. Older iOS attestations omit it; the
# 2026-09-23 iPhone ad hoc captures report 5. Mac admission requires 3 so an iOS
# attestation or an unexpected category cannot be admitted under this Mac policy.
MACOS_VALIDATION_CATEGORY = 3


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


SPECIAL_SLOTS = {1: 'Info.plist', 2: 'Requirements', 3: 'ResourceDir', 4: 'Application',
                 5: 'Entitlements', 6: 'RepSpecific', 7: 'DER-Entitlements'}
SUPERBLOB_MAGIC = {0xfade0c02: 'CodeDirectory', 0xfade0c01: 'Requirements',
                   0xfade0b01: 'RequirementSet', 0xfade7171: 'Entitlements',
                   0xfade7172: 'DER-Entitlements', 0xfade0cc0: 'EmbeddedSignature',
                   0xfade0c05: 'CMS-Signature'}


def describe_code_directory(binary):
    """Expand the CodeDirectory whose SHA-256 is the attested CDHash.

    Shows the identity, entitlement and code-page slots that the single CDHash
    transitively commits to; parsing only, no code-page verification here.
    """
    def u32(offset, endian='<'):
        return struct.unpack_from(endian + 'I', binary, offset)[0]
    if u32(0) != 0xfeedfacf:
        raise ValueError('expected thin 64-bit Mach-O')
    offset, sig = 32, None
    for _ in range(u32(16)):
        command, size = u32(offset), u32(offset + 4)
        if command == 0x1d:
            sig = binary[u32(offset + 8):u32(offset + 8) + u32(offset + 12)]
            break
        offset += size
    if sig is None or int.from_bytes(sig[:4], 'big') != 0xfade0cc0:
        raise ValueError('missing embedded signature')
    blobs, cd = {}, None
    for i in range(int.from_bytes(sig[8:12], 'big')):
        start = int.from_bytes(sig[16 + 8 * i:20 + 8 * i], 'big')
        magic = int.from_bytes(sig[start:start + 4], 'big')
        blobs[SUPERBLOB_MAGIC.get(magic, hex(magic))] = hex(magic)
        if magic == 0xfade0c02:
            cd = sig[start:start + int.from_bytes(sig[start + 4:start + 8], 'big')]
    length, version, flags, hash_offset, ident_offset, n_special, n_code, code_limit = struct.unpack_from('>8I', cd, 4)
    hash_size, hash_type, _, page_log = cd[36], cd[37], cd[38], cd[39]
    special = {}
    for i in range(1, n_special + 1):
        h = cd[hash_offset - i * hash_size:hash_offset - (i - 1) * hash_size]
        special[f'-{i} {SPECIAL_SLOTS.get(i, "?")}'] = None if h == b'\0' * hash_size else h.hex()
    return {
        'identifier': cd[ident_offset:cd.index(b'\0', ident_offset)].decode(),
        'version': hex(version), 'flags': hex(flags), 'hash_type': hash_type,
        'hash_size': hash_size, 'page_size': 1 << page_log, 'code_limit': code_limit,
        'n_code_slots': n_code, 'n_special_slots': n_special,
        'superblob': blobs, 'special_slots': special,
        'code_slots': {'count': n_code,
                       'first': cd[hash_offset:hash_offset + hash_size].hex(),
                       'last': cd[hash_offset + (n_code - 1) * hash_size:hash_offset + n_code * hash_size].hex()},
        'cdhash': hashlib.sha256(cd).hexdigest(),
    }


def root():
    pem = ROOT.read_bytes()
    der = x509.load_pem_x509_certificate(pem).public_bytes(serialization.Encoding.DER)
    if hashlib.sha256(der).hexdigest() != ROOT_SHA256:
        raise ValueError('trust anchor fingerprint mismatch')
    return pem


def policy(digest, app_id=APP_ID):
    return Policy(app_id, environment='production', cdhashes=(digest,),
                  categories=(MACOS_VALIDATION_CATEGORY,), require_macos_acl=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path, nargs='?')
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--app-id', default=APP_ID, help='TeamID.signingIdentifier (macOS RP ID)')
    parser.add_argument('--at-time', type=int, help='Explicit historical replay time; not fresh admission')
    parser.add_argument('--dump-codedirectory', action='store_true',
                        help='Expand the CodeDirectory slots behind the CDHash and exit')
    args = parser.parse_args()
    if args.dump_codedirectory:
        print(json.dumps(describe_code_directory(args.binary.read_bytes()), indent=2, sort_keys=True))
        return
    if args.capture is None:
        parser.error('capture directory required unless --dump-codedirectory')
    folder = args.capture
    digest = code_directory_hash(args.binary.read_bytes())
    challenge = folder / 'clientData.bin'
    if not challenge.exists():
        challenge = folder / 'challenge.bin'
    result = verify_attestation((folder / 'attestation.cbor').read_bytes(),
        (folder / 'keyId.txt').read_text().strip(), challenge.read_bytes(),
        policy(digest, args.app_id), root(), args.at_time)
    result.pop('receipt')
    result.update(app_id=args.app_id, expected_cdhash=digest.hex(), root_sha256=ROOT_SHA256,
        required_validation_category=MACOS_VALIDATION_CATEGORY,
        verification_time=args.at_time or 'current', status='verified_capture_not_membership_admission')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
