#!/usr/bin/env python3
"""Compare a thin arm64 unsigned executable with its signed distribution copy.

Only the added LC_CODE_SIGNATURE and the size of __LINKEDIT may change. All
other original bytes must match. This is not a generic Mach-O normalizer.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct


def commands(data):
    if len(data) < 32 or struct.unpack_from('<II', data) != (0xfeedfacf, 0x100000c):
        raise ValueError('Expected thin arm64 Mach-O')
    count, size = struct.unpack_from('<II', data, 16)
    if count > 1000 or 32 + size > len(data):
        raise ValueError('Invalid command extent')
    result = []
    offset = 32
    for _ in range(count):
        cmd, length = struct.unpack_from('<II', data, offset)
        if length < 8 or length % 8 or offset + length > 32 + size:
            raise ValueError('Invalid load command')
        result.append((offset, cmd, length))
        offset += length
    if offset != 32 + size:
        raise ValueError('Load command size mismatch')
    return result


def verify(unsigned, signed):
    original = commands(unsigned)
    final = commands(signed)
    if any(cmd == 0x1d for _, cmd, _ in original):
        raise ValueError('Input must have no embedded signature')
    if len(final) != len(original) + 1 or final[:-1] != original:
        raise ValueError('Signing must append exactly one load command')
    offset, cmd, length = final[-1]
    if cmd != 0x1d or length != 16 or unsigned[offset:offset+16] != bytes(16):
        raise ValueError('Unexpected signature command or overwritten input bytes')
    start, size = struct.unpack_from('<II', signed, offset + 8)
    if start != (len(unsigned) + 15) // 16 * 16 or size <= 0 or start + size != len(signed):
        raise ValueError('Signature must follow unsigned EOF at 16-byte alignment')
    if signed[len(unsigned):start] != bytes(start - len(unsigned)):
        raise ValueError('Signature alignment padding must be zero')
    linkedit = [off for off, cmd, length in original
                if cmd == 0x19 and length == 72 and unsigned[off+8:off+24] == b'__LINKEDIT' + bytes(6)]
    if len(linkedit) != 1:
        raise ValueError('Expected one sectionless __LINKEDIT segment')
    off = linkedit[0]
    fileoff = struct.unpack_from('<Q', unsigned, off + 40)[0]
    if fileoff > len(unsigned):
        raise ValueError('Invalid __LINKEDIT offset')
    for data in (unsigned, signed):
        vmsize, actual_offset, filesize = struct.unpack_from('<QQQ', data, off + 32)
        expected_size = len(data) - fileoff
        if actual_offset != fileoff or filesize != expected_size or vmsize != (expected_size + 16383) // 16384 * 16384:
            raise ValueError('Unexpected __LINKEDIT size/alignment')
    normalized = bytearray(signed[:len(unsigned)])
    normalized[16:24] = unsigned[16:24]  # ncmds and sizeofcmds
    normalized[offset:offset+16] = bytes(16)
    normalized[off+32:off+40] = unsigned[off+32:off+40]  # vmsize
    normalized[off+48:off+56] = unsigned[off+48:off+56]  # filesize
    if normalized != unsigned:
        raise ValueError('Payload differs outside the allowed signing fields')
    return {'schema': 1, 'unsigned_payload_matches_signed': True,
            'unsigned_sha256': hashlib.sha256(unsigned).hexdigest(),
            'signed_sha256': hashlib.sha256(signed).hexdigest(),
            'signature_offset': start, 'signature_size': size, 'zero_alignment_padding': start - len(unsigned),
            'comparison': 'all original bytes, except appended signature load command and validated LINKEDIT sizes; only zero padding to 16-byte signature alignment'}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('unsigned', type=Path)
    p.add_argument('signed', type=Path)
    args = p.parse_args()
    print(json.dumps(verify(args.unsigned.read_bytes(), args.signed.read_bytes()), indent=2))


if __name__ == '__main__':
    main()
