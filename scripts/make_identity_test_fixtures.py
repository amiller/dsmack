#!/usr/bin/env python3
"""Generate synthetic identity variants of our node-honest fixture.

These are metadata/parser fixtures, not Apple-signed executable variants or
valid attestations. No certificate, signing key, or third-party executable is used.
"""
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / 'contracts/fixtures/resign'


def tlv(tag, body):
    n = len(body)
    size = bytes([n]) if n < 128 else bytes([0x82]) + n.to_bytes(2, 'big') if n > 255 else bytes([0x81, n])
    return bytes([tag]) + size + body


def parts(data):
    offset = 0
    while offset < len(data):
        start = offset
        tag, n = data[offset:offset + 2]
        offset += 2
        if n >= 128:
            count = n & 127
            n = int.from_bytes(data[offset:offset + count], 'big')
            offset += count
        end = offset + n
        assert end <= len(data)
        yield tag, data[offset:end], data[start:end]
        offset = end


def without_team(ent):
    [(tag, body, _)] = list(parts(ent))
    fields = list(parts(body))
    assert tag == 0x70 and len(fields) == 2 and fields[1][0] == 0xb0
    entries = list(parts(fields[1][1]))
    kept = [raw for _, body, raw in entries
            if list(parts(body))[0][1] != b'com.apple.developer.team-identifier']
    assert len(kept) == len(entries) - 1
    return tlv(tag, fields[0][2] + tlv(0xb0, b''.join(kept)))


def variant(source, ent, replace_team=False):
    cd = bytearray.fromhex(source['cd'][2:])
    if replace_team:
        cd = bytearray(cd.replace(b'DC9JH5DRMY', b'TESTTEAM01'))
    offset = struct.unpack_from('>I', cd, 16)[0]
    seal = hashlib.sha256(struct.pack('>II', 0xfade7172, len(ent) + 8) + ent).digest()
    cd[offset - 7 * 32:offset - 6 * 32] = seal
    return {**source, 'cd': '0x' + cd.hex(), 'ent': '0x' + ent.hex(),
            'cdhash': '0x' + hashlib.sha256(cd).hexdigest()}


def main():
    source = json.loads((DIRECTORY / 'node-honest.json').read_text())
    ent = bytes.fromhex(source['ent'][2:])
    no_team = without_team(ent)
    variants = {
        'node-synthetic-team': variant(source, ent.replace(b'DC9JH5DRMY', b'TESTTEAM01'), True),
        'node-synthetic-prefix-only': variant(source, no_team),
        'node-synthetic-prefix-only-other': variant(source, no_team.replace(b'DC9JH5DRMY', b'TESTTEAM01'), True),
    }
    for name, record in variants.items():
        (DIRECTORY / (name + '.json')).write_text(json.dumps(record, indent=2) + '\n')
    print('Generated three synthetic identity fixtures from our own node-honest measurement')


if __name__ == '__main__':
    main()
