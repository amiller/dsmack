#!/usr/bin/env python3
"""Measure signed executables and require one M for honest builds, another for the modified one.

The measurement is a copy of the definition in the open-admission design (section 2);
replace it with scripts/release/measure.py once that lands."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cd_args import args as cd_args  # noqa: E402

IDENTITY_KEYS = {b'application-identifier', b'com.apple.application-identifier',
                 b'com.apple.developer.team-identifier', b'keychain-access-groups'}


def be32(b, o):
    return struct.unpack_from('>I', b, o)[0]


def der(b, o):
    """Return (tag, body start, end) of the DER element at o."""
    tag, n = b[o], b[o + 1]
    if n < 0x80:
        return tag, o + 2, o + 2 + n
    k = n & 0x7f
    length = int.from_bytes(b[o + 2:o + 2 + k], 'big')
    return tag, o + 2 + k, o + 2 + k + length


def entitlement_pairs(ent):
    tag, body, end = der(ent, 0)
    assert tag == 0x70 and end == len(ent), 'entitlements wrapper'
    tag, vbody, vend = der(ent, body)
    assert tag == 0x02 and ent[vbody:vend] == b'\x01', 'entitlements version'
    tag, p, dend = der(ent, vend)
    assert tag == 0xb0 and dend == end, 'entitlements dictionary'
    while p < dend:
        tag, pbody, pend = der(ent, p)
        assert tag == 0x30, 'entitlement pair'
        ktag, kbody, kend = der(ent, pbody)
        assert ktag == 0x0c, 'entitlement key'
        yield ent[kbody:kend], ent[pbody:kend], ent[p:pend]
        p = pend


def measure(cd, page0, ent, L, S):
    off, n = be32(cd, 0x10), be32(cd, 0x1c)
    assert be32(cd, 0) == 0xfade0c02 and be32(cd, 4) == len(cd), 'CodeDirectory blob'
    assert be32(cd, 8) == 0x20500, 'CodeDirectory version'
    assert cd[0x24] == 32 and cd[0x25] == 2 and cd[0x27] == 14, 'SHA-256, 16 KiB pages'
    assert be32(cd, 0x2c) == 0 and be32(cd, 0x18) == 7, 'scatter / special slots'
    assert off + 32 * n <= len(cd) and len(page0) == 16384, 'slot bounds'
    assert cd[off - 128:off - 96] == bytes(32) and cd[off - 192:off - 160] == bytes(32), 'slots -4 and -6'
    assert hashlib.sha256(page0).digest() == cd[off:off + 32], 'page0 hash'
    sealed = struct.pack('>II', 0xfade7172, len(ent) + 8) + ent
    assert hashlib.sha256(sealed).digest() == cd[off - 224:off - 192], 'entitlements slot'
    assert struct.unpack_from('<I', page0, L)[0] == 0x19 and page0[L + 8:L + 24] == b'__LINKEDIT'.ljust(16, b'\0'), '__LINKEDIT'
    assert struct.unpack_from('<I', page0, S)[0] == 0x1d, 'LC_CODE_SIGNATURE'
    masked = bytearray(page0)
    for a, b in ((L + 32, L + 40), (L + 48, L + 56), (S + 12, S + 16)):
        masked[a:b] = bytes(b - a)
    E = b''.join(b'\x00' + key_der if key in IDENTITY_KEYS else b'\x01' + pair
                 for key, key_der, pair in entitlement_pairs(ent))
    C = (b'dsmack.measure.v1' + cd[0x08:0x10] + cd[0x1c:0x24] + cd[0x24:0x30] + cd[0x34:0x60]
         + struct.pack('>II', L, S) + hashlib.sha256(bytes(masked)).digest() + cd[off + 32:off + 32 * n] + E)
    return hashlib.sha256(C).hexdigest()


def measure_args(a):
    h = lambda k: bytes.fromhex(a[k][2:])
    return measure(h('cd'), h('page0'), h('ent'), a['linkeditCmd'], a['codeSigCmd'])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True, help='directory for one JSON vector per build')
    p.add_argument('builds', nargs=3, metavar='NAME=EXECUTABLE', help='honest-a, honest-b, modified')
    a = p.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    result = {}
    for spec in a.builds:
        name, path = spec.split('=', 1)
        vector = cd_args(path)
        vector['M'] = '0x' + measure_args(vector)
        (a.out / f'{name}.json').write_text(json.dumps(vector, indent=1) + '\n')
        result[name] = {'M': vector['M'], 'cdhash': vector['cdhash']}
    (a.out / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    ha, hb, mod = (result[k] for k in ('honest-a', 'honest-b', 'modified'))
    if not (ha['M'] == hb['M'] != mod['M']):
        raise SystemExit('Expected M(honest-a) == M(honest-b) != M(modified)')
    if len({ha['cdhash'], hb['cdhash'], mod['cdhash']}) != 3:
        raise SystemExit('Expected three different CDHashes')
    print('measure-two-teams: pass')


if __name__ == '__main__':
    main()
