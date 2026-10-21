#!/usr/bin/env python3
import argparse
import datetime
import hashlib
import json
from pathlib import Path


def tlv(b, p):
    start = p
    size = b[p + 1]
    p += 2
    if size >= 128:
        count = size & 127
        size = int.from_bytes(b[p:p + count], 'big')
        p += count
    return start, p, p + size


def children(b, n):
    p = n[1]
    out = []
    while p < n[2]:
        child = tlv(b, p)
        out.append(child)
        p = child[2]
    assert p == n[2]
    return out


def parts(b):
    tbs = children(b, tlv(b, 0))[0]
    nodes = children(b, tbs)
    validity = children(b, nodes[4])
    times = [int(datetime.datetime.strptime('20' + b[n[1]:n[2]].decode(), '%Y%m%d%H%M%SZ')
                 .replace(tzinfo=datetime.timezone.utc).timestamp()) for n in validity]
    key = children(b, nodes[6])[1]
    point = b[key[1] + 2:key[2]]
    exts = children(b, children(b, nodes[7])[0])
    values = {}
    for ext in exts:
        items = children(b, ext)
        oid, value = items[0], items[-1]
        values[b[oid[1]:oid[2]]] = b[value[1]:value[2]]
    return times, point, values


def cbor_head(b, p):
    n = b[p] & 31
    p += 1
    if n == 24:
        n, p = b[p], p + 1
    elif n == 25:
        n, p = int.from_bytes(b[p:p + 2], 'big'), p + 2
    return n, p


def auth_extensions(b):
    count, p = cbor_head(b, 164)
    out = {}
    for _ in range(count):
        size, p = cbor_head(b, p)
        key = b[p:p + size].decode()
        p += size
        size, p = cbor_head(b, p)
        out[key] = b[p:p + size]
        p += size
    return out


def pack(b):
    assert len(b) == 32
    return [int.from_bytes(b[:16], 'big'), int.from_bytes(b[16:], 'big')]


def prepare(f):
    raw = lambda key: bytes.fromhex(f[key].removeprefix('0x'))
    leaf, ca, auth = raw('cert'), raw('intermediate'), raw('auth')
    client_hash = hashlib.sha256(raw('clientData')).digest()
    ca_point = b''
    if 'public_inputs' not in f or 'intermediate_x' not in f or 'intermediate_y' not in f:
        _, ca_point, _ = parts(ca)
    if 'public_inputs' in f:
        public = [int(v, 0) if isinstance(v, str) else v for v in f['public_inputs']]
    else:
        lt, point, exts = parts(leaf)
        subject = children(ca, children(ca, tlv(ca, 0))[0])[5]
        ae = auth_extensions(auth)
        public = (pack(auth[:32]) + pack(ae['apple_cd_hash_hash_01']) + pack(client_hash)
                  + pack(point[:32]) + pack(point[32:])
                  + lt + [int.from_bytes(auth[37:53], 'big'),
                          int.from_bytes(ae['apple_validation_category_01'], 'little')]
                  + pack(hashlib.sha256(exts[bytes.fromhex('2a864886f763640806')]).digest())
                  + [int.from_bytes(ca_point[i:i+16], 'big') for i in range(0, 96, 16)]
                  + pack(hashlib.sha256(ca[subject[0]:subject[2]]).digest()))
    assert len(public) == 24
    assert len(leaf) <= 4096 and len(auth) <= 1024
    x = raw('intermediate_x') if 'intermediate_x' in f else ca_point[:48]
    y = raw('intermediate_y') if 'intermediate_y' in f else ca_point[48:]
    assert len(x) == len(y) == 48
    return dict(leaf=list(leaf.ljust(4096, b'\0')), leaf_len=len(leaf),
                auth=list(auth.ljust(1024, b'\0')), auth_len=len(auth),
                client_hash=list(client_hash), public=[str(v) for v in public],
                intermediate_x=list(x), intermediate_y=list(y))


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('fixture', type=Path)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    witness = prepare(json.loads(a.fixture.read_text()))
    a.out.write_text(''.join(f'{k} = {json.dumps(v)}\n' for k, v in witness.items()))
