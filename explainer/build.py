"""Builds index.html from template.html + the iOS 27 / 18.5 captures and our probe binary (original + re-signed)."""
import base64, hashlib, json, struct, sys
from pathlib import Path
from cryptography import x509
H = Path(__file__).parent
DATA = H / '../data/ios'
sha = lambda b: hashlib.sha256(b).digest()

def cbor(b, p=0):
    """Returns (value, start, end); maps/arrays hold child spans as (key, (value, start, end))."""
    s, head = p, b[p]; p += 1
    major, info = head >> 5, head & 31
    n = info if info < 24 else int.from_bytes(b[p:p + (1 << (info - 24))], 'big')
    p += 0 if info < 24 else 1 << (info - 24)
    if major in (0, 1): return (n if major == 0 else -1 - n, s, p)
    if major in (2, 3): return (b[p:p + n], s, p + n)
    if major == 4:
        out = []
        for _ in range(n): v = cbor(b, p); out.append(v); p = v[2]
        return (out, s, p)
    out = []
    for _ in range(n):
        k = cbor(b, p); v = cbor(b, k[2]); out.append((k[0].decode(), k[1], v)); p = v[2]
    return (out, s, p)

def att(row):
    d = json.loads((DATA / row).read_text())
    raw = base64.b64decode(d['attestation']); top = cbor(raw)
    f = {k: v for k, _, v in top[0]}
    st = {k: v for k, _, v in f['attStmt'][0]}
    leaf = st['x5c'][0][0][0]
    cert = x509.load_der_x509_certificate(leaf)
    ext = {e.oid.dotted_string: e.value.value for e in cert.extensions if hasattr(e.value, 'value')}
    auth = f['authData'][0]
    cdh = sha(base64.b64decode(d['challenge']))
    nonce = ext['1.2.840.113635.100.8.2'][6:]
    assert nonce == sha(auth + cdh)
    osv = ext['1.2.840.113635.100.8.7']
    tags = {}
    i = 2 + (osv[1] & 0x7f if osv[1] > 0x80 else 0)
    while i < len(osv):
        j = i + 1
        t = osv[i] & 0x1f if osv[i] & 0x1f != 0x1f else None
        if t is None:
            t = 0
            while osv[j] & 0x80: t = (t << 7) | (osv[j] & 0x7f); j += 1
            t = (t << 7) | osv[j]; j += 1
        ln = osv[j]; j += 1
        inner = osv[j:j + ln]
        tags[t] = inner[2:].decode() if inner[0] == 4 else inner.hex()
        i = j + ln
    return dict(raw=raw.hex(), challenge=d['challenge'], clientDataHash=cdh.hex(),
                top=[(k, ks, v[1], v[2]) for k, ks, v in top[0]],
                attStmt=[(k, ks, v[1], v[2]) for k, ks, v in f['attStmt'][0]],
                x5c=[(c[1], c[2]) for c in st['x5c'][0]],
                cert=dict(subject=cert.subject.rfc4514_string(), issuer=cert.issuer.rfc4514_string(),
                          notBefore=str(cert.not_valid_before_utc), nonce=nonce.hex(),
                          nonceAt=raw.find(nonce), os=tags),
                authData=auth.hex(), authAt=f['authData'][1],
                ext=[(k, ks, v[1], v[2]) for k, ks, v in cbor(auth, 164)[0]] if len(auth) > 164 else [],
                cdHashAt=({k: v for k, _, v in f['cdHash'][0]}['hash'][2] - 20) if 'cdHash' in f else None)

def cd_of(b):
    off = 32
    for _ in range(struct.unpack_from('<I', b, 16)[0]):
        cmd, sz = struct.unpack_from('<II', b, off)
        if cmd == 0x1d: dataoff, datasize = struct.unpack_from('<II', b, off + 8); sigcmd = off
        if cmd == 0x19 and b[off + 8:off + 18] == b'__LINKEDIT': linkedit = off
        off += sz
    sb = b[dataoff:dataoff + datasize]
    blobs = {}
    for i in range(struct.unpack_from('>I', sb, 8)[0]):
        t, o = struct.unpack_from('>II', sb, 12 + 8 * i)
        blobs[t] = sb[o:o + struct.unpack_from('>I', sb, o + 4)[0]]
    return blobs, linkedit, sigcmd

def macho(name):
    b = (H / 'bin' / name).read_bytes()
    blobs, linkedit, sigcmd = cd_of(b)
    cd = blobs[0]
    limit = struct.unpack_from('>I', cd, 0x20)[0]
    return dict(cd=cd.hex(), cdhash=sha(cd).hex(), limit=limit, linkedit=linkedit, sigcmd=sigcmd,
                ents=blobs[5][8:].decode(), size=len(b)), b[:limit]

a27, a18 = att('iphone27-20260923/row-10.json'), att('iphone18-20261005/row-01.json')
m0, code0 = macho('honest')
m1, code1 = macho('resigned')
assert code0[16384:] == code1[16384:]
ext = cbor(bytes.fromhex(a27['authData']), 164)
assert dict((k, v[0]) for k, _, v in ext[0])['apple_cd_hash_hash_01'].hex() == m0['cdhash']
data = dict(ios27=a27, ios18=a18, orig=m0, resigned=m1,
            code=base64.b64encode(code0).decode(), page0b=base64.b64encode(code1[:16384]).decode())
(H / 'index.html').write_text((H / 'template.html').read_text().replace('/*DATA*/null', json.dumps(data)))
print('ok', {k: len(v) if isinstance(v, str) else '' for k, v in data.items()}, m0['linkedit'], m0['sigcmd'], a27['cert']['os'], a18['cert']['os'])
