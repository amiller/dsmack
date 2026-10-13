"""Signer-independent code measurement M (planning: open admission §2).
Module: measure(cd, page0, ent, L, S) -> 32-byte M; inputs(path) -> dict for a signed arm64 Mach-O.
CLI: measure.py <Mach-O> prints {cdhash, M, cd, page0, ent, L, S} as JSON."""
import hashlib, json, struct, sys

TAG = b"dsmack.measure.v1"
IDENTITY = {b"application-identifier", b"com.apple.application-identifier",
            b"com.apple.developer.team-identifier", b"keychain-access-groups"}
sha = lambda b: hashlib.sha256(b).digest()
be32 = lambda b, o: struct.unpack_from(">I", b, o)[0]

def need(ok, what):
    if not ok: raise ValueError(what)

def der(b, at, limit, tag=None):
    """StrictDER.node: returns (start, body, end, tag)."""
    need(limit <= len(b) and at + 2 <= limit, "DER bounds")
    t = b[at]; need(t & 31 != 31, "DER long tag")
    n, body = b[at + 1], at + 2
    if n >= 128:
        count = n & 127; need(0 < count <= 2 and body + count <= limit, "DER length")
        need(b[body] != 0, "DER leading length zero")
        n = int.from_bytes(b[body:body + count], "big"); body += count
        need(n >= 128, "DER nonminimal length")
    need(body + n <= limit, "DER truncated")
    need(tag is None or t == tag, "DER tag")
    return at, body, body + n, t

def entitlements(ent):
    _, body, end, _ = der(ent, 0, len(ent), 0x70)
    _, vb, ve, _ = der(ent, body, end, 0x02)
    need(end == len(ent) and ve == vb + 1 and ent[vb] == 1, "entitlements")
    _, p, dend, _ = der(ent, ve, end, 0xb0)
    need(dend == end, "entitlements")
    e = b""
    while p < dend:
        ps, pb, pe, _ = der(ent, p, dend, 0x30)
        ks, kb, ke, _ = der(ent, pb, pe, 0x0c)
        need(der(ent, ke, pe)[2] == pe, "entitlements")
        e += b"\x00" + ent[ks:ke] if ent[kb:ke] in IDENTITY else b"\x01" + ent[ps:pe]
        p = pe
    return e

def app_identifier(ent):
    """The App ID the entitlements name (com.apple.application-identifier, else application-identifier): App Attest's rpId."""
    _, body, end, _ = der(ent, 0, len(ent), 0x70)
    _, p, dend, _ = der(ent, der(ent, body, end, 0x02)[2], end, 0xb0)
    found = {}
    while p < dend:
        _, pb, pe, _ = der(ent, p, dend, 0x30)
        _, kb, ke, _ = der(ent, pb, pe, 0x0c)
        _, vb, ve, t = der(ent, ke, pe)
        if t == 0x0c: found[ent[kb:ke]] = ent[vb:ve].decode()
        p = pe
    app = found.get(b"com.apple.application-identifier", found.get(b"application-identifier"))
    need(app is not None, "entitlements name no application identifier")
    return app

def measure(cd, page0, ent, L, S):
    need(len(cd) >= 0x60 and be32(cd, 0) == 0xfade0c02 and be32(cd, 4) == len(cd) and be32(cd, 8) == 0x20500, "blob")
    need(cd[0x24] == 32 and cd[0x25] == 2 and cd[0x27] == 14 and be32(cd, 0x2c) == 0 and be32(cd, 0x18) == 7, "layout")
    off, n = be32(cd, 0x10), be32(cd, 0x1c)
    need(224 <= off and off + 32 * n <= len(cd) and n > 0, "bounds")
    need(cd[off - 128:off - 96] == bytes(32) and cd[off - 192:off - 160] == bytes(32), "slots -4/-6")
    need(len(page0) == 16384 and sha(page0) == cd[off:off + 32], "page0 hash")
    need(sha(struct.pack(">II", 0xfade7172, len(ent) + 8) + ent) == cd[off - 224:off - 192], "entitlements slot")
    need(0 <= L <= 16384 - 56 and 0 <= S <= 16384 - 16 and struct.unpack_from("<I", page0, L)[0] == 0x19
         and page0[L + 8:L + 24] == b"__LINKEDIT".ljust(16, b"\0") and struct.unpack_from("<I", page0, S)[0] == 0x1d, "load commands")
    m = bytearray(page0)
    for a, b in ((L + 32, L + 40), (L + 48, L + 56), (S + 12, S + 16)): m[a:b] = bytes(b - a)
    return sha(TAG + cd[8:16] + cd[0x1c:0x30] + cd[0x34:0x60] + struct.pack(">II", L, S) + sha(bytes(m))
               + cd[off + 32:off + 32 * n] + entitlements(ent))

def inputs(path):
    b = open(path, "rb").read()
    need(struct.unpack_from("<II", b, 0) == (0xfeedfacf, 0x0100000c), "arm64 Mach-O")
    p, L, S = 32, None, None
    for _ in range(struct.unpack_from("<I", b, 16)[0]):
        cmd, size = struct.unpack_from("<II", b, p)
        if cmd == 0x19 and b[p + 8:p + 24] == b"__LINKEDIT".ljust(16, b"\0"): L = p
        if cmd == 0x1d: S = p
        p += size
    need(L is not None and S is not None, "load commands")
    dataoff, datasize = struct.unpack_from("<II", b, S + 8)
    sb = b[dataoff:dataoff + datasize]
    need(be32(sb, 0) == 0xfade0cc0, "superblob")
    blobs = {}
    for i in range(be32(sb, 8)):
        t, o = struct.unpack_from(">II", sb, 12 + 8 * i)
        blobs[t] = sb[o:o + be32(sb, o + 4)]
    need(0 in blobs and 7 in blobs and be32(blobs[7], 0) == 0xfade7172, "CodeDirectory/DER entitlements")
    return {"cd": blobs[0], "page0": b[:16384], "ent": blobs[7][8:], "L": L, "S": S}

if __name__ == "__main__":
    x = inputs(sys.argv[1])
    out = {"cdhash": "0x" + sha(x["cd"]).hex(), "M": "0x" + measure(**x).hex()}
    out.update({k: v if isinstance(v, int) else "0x" + v.hex() for k, v in x.items()})
    json.dump(out, sys.stdout, indent=1); print()
