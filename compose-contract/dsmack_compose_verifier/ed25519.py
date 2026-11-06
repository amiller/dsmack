"""Ed25519 signature VERIFICATION only (RFC 8032), Python stdlib.

Contract3 (astra C01) requires verifier reports to be AUTHENTICATED: a
caller-pinned verifier public key must verify a signature over the exact
canonical report bytes. The contract is stdlib-only and never performs
Apple cryptography, so this module provides the minimal pure-Python
Ed25519 VERIFY path (signing is intentionally absent; tests generate keys
with their own copy of the RFC 8032 reference or use precomputed vectors).

Verify-only, no side channels of concern (public data only), constant-time
not required for this threat model (public keys and public reports). The
implementation follows RFC 8032 directly; test vectors from RFC 8032
section 7.1 are checked in tests/test_attestation.py.
"""

import hashlib

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
I = pow(2, (P - 1) // 4, P)


def _sha512(data):
    return hashlib.sha512(data).digest()


def _inv(x):
    return pow(x, P - 2, P)


def _xrecover(y):
    xx = (y * y - 1) * _inv(D * y * y + 1)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * I) % P
    if (x * x - xx) % P != 0:
        raise ValueError("point decompression failed")
    if x % 2 != 0:
        x = P - x
    return x


_BY = (4 * _inv(5)) % P
_BX = _xrecover(_BY)
_B = (_BX % P, _BY % P, 1, (_BX * _BY) % P)  # extended coordinates


def _edwards_add(pt1, pt2):
    x1, y1, z1, t1 = pt1
    x2, y2, z2, t2 = pt2
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = t1 * 2 * D * t2 % P
    dd = z1 * 2 * z2 % P
    e = b - a
    f = dd - c
    g = dd + c
    h = b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _scalarmult(pt, e):
    q = (0, 1, 1, 0)
    while e > 0:
        if e & 1:
            q = _edwards_add(q, pt)
        pt = _edwards_add(pt, pt)
        e >>= 1
    return q


def _point_equal(p1, p2):
    x1, y1, z1, _ = p1
    x2, y2, z2, _ = p2
    if (x1 * z2 - x2 * z1) % P != 0:
        return False
    if (y1 * z2 - y2 * z1) % P != 0:
        return False
    return True


def _point_decompress(s):
    if len(s) != 32:
        raise ValueError("compressed point must be 32 bytes")
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= P:
        raise ValueError("y coordinate out of range")
    x = _xrecover(y)
    if x & 1 != sign:
        x = P - x
    p = (x, y, 1, (x * y) % P)
    if not _on_curve(p):
        raise ValueError("decompressed point is not on curve")
    return p


def _on_curve(p):
    x, y, z, t = p
    return (
        z % P != 0
        and (x * y - z * t) % P == 0
        and (y * y - x * x - z * z - D * t * t) % P == 0
    )


def verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """RFC 8032 Ed25519 verification. Returns True iff the signature is valid."""
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
        return False
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
        return False
    try:
        a = _point_decompress(bytes(public_key))
    except ValueError:
        return False
    rs = bytes(signature)[:32]
    try:
        r = _point_decompress(rs)
    except ValueError:
        return False
    s = int.from_bytes(bytes(signature)[32:], "little")
    if s >= L:  # canonical scalar range check (malleability rejection)
        return False
    h = int.from_bytes(_sha512(rs + bytes(public_key) + bytes(message)), "little") % L
    sb = _scalarmult(_B, s)
    rha = _edwards_add(r, _scalarmult(a, h))
    return _point_equal(sb, rha)


__all__ = ["verify"]
