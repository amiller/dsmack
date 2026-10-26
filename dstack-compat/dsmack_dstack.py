"""dstack guest-api-v1 key derivation and the dsmack worker-grant chain. Stdlib only, so the
in-guest agent can import it (the guest image has no crypto packages).

A dsmack guest serves dstack's GetKey from a scoped root key that a dstack
coordinator app grants per (task, worker). The returned signature chain is
[link0 by scoped root, grant by coordinator signer, signer's dstack chain (2 links)],
so a Mac-derived key verifies to the dstack KMS root but never as the coordinator's own key.
"""
import hashlib
import hmac
import struct

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def lp(x):
    if isinstance(x, str):
        x = x.encode()
    return struct.pack(">I", len(x)) + x


def _keccak_f(a):
    rol = lambda v, n: ((v << n) | (v >> (64 - n))) & (2**64 - 1)
    r = 1
    for _ in range(24):
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        a = [a[i] ^ c[(i - 1) % 5] ^ rol(c[(i + 1) % 5], 1) for i in range(25)]
        b = [0] * 25
        for i in range(25):
            x, y = i % 5, i // 5
            b[y + 5 * ((2 * x + 3 * y) % 5)] = rol(a[i], _ROT[i])
        a = [b[i] ^ (~b[(i + 1) % 5 + i - i % 5] & b[(i + 2) % 5 + i - i % 5]) for i in range(25)]
        for j in range(7):
            r = ((r << 1) ^ ((r >> 7) * 0x71)) % 256
            if r & 2:
                a[0] ^= 1 << ((1 << j) - 1)
    return a


_ROT = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14]


def keccak256(data):
    m = bytearray(data) + b"\x01" + bytes(-(len(data) + 1) % 136)
    m[-1] |= 0x80
    s = [0] * 25
    for off in range(0, len(m), 136):
        for i in range(17):
            s[i] ^= int.from_bytes(m[off + 8 * i:off + 8 * i + 8], "little")
        s = _keccak_f(s)
    return b"".join(w.to_bytes(8, "little") for w in s[:4])


def _add(a, b):
    if a is None or b is None:
        return a or b
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    lam = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) if a == b else (b[1] - a[1]) * pow(b[0] - a[0], -1, P)
    x = (lam * lam - a[0] - b[0]) % P
    return x, (lam * (a[0] - x) - a[1]) % P


def _mul(k, q):
    r = None
    while k:
        if k & 1:
            r = _add(r, q)
        q, k = _add(q, q), k >> 1
    return r


def _compress(q):
    return bytes([2 + (q[1] & 1)]) + q[0].to_bytes(32, "big")


def secp256k1_public(priv):
    return _compress(_mul(int.from_bytes(priv, "big"), G))


def _ed25519_public(seed):
    q = 2**255 - 19
    d = -121665 * pow(121666, -1, q) % q
    def add(a, b):
        t = d * a[0] * b[0] * a[1] * b[1]
        return ((a[0] * b[1] + b[0] * a[1]) * pow(1 + t, -1, q) % q, (a[1] * b[1] + a[0] * b[0]) * pow(1 - t, -1, q) % q)
    by = 4 * pow(5, -1, q) % q
    bx = pow((by * by - 1) * pow(d * by * by + 1, -1, q), (q + 3) // 8, q)
    if (bx * bx - (by * by - 1) * pow(d * by * by + 1, -1, q)) % q:
        bx = bx * pow(2, (q - 1) // 4, q) % q
    if bx & 1:
        bx = q - bx
    h = hashlib.sha512(seed).digest()
    k = int.from_bytes(h[:32], "little") & ((1 << 254) - 8) | (1 << 254)
    r, p = (0, 1), (bx, by)
    while k:
        if k & 1:
            r = add(r, p)
        p, k = add(p, p), k >> 1
    return (r[1] | (r[0] & 1) << 255).to_bytes(32, "little")


def derive(root, domain, algorithm):
    """dstack guest-api-v1 KDF (docs/guest-api-v1.md, "The KDF"): HKDF-SHA256, L = 32 (one expand block)."""
    if algorithm not in ("secp256k1", "ed25519"):
        raise ValueError("algorithm must be secp256k1 or ed25519")
    info = lp("dstack-guest-v1-key") + lp(algorithm) + lp(domain)
    prk = hmac.new(b"dstack-guest-v1", root, hashlib.sha256).digest()
    key = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    if algorithm == "secp256k1":
        if not 0 < int.from_bytes(key, "big") < N:
            raise ValueError("derived scalar out of range; choose another domain")
        return key, secp256k1_public(key)
    return key, _ed25519_public(key)


def key_claim(algorithm, domain, pub):
    return keccak256(lp("dstack-guest-v1-key-claim") + lp(algorithm) + lp(domain) + lp(pub))


def kms_message(app_id, app_root_pub):
    return keccak256(b"dstack-kms-issued:" + app_id + app_root_pub)


def grant_statement(g):
    return keccak256(lp("dsmack-worker-grant/1") + lp(g["task_id"]) + lp(g["worker_id"])
                     + lp(bytes.fromhex(g["compose_hash"])) + struct.pack(">Q", g["expires"])
                     + lp(bytes.fromhex(g["root_pub"])))


def sign(priv, digest):
    """Recoverable ECDSA r || s || recid, low-S, RFC 6979 nonce over (key, digest) as libsecp256k1 does."""
    d = int.from_bytes(priv, "big")
    mac = lambda k, m: hmac.new(k, m, hashlib.sha256).digest()
    v, k = b"\x01" * 32, mac(b"\x00" * 32, b"\x01" * 32 + b"\x00" + priv + digest)
    v = mac(k, v)
    k = mac(k, v + b"\x01" + priv + digest)
    v = mac(k, v)
    while True:
        v = mac(k, v)
        n = int.from_bytes(v, "big")
        if 0 < n < N:
            r_pt = _mul(n, G)
            r = r_pt[0] % N
            s = pow(n, -1, N) * (int.from_bytes(digest, "big") + r * d) % N
            if r and s:
                break
        k = mac(k, v + b"\x00")
        v = mac(k, v)
    rec = (r_pt[1] & 1) | (2 if r_pt[0] >= N else 0)
    if s > N // 2:
        s, rec = N - s, rec ^ 1
    return r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([rec])


def recover(sig, digest):
    r, s, rec = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big"), sig[64]
    if s > N // 2:
        raise ValueError("high-S signature")
    if not (0 < r < N and 0 < s < N and rec < 4):
        raise ValueError("malformed signature")
    x = r + (N if rec & 2 else 0)
    y = pow((x**3 + 7) % P, (P + 1) // 4, P)
    if (y * y - x**3 - 7) % P:
        raise ValueError("signature r is not on the curve")
    if y & 1 != rec & 1:
        y = P - y
    ri = pow(r, -1, N)
    q = _add(_mul(s * ri % N, (x, y)), _mul(-int.from_bytes(digest, "big") * ri % N, G))
    if q is None:
        raise ValueError("signature recovers to infinity")
    return _compress(q)


def get_key(root, domain, algorithm, tail):
    key, pub = derive(root, domain, algorithm)
    return {"key": key.hex(), "public_key": pub.hex(),
            "signature_chain": [sign(root, key_claim(algorithm, domain, pub)).hex()] + tail}


def verify_dstack_chain(pub, chain, domain, algorithm, app_id):
    """Steps 2-5 of "Verifying a chain"; returns the KMS root key the chain recovers to."""
    if len(chain) != 2:
        raise ValueError("dstack chain has %d links, expected 2" % len(chain))
    app_root = recover(chain[0], key_claim(algorithm, domain, pub))
    return recover(chain[1], kms_message(app_id, app_root))


def verify_worker_chain(pub, chain, domain, algorithm, app_id, grant, now):
    """Mac key -> grant -> coordinator signer -> KMS root. Returns the KMS root key."""
    if len(chain) != 4:
        raise ValueError("worker chain has %d links, expected 4" % len(chain))
    if now >= grant["expires"]:
        raise ValueError("grant expired")
    if recover(chain[0], key_claim(algorithm, domain, pub)).hex() != grant["root_pub"]:
        raise ValueError("link0 not signed by the granted root")
    signer = recover(chain[1], grant_statement(grant))
    return verify_dstack_chain(signer, chain[2:], grant["signer_domain"], "secp256k1", app_id)
