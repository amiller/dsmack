"""dsmack guest Attest: event log, client data, VersionedAttestation encoding and its reference verifier.

Stdlib only, so the in-guest agent can import it. Bytes inside the attestation are
MessagePack arrays of u8 and event payloads base64 strings, as rmp_serde's
to_vec_named encodes dstack's Vec<u8> fields and RuntimeEvent payloads.
"""
import base64
import hashlib
import struct

DOMAIN = b"dsmack.appattest.guest-attest/1"
SYSTEM_READY = "system-ready"


CANARY_GUEST_EVENT = "canary-guest-key"
P256_P = 2**256 - 2**224 + 2**192 + 2**96 - 1
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
          0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def p256_mul(k, point=P256_G):
    """k*point on P-256 (affine double-and-add; the guest has no EC library)."""
    def add(a, b):
        if a is None or b is None:
            return a or b
        if a[0] == b[0] and (a[1] + b[1]) % P256_P == 0:
            return None
        lam = (3 * a[0] * a[0] - 3) * pow(2 * a[1], -1, P256_P) if a == b else (b[1] - a[1]) * pow(b[0] - a[0], -1, P256_P)
        x = (lam * lam - a[0] - b[0]) % P256_P
        return x, (lam * (a[0] - x) - a[1]) % P256_P
    if not 0 < k < P256_N:
        raise ValueError("P-256 scalar out of range")
    r, q = None, point
    while k:
        if k & 1:
            r = add(r, q)
        q, k = add(q, q), k >> 1
    return r


def p256_public(k):
    """x || y of k*G."""
    x, y = p256_mul(k)
    return x.to_bytes(32, "big") + y.to_bytes(32, "big")


def sha256(b):
    return hashlib.sha256(b).digest()


def lp(b):
    return struct.pack(">I", len(b)) + b


def extend(head, name, payload):
    return sha256(head + sha256(lp(name.encode()) + lp(payload)))


def replay(events):
    head = bytes(32)
    for name, payload in events:
        head = extend(head, name, payload)
    return head


def client_data(os_image_hash, manifest_sha256, run, head, caller, report_data):
    fields = [os_image_hash, manifest_sha256, run, head, caller, report_data]
    if [len(f) for f in fields] != [32] * 5 + [64]:
        raise ValueError("client data fields must be 5 x 32 bytes and 64 bytes of report_data")
    return DOMAIN + b"".join(fields)


def pack(o):
    if isinstance(o, dict):
        return _head(len(o), 0x80, 0xDE) + b"".join(pack(k) + pack(v) for k, v in o.items())
    if isinstance(o, list):
        return _head(len(o), 0x90, 0xDC) + b"".join(pack(x) for x in o)
    if isinstance(o, str):
        b = o.encode()
        n = len(b)
        return (bytes([0xA0 | n]) if n < 32 else b"\xd9" + bytes([n]) if n < 256 else b"\xda" + struct.pack(">H", n)) + b
    if isinstance(o, int) and 0 <= o < 128:
        return bytes([o])
    if isinstance(o, int) and 0 <= o < 256:
        return b"\xcc" + bytes([o])
    raise TypeError("cannot pack %r" % type(o))


def _head(n, fix, wide):
    return bytes([fix | n]) if n < 16 else bytes([wide]) + struct.pack(">H", n)


def unpack(b):
    o, i = _unpack(b, 0)
    if i != len(b):
        raise ValueError("trailing bytes after attestation")
    return o


def _unpack(b, i):
    t = b[i]
    if t < 0x80:
        return t, i + 1
    if t == 0xCC:
        return b[i + 1], i + 2
    if 0xA0 <= t <= 0xBF or t in (0xD9, 0xDA):
        if t == 0xD9:
            n, i = b[i + 1], i + 2
        elif t == 0xDA:
            n, i = struct.unpack_from(">H", b, i + 1)[0], i + 3
        else:
            n, i = t & 0x1F, i + 1
        return b[i:i + n].decode(), i + n
    if 0x80 <= t <= 0x9F or t in (0xDC, 0xDE):
        is_map = t < 0x90 or t == 0xDE
        n, i = (t & 0x0F, i + 1) if t < 0xA0 else (struct.unpack_from(">H", b, i + 1)[0], i + 3)
        out = []
        for _ in range(2 * n if is_map else n):
            x, i = _unpack(b, i)
            out.append(x)
        return (dict(zip(out[::2], out[1::2])) if is_map else out), i
    raise ValueError("unsupported MessagePack type 0x%02x" % t)


def attestation(hello, caller, report_data, reply):
    """The VersionedAttestation the agent returns for one app attest reply."""
    h = {k: list(bytes.fromhex(hello[k])) for k in ("os_image_hash", "manifest_sha256", "run")}
    events = [{"event": e["name"], "payload": base64.b64encode(bytes.fromhex(e["payload"])).decode()}
              for e in reply["events"]]
    return pack({"version": 1,
                 "platform": {"kind": "apple-app-attest",
                              "data": {"key_id": list(bytes.fromhex(reply["key_id"])),
                                       "assertion": list(bytes.fromhex(reply["assertion"]))}},
                 "stack": {"kind": "dsmack",
                           "data": dict(report_data=list(report_data), **h, caller=list(caller), events=events)}})


def verify(blob):
    """Decode, replay the event log and rebuild the client data.

    Returns the fields plus client_data_hash; the caller checks the App Attest
    assertion over client_data_hash with the enrolled key for key_id.
    """
    a = unpack(blob)
    if (a["version"], a["platform"]["kind"], a["stack"]["kind"]) != (1, "apple-app-attest", "dsmack"):
        raise ValueError("not a dsmack apple-app-attest v1 attestation")
    s, p = a["stack"]["data"], a["platform"]["data"]
    events = [(e["event"], base64.b64decode(e["payload"], validate=True)) for e in s["events"]]
    if [n for n, _ in events].count(SYSTEM_READY) != 1 or events[-1] != (SYSTEM_READY, b""):
        raise ValueError("event log must end in its only system-ready")
    out = {k: bytes(s[k]) for k in ("os_image_hash", "manifest_sha256", "run", "caller", "report_data")}
    head = replay(events)
    cd = client_data(out["os_image_hash"], out["manifest_sha256"], out["run"], head, out["caller"], out["report_data"])
    return dict(out, head=head, system_events=events[:-1], key_id=bytes(p["key_id"]),
                assertion=bytes(p["assertion"]), client_data_hash=sha256(cd))
