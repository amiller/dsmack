import hashlib, struct, sys
from macho_pages import cd_of, slots
def mask(b):
    n = struct.unpack_from("<I", b, 16)[0]; off = 32; m = set()
    for _ in range(n):
        cmd, sz = struct.unpack_from("<II", b, off)
        if cmd == 0x19 and b[off + 8:off + 18] == b"__LINKEDIT": m |= set(range(off + 32, off + 40)) | set(range(off + 48, off + 56))
        if cmd == 0x1d: m |= set(range(off + 12, off + 16))
        off += sz
    return m
base = None
for f in sys.argv[1:]:
    b, cd, _, _ = cd_of(f); p, sl = slots(cd); lim = p["codeLimit"]
    if base is None: base = (b, sl, lim); m = mask(b)
    ds = [i for i in range(len(sl)) if sl[i] != base[1][i]] if len(sl) == len(base[1]) else "count differs"
    db = [i for i in range(min(lim, base[2])) if b[i] != base[0][i]]
    print(f, "cdhash", hashlib.sha256(cd).hexdigest()[:16], "pageSize", 1 << p["pageSize"], "codeLimit", lim, "slots", len(sl), "diffslots", ds, "diffbytes", len(db), "outside-mask", [i for i in db if i not in m][:5])
