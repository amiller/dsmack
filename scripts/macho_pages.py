import struct, sys, hashlib
from cd_layout import parse
def cd_of(path):
    b = open(path, "rb").read()
    ncmds = struct.unpack_from("<I", b, 16)[0]; off = 32
    for _ in range(ncmds):
        cmd, sz = struct.unpack_from("<II", b, off)
        if cmd == 0x1d:
            dataoff, datasize = struct.unpack_from("<II", b, off + 8)
            sb = b[dataoff:dataoff + datasize]; n = struct.unpack_from(">I", sb, 8)[0]
            for i in range(n):
                t, o = struct.unpack_from(">II", sb, 12 + 8 * i)
                if t == 0: return b, struct.unpack_from(">I", sb, o + 4)[0] and sb[o:o + struct.unpack_from(">I", sb, o + 4)[0]], dataoff, datasize
        off += sz
def slots(cd):
    p = parse(cd); h = p["hashOffset"]
    return p, [cd[h + 32 * i:h + 32 * i + 32] for i in range(p["nCodeSlots"])]
if __name__ == "__main__":
    out = []
    for f in sys.argv[1:]:
        b, cd, dataoff, datasize = cd_of(f); p, sl = slots(cd); ps = 1 << p["pageSize"]
        ok = all(hashlib.sha256(b[i * ps:min((i + 1) * ps, p["codeLimit"])]).digest() == s for i, s in enumerate(sl))
        print(f, "cdhash", hashlib.sha256(cd).hexdigest(), "LC_CODE_SIGNATURE dataoff", dataoff, "datasize", datasize, "codeLimit", p["codeLimit"], "pages verified vs file:", ok)
        out.append((b, sl, ps))
    if len(out) == 2:
        (b1, s1, ps), (b2, s2, _) = out
        print("code slots differing:", [i for i in range(len(s1)) if s1[i] != s2[i]], "of", len(s1))
        print("bytes differing in file (first 20):", [i for i in range(min(len(b1), len(b2))) if b1[i] != b2[i]][:20], "sizes", len(b1), len(b2))
