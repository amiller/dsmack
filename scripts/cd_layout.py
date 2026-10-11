import struct, sys, hashlib
def parse(b):
    (magic, length, version, flags, hashOff, identOff, nSpecial, nCode, codeLimit, hashSize, hashType, platform, pageSize,
     spare2, scatter, teamOff, spare3, cl64, esBase, esLimit, esFlags) = struct.unpack_from(">IIIIIIIIIBBBBIIIIQQQQ", b)
    runtime, preEnc = struct.unpack_from(">II", b, 0x58)
    return dict(magic=hex(magic), length=length, version=hex(version), flags=flags, hashOffset=hashOff, identOffset=identOff,
                nSpecialSlots=nSpecial, nCodeSlots=nCode, codeLimit=codeLimit, hashSize=hashSize, hashType=hashType,
                platform=platform, pageSize=pageSize, scatterOffset=scatter, teamIDOffset=teamOff, codeLimit64=cl64,
                execSegBase=esBase, execSegLimit=esLimit, execSegFlags=esFlags, runtime=runtime, preEncryptOffset=preEnc)
def ranges(b, p):
    hs, hoff = p["hashSize"], p["hashOffset"]
    r = [("header", 0, p["identOffset"]),
         ("identifier", p["identOffset"], p["teamIDOffset"]),
         ("teamID", p["teamIDOffset"], hoff - p["nSpecialSlots"] * hs),
         ("special slots", hoff - p["nSpecialSlots"] * hs, hoff),
         ("code slots", hoff, hoff + p["nCodeSlots"] * hs)]
    end = hoff + p["nCodeSlots"] * hs
    if end < p["length"]: r.append(("trailing", end, p["length"]))
    return r
if __name__ == "__main__":
    bl = [open(f, "rb").read() for f in sys.argv[1:]]
    for f, b in zip(sys.argv[1:], bl):
        p = parse(b); print(f, hashlib.sha256(b).hexdigest()); print(p)
        for n, s, e in ranges(b, p): print(f"  {n:14s} [{s:#06x},{e:#06x}) {e-s} B")
    if len(bl) == 2:
        a, b = bl; assert len(a) == len(b)
        d = [i for i in range(len(a)) if a[i] != b[i]]
        print("differing bytes:", len(d))
        runs = []
        for i in d:
            if runs and i == runs[-1][1] + 1: runs[-1][1] = i
            else: runs.append([i, i])
        print("diff runs:", [(hex(s), hex(e)) for s, e in runs])
