"""Signed thin arm64 Mach-O -> CDRegistry.setBuild/registerBuild arguments (JSON on stdout)."""
import hashlib, json, struct, sys
def args(path):
    b = open(path, "rb").read()
    if struct.unpack_from("<II", b) != (0xfeedfacf, 0x0100000c): raise ValueError("not a thin arm64 Mach-O; lipo -thin arm64 first")
    ncmds, sizeofcmds = struct.unpack_from("<II", b, 16)
    off, end, linkedit, codesig = 32, 32 + sizeofcmds, [], []
    if end > 16384: raise ValueError("load commands exceed page 0")
    for _ in range(ncmds):
        cmd, sz = struct.unpack_from("<II", b, off)
        if sz < 8 or off + sz > end: raise ValueError("load command outside sizeofcmds")
        if cmd == 0x19 and b[off + 8:off + 24] == b"__LINKEDIT".ljust(16, b"\0"): linkedit.append(sz)
        if cmd == 0x1d: codesig.append((off, sz))
        off += sz
    if linkedit != [72] or [sz for _, sz in codesig] != [16]: raise ValueError("need one __LINKEDIT and one LC_CODE_SIGNATURE")
    codesig = codesig[0][0]
    dataoff, datasize = struct.unpack_from("<II", b, codesig + 8)
    sb = b[dataoff:dataoff + datasize]; blobs = {}
    for i in range(struct.unpack_from(">I", sb, 8)[0]):
        t, o = struct.unpack_from(">II", sb, 12 + 8 * i)
        magic, length = struct.unpack_from(">II", sb, o)
        blobs.setdefault(t, (magic, sb[o:o + length]))
    magic, cd = blobs[0]
    if magic != 0xfade0c02: raise ValueError("slot 0 is not a CodeDirectory")
    ent = next((blob[8:] for m, blob in blobs.values() if m == 0xfade7172), b"")
    return {"cdhash": "0x" + hashlib.sha256(cd).hexdigest(), "cd": "0x" + cd.hex(), "page0": "0x" + b[:16384].hex(),
            "ent": "0x" + ent.hex()}
if __name__ == "__main__": json.dump(args(sys.argv[1]), sys.stdout, indent=1)
