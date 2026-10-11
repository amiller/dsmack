"""Signed Mach-O -> CDRegistry.setBuild/registerBuild arguments (JSON on stdout).
ent = DER entitlements blob (special slot -7), empty if the signature has none."""
import hashlib, json, struct, sys
from macho_pages import cd_of
def load_commands(b):
    n = struct.unpack_from("<I", b, 16)[0]; off = 32; linkedit = codesig = None
    for _ in range(n):
        cmd, sz = struct.unpack_from("<II", b, off)
        if cmd == 0x19 and b[off + 8:off + 18] == b"__LINKEDIT": linkedit = off
        if cmd == 0x1d: codesig = off
        off += sz
    return linkedit, codesig
def der_entitlements(sb):
    for i in range(struct.unpack_from(">I", sb, 8)[0]):
        o = struct.unpack_from(">I", sb, 16 + 8 * i)[0]; magic, length = struct.unpack_from(">II", sb, o)
        if magic == 0xfade7172: return sb[o + 8:o + length]
    return b""
def args(path):
    b, cd, dataoff, datasize = cd_of(path)
    linkedit, codesig = load_commands(b)
    return {"cdhash": "0x" + hashlib.sha256(cd).hexdigest(), "cd": "0x" + cd.hex(), "page0": "0x" + b[:16384].hex(),
            "ent": "0x" + der_entitlements(b[dataoff:dataoff + datasize]).hex(), "linkeditCmd": linkedit, "codeSigCmd": codesig}
if __name__ == "__main__": json.dump(args(sys.argv[1]), sys.stdout, indent=1)
