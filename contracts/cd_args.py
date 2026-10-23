"""Signed thin arm64 Mach-O -> CDRegistry.setBuild/registerBuild arguments (JSON on stdout)."""
import hashlib, json, struct, sys

def inspect_bytes(b):
    """Inspect signed thin arm64 bytes, including EVERY CodeDirectory/code page.

    This is an integrity check, not CMS/Apple certificate or bundle verification.
    Deliberately rejects scatter and unsupported hash formats instead of guessing.
    """
    def require(ok, why):
        if not ok:
            raise ValueError(why)
    def u32(data, off):
        require(0 <= off <= len(data) - 4, "truncated integer")
        return struct.unpack_from(">I", data, off)[0]
    require(len(b) >= 32, "truncated Mach-O")
    require(struct.unpack_from("<II", b) == (0xfeedfacf, 0x0100000c),
            "need thin arm64 Mach-O")
    ncmds, sizeofcmds = struct.unpack_from("<II", b, 16)
    end, off, signatures = 32 + sizeofcmds, 32, []
    require(end <= min(len(b), 16384), "load commands exceed page 0/file")
    require(ncmds <= sizeofcmds // 8, "invalid load-command count")
    for _ in range(ncmds):
        require(off + 8 <= end, "truncated load command")
        cmd, size = struct.unpack_from("<II", b, off)
        require(size >= 8 and size % 8 == 0 and off + size <= end,
                "invalid load-command size")
        if cmd == 0x1d:
            require(size == 16, "invalid LC_CODE_SIGNATURE")
            signatures.append(struct.unpack_from("<II", b, off + 8))
        off += size
    require(off == end and len(signatures) == 1, "need exactly one signature command")
    start, size = signatures[0]
    require(start >= end and size >= 12 and start + size == len(b),
            "signature must be bounded at EOF")
    sb = b[start:]
    require(u32(sb, 0) == 0xfade0cc0, "invalid signature SuperBlob")
    length, count = u32(sb, 4), u32(sb, 8)
    require(12 <= length <= size and count <= (length - 12) // 8,
            "invalid SuperBlob bounds")
    blobs, ranges = {}, []
    for i in range(count):
        slot, pos = struct.unpack_from(">II", sb, 12 + i * 8)
        require(slot not in blobs, "duplicate signature slot")
        require(pos >= 12 + count * 8 and pos + 8 <= length, "blob index out of bounds")
        blen = u32(sb, pos + 4)
        require(blen >= 8 and pos + blen <= length, "blob length out of bounds")
        require(all(pos + blen <= lo or pos >= hi for lo, hi in ranges), "overlapping blobs")
        ranges.append((pos, pos + blen))
        blobs[slot] = sb[pos:pos + blen]
    require(0 in blobs, "missing primary CodeDirectory")
    directories = []
    for slot, cd in sorted(blobs.items()):
        is_cd = u32(cd, 0) == 0xfade0c02
        require(is_cd == (slot == 0 or 0x1000 <= slot <= 0x1005),
                "CodeDirectory magic/slot mismatch")
        if not is_cd:
            continue
        require(len(cd) >= 44, "short CodeDirectory")
        version, flags, hashes, ident, special, pages, limit = struct.unpack_from(">7I", cd, 8)
        hsize, htype, platform, power = struct.unpack_from("4B", cd, 36)
        require(htype in (1, 2, 3, 4), "unsupported CodeDirectory hash")
        algorithm, expected_size = {1: ("sha1", 20), 2: ("sha256", 32),
                                   3: ("sha256", 20), 4: ("sha384", 48)}[htype]
        require(hsize == expected_size, "hash size/type mismatch")
        minimum = 44
        if version >= 0x20100:
            minimum = 48
            require(len(cd) >= minimum and u32(cd, 44) == 0, "scatter CodeDirectory unsupported")
        if version >= 0x20200:
            minimum = 52
        if version >= 0x20300:
            minimum = 64
            require(len(cd) >= minimum, "short CodeDirectory v20300")
            wide = struct.unpack_from(">Q", cd, 56)[0]
            if limit == 0xffffffff:
                limit = wide
            else:
                require(wide in (0, limit), "conflicting code limits")
        if version >= 0x20400:
            minimum = 88
        if version >= 0x20500:
            minimum = 96
        if version >= 0x20600:
            minimum = 108
        require(version <= 0x20600 and len(cd) >= minimum, "unsupported/short CodeDirectory version")
        require(power <= 20 and 0 < limit == start, "invalid page size/code limit")
        page_size = (1 << power) if power else limit
        require(pages == (limit + page_size - 1) // page_size, "wrong code-page count")
        require(special <= 64 and hashes - special * hsize >= minimum,
                "special hash table overlaps header")
        require(hashes + pages * hsize <= len(cd), "code hash table out of bounds")
        def text(offset):
            require(minimum <= offset < hashes - special * hsize, "identifier out of bounds")
            nul = cd.find(b"\0", offset, hashes - special * hsize)
            require(nul >= 0, "unterminated identifier")
            return cd[offset:nul].decode("utf-8", "strict")
        identifier = text(ident)
        team_offset = u32(cd, 48) if version >= 0x20200 else 0
        team = text(team_offset) if team_offset else None
        for i in range(pages):
            actual = hashlib.new(algorithm, b[i * page_size:min(limit, (i + 1) * page_size)]).digest()[:hsize]
            require(actual == cd[hashes + i * hsize:hashes + (i + 1) * hsize],
                    "code page mismatch: slot %d page %d" % (slot, i))
        checked_special = []
        for i in range(1, special + 1):
            digest = cd[hashes - i * hsize:hashes - (i - 1) * hsize]
            if i in blobs:
                actual = hashlib.new(algorithm, blobs[i]).digest()[:hsize]
                require(actual == digest, "embedded special-slot mismatch: %d" % i)
                checked_special.append(i)
        directories.append({"slot": slot, "full_digest": hashlib.new(algorithm, cd).hexdigest(),
                            "sha256": hashlib.sha256(cd).hexdigest(), "hash_type": htype,
                            "identifier": identifier, "team": team, "flags": flags,
                            "code_limit": limit, "page_size": page_size,
                            "code_pages_verified": pages, "special_slots": special,
                            "embedded_special_slots_verified": checked_special})
    return {"schema": "dsmack-mach-o-inspection/1", "sha256": hashlib.sha256(b).hexdigest(),
            "bytes": len(b), "architecture": "arm64", "code_directories": directories,
            "code_pages_verified": True, "apple_signature_verified": False,
            "external_bundle_resources_verified": False}, blobs

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
