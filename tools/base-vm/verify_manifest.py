#!/usr/bin/env python3
"""Consumer-side image-admission verifier for the dstack-derived minimal ARM64
image bundle (files/ directory produced by build_image_arm64.sh).

Adopts the dstack checksum-manifest identity (os/image/assemble.sh @ 247c3add):
    os_image_hash = sha256(sha256sum.txt)
with this profile's documented arm64 deltas (rootfs image included in the
checksum manifest; no firmware/TEE measurement artifacts).

Checks (fail-closed, each with a precise reason on failure):
  1. artifact-manifest.json present, schema_version=1, verity fields well-formed
  2. every artifact-manifest artifact path exists
  3. sha256sum.txt covers exactly the expected file set and every hash matches
  4. digest.txt == sha256(sha256sum.txt)  -> this is os_image_hash
  5. metadata.json binds kernel/initrd/rootfs names + cmdline; cmdline carries
     dstack.rootfs_hash == artifact-manifest verity.root_hash and
     dstack.rootfs_size == verity.data_size
  6. dm-verity root hash recomputed from rootfs.squashfs.verity matches
     (veritysetup verify; run where veritysetup exists, e.g. the builder image)
  7. tamper self-test mode: verifies that a single flipped byte in a COPY of the
     rootfs is rejected (proves check 6 actually discriminates)

Usage:
  verify_manifest.py <files-dir>                     # checks 1-5 (+6 if veritysetup present)
  verify_manifest.py <files-dir> --tamper-test       # adds 7, using a temp copy
Exit 0 = admitted; nonzero with reasons = rejected.
"""
import hashlib, json, os, re, shutil, subprocess, sys, tempfile

EXPECTED_CHECKSUM_FILES = ["Image", "initramfs.cpio.gz", "metadata.json", "rootfs.squashfs.verity"]


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    d = sys.argv[1]
    tamper = "--tamper-test" in sys.argv
    problems = []

    am_path = os.path.join(d, "artifact-manifest.json")
    if not os.path.isfile(am_path):
        print("REJECT: artifact-manifest.json missing"); return 2
    am = json.load(open(am_path))
    if am.get("schema_version") != 1:
        problems.append(f"artifact-manifest schema_version {am.get('schema_version')!r} != 1")
    for key in ("backend", "image", "source", "boot", "verity", "artifacts"):
        if key not in am:
            problems.append(f"artifact-manifest missing required key {key}")
    root_hash = am.get("verity", {}).get("root_hash", "")
    data_size = str(am.get("verity", {}).get("data_size", ""))
    if not re.fullmatch(r"[0-9a-f]{64}", root_hash):
        problems.append("verity.root_hash not a 64-hex digest")
    if not data_size.isdigit():
        problems.append("verity.data_size not a positive integer")
    arts = am.get("artifacts", {})
    for name in ("initramfs", "kernel", "rootfs_verity"):
        rel = arts.get(name)
        if not isinstance(rel, str) or not os.path.isfile(os.path.join(d, rel)):
            problems.append(f"artifact {name} missing or not a path: {rel!r}")
    for name in ("firmware", "firmware_sev", "uki"):
        if name not in arts:
            problems.append(f"artifacts missing key {name} (must be path or null on arm64)")

    # checksum manifest
    sum_path = os.path.join(d, "sha256sum.txt")
    if not os.path.isfile(sum_path):
        print("REJECT: sha256sum.txt missing"); return 2
    listed = {}
    for line in open(sum_path):
        h, _, name = line.strip().partition("  ")
        if not h or not name:
            problems.append(f"unparsable sha256sum.txt line: {line!r}"); continue
        listed[name] = h
    if sorted(listed) != sorted(EXPECTED_CHECKSUM_FILES):
        problems.append(f"sha256sum.txt covers {sorted(listed)} != expected {sorted(EXPECTED_CHECKSUM_FILES)}")
    for name, h in sorted(listed.items()):
        p = os.path.join(d, name)
        if not os.path.isfile(p):
            problems.append(f"checksummed file missing: {name}"); continue
        got = sha256_file(p)
        if got != h:
            problems.append(f"{name}: sha256sum.txt says {h}, file hashes {got}")

    digest_path = os.path.join(d, "digest.txt")
    if not os.path.isfile(digest_path):
        print("REJECT: digest.txt missing"); return 2
    claimed = open(digest_path).read().strip()
    computed = sha256_file(sum_path)
    if claimed != computed:
        problems.append(f"digest.txt {claimed} != sha256(sha256sum.txt) {computed}")

    # metadata binds identity + cmdline
    md = json.load(open(os.path.join(d, "metadata.json")))
    for k in ("kernel", "cmdline", "initrd", "rootfs", "version", "git_revision", "builder"):
        if k not in md:
            problems.append(f"metadata.json missing {k}")
    cl = md.get("cmdline", "")
    m = re.search(r"(?:^| )dstack\.rootfs_hash=([0-9a-f]{64})(?: |$)", cl)
    if not m:
        problems.append("cmdline has no dstack.rootfs_hash")
    elif m.group(1) != root_hash:
        problems.append(f"cmdline rootfs_hash {m.group(1)} != manifest verity.root_hash {root_hash}")
    m = re.search(r"(?:^| )dstack\.rootfs_size=([0-9]+)(?: |$)", cl)
    if not m:
        problems.append("cmdline has no dstack.rootfs_size")
    elif m.group(1) != data_size:
        problems.append(f"cmdline rootfs_size {m.group(1)} != manifest verity.data_size {data_size}")
    for k, f in (("kernel", "Image"), ("initrd", "initramfs.cpio.gz"), ("rootfs", "rootfs.squashfs.verity")):
        if md.get(k) != f:
            problems.append(f"metadata {k}={md.get(k)!r} != {f!r}")

    # dm-verity recompute (the verified-byte boot gate). Success criterion is
    # the EXIT CODE: cryptsetup 2.7.x veritysetup verify returns 0 on a match
    # and prints NOTHING on success (observed in this builder image; older
    # versions printed "Hash matched"), nonzero with a message on mismatch.
    def verity_check(path, expected_hash, size):
        if shutil.which("veritysetup") is None:
            return None  # skipped, reported below
        r = subprocess.run(["veritysetup", "verify", path, path,
                            "--hash-offset", size, "--data-block-size", "4096",
                            "--hash-block-size", "4096",
                            "--uuid", "00000000-0000-0000-0000-000000000000",
                            "--salt", "0" * 64, expected_hash],
                           capture_output=True, text=True)
        return r.returncode == 0, (r.stdout + r.stderr).strip()

    rootfs = os.path.join(d, "rootfs.squashfs.verity")
    verity_status = "skipped (veritysetup not on PATH; rerun inside the builder image)"
    if os.path.isfile(rootfs) and root_hash and data_size.isdigit():
        res = verity_check(rootfs, root_hash, data_size)
        if res is not None:
            ok, out = res
            verity_status = "verified" if ok else "MISMATCH"
            if not ok:
                problems.append(f"dm-verity root hash recompute failed: {out[-300:]}")

    tamper_status = "skipped"
    if tamper and os.path.isfile(rootfs) and shutil.which("veritysetup"):
        with tempfile.NamedTemporaryFile(dir=d, prefix=".tamper-", delete=False) as t:
            shutil.copyfile(rootfs, t.name)
            t.seek(2048); b = t.read(1); t.seek(2048); t.write(bytes([b[0] ^ 0x40]))
            t.close()
            res = verity_check(t.name, root_hash, data_size)
            os.unlink(t.name)
            rejected = res is not None and res[0] is False
            tamper_status = "tamper-rejected" if rejected else "FAILED-TO-REJECT"
            if not rejected:
                problems.append("TAMPER TEST FAILED: a mutated rootfs was NOT rejected by verity recompute")

    if problems:
        print("REJECT:")
        for p in problems:
            print("  -", p)
        return 1
    print(f"ADMIT os_image_hash={claimed}")
    print(f"  verity: {verity_status}; tamper-test: {tamper_status}")
    print(f"  cmdline: {cl}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
