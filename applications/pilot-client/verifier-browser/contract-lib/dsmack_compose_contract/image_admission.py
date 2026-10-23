"""External image admission + verified-byte boot identity (contract4.1; E01/E02).

Image identity follows the DELIVERED dstack checksum manifest format exactly
(``sha256sum.txt``): ``os_image_hash`` is the SHA256 of the EXACT manifest
bytes, and the boot-component pins in ``manifest.base_vm`` must equal the
entries under their DELIVERED names. The dstack-base-image2 bundle carries
exactly four entries -- ``Image`` (arm64 kernel image), ``initramfs.cpio.gz``,
``metadata.json`` and ``rootfs.squashfs.verity`` -- so the identity mapping is
those exact names. Renaming or adding entries changes ``os_image_hash``; there
is no compatibility-by-rename (the delivered layout IS the identity).

ADMISSION AUTHENTICATES THE WHOLE BOOT TUPLE (E01): the metadata document
bytes are pinned (``metadata_sha256``) and consumed by admission. Admission
requires the metadata-declared cmdline to equal ``base_vm.cmdline`` byte for
byte, the cmdline's ``dstack.rootfs_hash`` to equal ``base_vm.verity_root_hash``,
``dstack.rootfs_size`` to define the verity data size, ``dstack.rootfs_device``
to be the declared verity root device, the metadata platform to agree with
``base_vm.architecture``, and ``is_dev`` to be false (dev images are never
admissible). Verity geometry is FROZEN from the ACTUAL bundle bytes, not
derived from a layout assumption (contract6 R01): the data region is
``[0, data_size)``, the dm-verity superblock occupies the FIRST block of
the hash region ``[data_size, data_size + 4096)``, and the hash tree
follows TOP-DOWN (root block immediately after the superblock, descending
levels, leaf digests LAST -- the final block of the file is tree data).
``verify_stored_verity_image`` inspects the stored superblock parameters
and byte-locates every tree level; ``recompute_verity_root`` remains a
DATA-ROOT recomputation that is explicitly separate from stored-image
verification. Both bundles delivered to date share this exact geometry
(data 209592320; superblock at 209592320; root block at 209596416; L1 at
209600512; leaves at 209616896; total 211255296) with different root
hashes, and the layout was cross-checked against veritysetup 2.4.3
reference output and the delivered initramfs' own
``veritysetup open --hash-offset`` consumption.

ADMITS ARE EXTERNAL DECISIONS: a separately configured admission document
(outside the signed app) lists allowed ``os_image_hash`` values; ``admit_image``
fails closed on anything else and returns a decision record bound to the
admission bytes themselves.

VERIFIED-BYTE LOADING -- TWO ROUTES, UNEQUAL CLAIMS (E02, spike R1/R2):

  OWNED-COPY ROUTE (the admitted-boot invariant, boot-binding-spike DESIGN R1+
  R2, authoritative): the backend COPIES each component's bytes once into
  backend-owned immutable storage, hashes the OWNED COPY against the
  admission-bound pins, and CONSUMES THAT COPY (guest RAM / VM disk populated
  from the owned bytes). There is no second read of any host path between
  verification and consumption. ``own_component`` + ``consume`` implement this;
  ``build_boot_observation`` verifies the kernel architecture header, the
  verity root (recomputed over the owned rootfs bytes), and the metadata copy,
  and emits the receipt boot object with ``loader_mode: "owned-copy"``.

  HELD-FD ROUTE (ENGINEERING TRANSPORT ONLY): stage once, open O_NOFOLLOW,
  hash through the descriptor, hold, re-verify through the SAME descriptor
  before boot. This closes the loader's own path-swap TOCTOU but a held
  ordinary-file descriptor does NOT prevent same-inode modification after the
  final hash, and a QEMU-style consumer re-reads through a path. Receipts
  recorded with ``loader_mode: "held-fd"`` are therefore ENGINEERING
  TRANSPORT evidence (interfaces/base-vm-handoff.md); the owned-copy invariant
  is the only route that backs the verified-byte boot-binding claim.

HONEST BOUNDARY (unchanged): neither route makes VM memory immune to a
compromised host root; platform contract A stays open. Hardware qualification
is not claimed and is not required for the contract implementation itself.
"""

import hashlib
import os
import stat

from .canonical import load_json_bytes, sha256_hex
from .errors import ContractError, ImageAdmissionError

#: Fixed component mapping for the DELIVERED dstack checksum-manifest format
#: (E01): the exact entry names in dstack-base-image2/build/artifacts/sha256sum.txt.
#: Exactly these four entries, exactly these names; the byte layout of the
#: manifest is what ``os_image_hash`` covers.
COMPONENT_PATHS = {
    "kernel_sha256": "Image",
    "initrd_sha256": "initramfs.cpio.gz",
    "metadata_sha256": "metadata.json",
    "rootfs_sha256": "rootfs.squashfs.verity",
}
CHECKSUM_MANIFEST_PATHS = tuple(sorted(COMPONENT_PATHS.values()))

#: Metadata document (dstack metadata.json): exact key set and required values.
METADATA_KEYS = {
    "kernel",
    "cmdline",
    "initrd",
    "rootfs",
    "version",
    "git_revision",
    "builder",
    "shared_ro",
    "is_dev",
    "platform",
    "os_image_hash_def",
}
#: The identity derivation statement the metadata must carry.
OS_IMAGE_HASH_DEF = "sha256(sha256sum.txt)"
#: Metadata platform spellings -> base_vm architectures.
METADATA_ARCH = {"arm64": "aarch64", "amd64": "x86_64", "x86_64": "x86_64", "aarch64": "aarch64"}

#: dm-verity parameters FROZEN from the ACTUAL bundle bytes (R01; verified
#: against both delivered bundles and against veritysetup 2.4.3 reference
#: output: salt = 64 zero hex chars, uuid 0, 4096/4096 blocks, fanout 128,
#: hash-region offset == data size, superblock as the FIRST hash-region
#: block, tree stored TOP-DOWN with the leaf digests last).
VERITY_SALT_HEX = "0" * 64
VERITY_SALT_BYTES = bytes(32)
VERITY_BLOCK_BYTES = 4096
VERITY_FANOUT = 128
VERITY_ROOTFS_DEVICE = "/dev/vda"

#: R01: the frozen on-disk region order of a dstack verity rootfs image.
#: ``hash_offset_bytes`` (== data size) is where the HASH REGION starts: the
#: superblock is its first block and the tree follows immediately, TOP-DOWN
#: (root block first, leaf digests last). The final block of the file is
#: therefore always tree data, never the superblock. Levels are listed
#: top-down; each level is zero-padded to whole hash blocks (the padding is
#: part of the verified layout and must stay zero).
VERITY_REGION_ORDER = ("data", "superblock", "tree")

MAX_CHECKSUM_MANIFEST_ENTRIES = 64
MAX_CHECKSUM_MANIFEST_BYTES = 65536
MAX_METADATA_BYTES = 65536
MAX_ADMISSION_BYTES = 65536
ADMISSION_VERSION = 1

READ_CHUNK = 1024 * 1024

#: Loader modes for the receipt boot observation (E02).
LOADER_OWNED_COPY = "owned-copy"
LOADER_HELD_FD = "held-fd"
LOADER_MODES = (LOADER_OWNED_COPY, LOADER_HELD_FD)


# ------------------------------------------------------------------ checksum manifest


def parse_checksum_manifest(manifest_bytes):
    """Parse the exact checksum-manifest bytes (delivered dstack sha256sum.txt).

    Format: LF-separated lines of "<64 lowercase hex>  <path>"; the byte
    layout is exactly what ``os_image_hash`` covers. Structural rules: bounded
    byte size and entry count, no duplicate paths, exactly the delivered
    component path set, sorted by path. Raises ImageAdmissionError on any
    violation (value-free diagnostics).
    """
    if not isinstance(manifest_bytes, (bytes, bytearray)):
        raise ImageAdmissionError("checksum manifest must be bytes")
    if len(manifest_bytes) > MAX_CHECKSUM_MANIFEST_BYTES:
        raise ImageAdmissionError(
            "checksum manifest is %d bytes, exceeding the %d-byte bound" % (len(manifest_bytes), MAX_CHECKSUM_MANIFEST_BYTES)
        )
    text = bytes(manifest_bytes).decode("utf-8", errors="replace")
    if not text.endswith("\n"):
        raise ImageAdmissionError("checksum manifest must end with a newline-terminated final line")
    lines = text.split("\n")[:-1]
    if not lines or len(lines) > MAX_CHECKSUM_MANIFEST_ENTRIES:
        raise ImageAdmissionError("checksum manifest must hold between 1 and %d entries" % MAX_CHECKSUM_MANIFEST_ENTRIES)
    entries = {}
    order = []
    for line in lines:
        if len(line) < 67 or line[64:66] != "  ":
            raise ImageAdmissionError("checksum manifest line is not '<64hex>  <path>'")
        digest, path = line[:64], line[66:]
        if any(c not in "0123456789abcdef" for c in digest):
            raise ImageAdmissionError("checksum manifest line digest is not 64 lowercase hex")
        if path not in COMPONENT_PATHS.values():
            raise ImageAdmissionError("checksum manifest contains a path outside the delivered dstack component layout")
        if path in entries:
            raise ImageAdmissionError("checksum manifest has a duplicate component path")
        entries[path] = digest
        order.append(path)
    if order != sorted(order):
        raise ImageAdmissionError("checksum manifest entries must be sorted by path")
    missing = set(COMPONENT_PATHS.values()) - set(entries)
    if missing:
        raise ImageAdmissionError("checksum manifest is missing %d delivered component path(s)" % len(missing))
    return entries


def os_image_hash(manifest_bytes):
    """The image identity: SHA256 over the EXACT checksum-manifest bytes."""
    return sha256_hex(manifest_bytes)


# ------------------------------------------------------------------ metadata + verity


def parse_metadata(metadata_bytes):
    """Parse the image metadata document under the strict JSON profile.

    Bounded size; exact key set (unknown keys reject: the metadata is part of
    the authenticated identity, and extra keys must not silently extend it).
    """
    if not isinstance(metadata_bytes, (bytes, bytearray)):
        raise ImageAdmissionError("image metadata must be bytes")
    if len(metadata_bytes) > MAX_METADATA_BYTES:
        raise ImageAdmissionError("image metadata exceeds the %d-byte bound" % MAX_METADATA_BYTES)
    try:
        doc = load_json_bytes(metadata_bytes, "image metadata", max_bytes=MAX_METADATA_BYTES)
    except ContractError as exc:
        raise ImageAdmissionError("image metadata is invalid: %s" % exc) from None
    if not isinstance(doc, dict) or set(doc) != METADATA_KEYS:
        raise ImageAdmissionError("image metadata must have exactly the documented key set")
    for key in ("kernel", "cmdline", "initrd", "rootfs", "version", "git_revision", "builder", "platform", "os_image_hash_def"):
        if not isinstance(doc[key], str) or not doc[key]:
            raise ImageAdmissionError("image metadata.%s must be a non-empty string" % key)
    if not isinstance(doc["shared_ro"], bool) or not isinstance(doc["is_dev"], bool):
        raise ImageAdmissionError("image metadata.shared_ro and metadata.is_dev must be booleans")
    if doc["os_image_hash_def"] != OS_IMAGE_HASH_DEF:
        raise ImageAdmissionError("image metadata.os_image_hash_def must document the frozen identity derivation")
    if doc["is_dev"]:
        raise ImageAdmissionError("image metadata.is_dev is true; dev images are never admissible")
    return doc


def _cmdline_field(cmdline, field):
    """Extract '<field>=<value>' from the metadata cmdline (bounded token scan)."""
    for token in cmdline.split(" "):
        if token.startswith(field + "="):
            return token[len(field) + 1:]
    return None


def _cmdline_rootfs_size(cmdline):
    for token in cmdline.split(" "):
        if token.startswith("dstack.rootfs_size="):
            digits = token[len("dstack.rootfs_size="):]
            if digits.isdigit() and len(digits) <= 15:
                return int(digits)
            return None
    return None


def verity_layout(data_bytes):
    """FROZEN dm-verity geometry for a dstack verity rootfs image (E01, R01).

    data_bytes must be block-aligned. The on-disk region order is frozen
    (VERITY_REGION_ORDER): data ``[0, data_bytes)``, then the hash region
    starting at ``hash_offset_bytes == data_bytes`` -- the superblock as its
    FIRST block, then the hash tree stored TOP-DOWN (root block, descending
    levels, leaf digests last; fanout 128, 32-byte sha256 digests, each
    level zero-padded to whole blocks). Verified against the delivered
    bundle: data 209592320 -> 51170 data blocks, tree levels 1+4+400 = 405
    hash blocks, 1 superblock block, total 211255296 bytes; the FINAL block
    of the file contains leaf digests (tree data), never the superblock.
    """
    if not (isinstance(data_bytes, int) and not isinstance(data_bytes, bool) and data_bytes > 0 and data_bytes % VERITY_BLOCK_BYTES == 0):
        raise ImageAdmissionError("verity data size must be a positive multiple of the 4096-byte block")
    data_blocks = data_bytes // VERITY_BLOCK_BYTES
    bottom_up = []
    remaining = data_blocks
    while remaining > 1:
        remaining = (remaining + VERITY_FANOUT - 1) // VERITY_FANOUT
        bottom_up.append(remaining)
    if not bottom_up:
        bottom_up = [1]  # a single data block still has a root hash level
    # top-down order: root first, leaves last
    levels_top_down = list(reversed(bottom_up))
    superblock_offset = data_bytes
    tree_offset = superblock_offset + VERITY_BLOCK_BYTES
    level_offsets = []
    cursor = tree_offset
    for blocks in levels_top_down:
        level_offsets.append({"blocks": blocks, "offset": cursor})
        cursor += blocks * VERITY_BLOCK_BYTES
    hash_blocks = sum(levels_top_down)
    return {
        "block_bytes": VERITY_BLOCK_BYTES,
        "data_bytes": data_bytes,
        "data_blocks": data_blocks,
        "hash_blocks": hash_blocks,
        "hash_offset_bytes": data_bytes,
        "salt_hex": VERITY_SALT_HEX,
        "region_order": list(VERITY_REGION_ORDER),
        "superblock_offset": superblock_offset,
        "superblock_bytes": VERITY_BLOCK_BYTES,
        "tree_offset": tree_offset,
        "tree_levels": level_offsets,  # top-down: [{"blocks": n, "offset": o}, ...]
        "leaf_level_offset": level_offsets[-1]["offset"],
        "total_bytes": data_bytes + (hash_blocks + 1) * VERITY_BLOCK_BYTES,
    }


def validate_verity_image_size(image_size, data_bytes):
    """The combined verity-image size must equal data + tree + superblock."""
    layout = verity_layout(data_bytes)
    if image_size != layout["total_bytes"]:
        raise ImageAdmissionError(
            "verity rootfs image size %d does not equal the derived verity layout total %d "
            "(data %d + %d hash blocks + superblock)" % (image_size, layout["total_bytes"], layout["data_bytes"], layout["hash_blocks"])
        )
    return layout


def recompute_verity_root(image_bytes, data_bytes):
    """DATA-ROOT recomputation over the verity image's data region (R01).

    This is EXPLICITLY SEPARATE from stored-image verification: it derives
    the root hash over the DATA region only (sha256, salt 32 zero bytes,
    fanout 128, each tree node sha256(salt || zero-padded block)) and does
    NOT inspect the stored superblock or the stored tree bytes. Use
    ``verify_stored_verity_image`` for the stored-superblock/tree/padding
    inspection; admission without image bytes binds the root through the
    authenticated metadata cmdline instead. A data-root match alone never
    asserts anything about the stored superblock or tree layout.
    """
    layout = verity_layout(data_bytes)
    if not isinstance(image_bytes, (bytes, bytearray)) or len(image_bytes) < layout["total_bytes"]:
        raise ImageAdmissionError("verity image bytes are shorter than the derived layout")
    digests = [
        hashlib.sha256(VERITY_SALT_BYTES + bytes(image_bytes[i * VERITY_BLOCK_BYTES:(i + 1) * VERITY_BLOCK_BYTES])).digest()
        for i in range(layout["data_blocks"])
    ]
    # Each hash BLOCK holds up to fanout digests zero-padded to the full
    # block size; every node digest (including the root) is
    # sha256(salt || full padded block).
    while len(digests) > 1:
        blocks = []
        for i in range(0, len(digests), VERITY_FANOUT):
            chunk = b"".join(digests[i:i + VERITY_FANOUT]).ljust(VERITY_BLOCK_BYTES, b"\x00")
            blocks.append(hashlib.sha256(VERITY_SALT_BYTES + chunk).digest())
        if len(blocks) == 1:
            return blocks[0].hex()
        digests = blocks
    return digests[0].hex()


#: Stored dm-verity superblock field offsets AND WIDTHS (R01, S04), byte-verified
#: against veritysetup 2.4.3 (lib/verity/verity.h device_superblock) and against
#: both delivered bundles: signature[8]@0, u32 version@8, u32 hash_type@12,
#: uuid[16]@16, algorithm[32]@32, u32 data_block_size@64, u32 hash_block_size@68,
#: u64 data_blocks@72, u16 salt_size@80, pad2[6]@82, salt[256]@88. The field
#: widths are exactly the reference struct's -- data_blocks is 64-bit, salt_size
#: is 16-bit -- and the uuid + pad2 regions are part of the frozen layout.
VERITY_SB_MAGIC = b"verity\x00\x00"
VERITY_SB_ALGORITHM = b"sha256"


def verify_stored_verity_image(image_bytes, data_bytes, expected_root=None):
    """Inspect the STORED superblock, tree layout and padding (R01).

    Unlike ``recompute_verity_root`` (data-region digest derivation only),
    this function verifies the image AS STORED against the frozen layout:

      1. total size == data + superblock + tree (whole 4096-byte blocks);
      2. superblock at offset == data_bytes: magic ``verity\\0\\0``, version 1,
         hash type 1, zero UUID (all 16 bytes, the frozen dstack zero-UUID
         policy), algorithm sha256, 4096/4096 blocks, the FULL 64-bit
         data-block count == data_bytes/4096 (S04: the upper count bytes are
         part of the field, so changing them alone is detected), 16-bit salt
         size 32, the reserved padding after the salt-size field zero, salt
         32 zero bytes;
      3. the tree is byte-located TOP-DOWN after the superblock and EVERY
         stored node (including zero padding at every level, which must
         stay zero) equals the recomputed content;
      4. the recomputed root over the data region equals ``expected_root``
         when one is supplied.

    value-free diagnostics; raises ImageAdmissionError on any violation.
    Returns the verified layout dict.
    """
    if not isinstance(image_bytes, (bytes, bytearray)):
        raise ImageAdmissionError("verity image bytes are required for stored-layout verification")
    image = bytes(image_bytes)
    layout = verity_layout(data_bytes)
    if len(image) != layout["total_bytes"]:
        raise ImageAdmissionError(
            "stored verity image size %d does not equal the frozen layout total %d "
            "(data %d + superblock %d + %d tree blocks, superblock FIRST in the hash region, "
            "leaves last)" % (len(image), layout["total_bytes"], layout["data_bytes"], 1, layout["hash_blocks"])
        )
    sb_off = layout["superblock_offset"]
    sb = image[sb_off:sb_off + VERITY_BLOCK_BYTES]
    if sb[0:8] != VERITY_SB_MAGIC:
        raise ImageAdmissionError("stored verity superblock magic mismatch (superblock must be the FIRST hash-region block)")
    import struct

    version, hash_type = struct.unpack_from("<II", sb, 8)
    if version != 1 or hash_type != 1:
        raise ImageAdmissionError("stored verity superblock version/hash type mismatch")
    # S04: the 16-byte UUID region is part of the frozen layout. Every
    # delivered dstack bundle (both build legs and both promoted images)
    # carries the veritysetup-format default zero UUID; a nonzero UUID is a
    # frozen-layout violation, checked INDEPENDENTLY of any whole-file digest.
    if sb[16:32] != bytes(16):
        raise ImageAdmissionError(
            "stored verity superblock UUID must be 16 zero bytes (the frozen dstack zero-UUID policy)"
        )
    if sb[32:38] != VERITY_SB_ALGORITHM or sb[38:64] != bytes(26):
        raise ImageAdmissionError("stored verity superblock algorithm must be exactly 'sha256' NUL-padded")
    data_bs, hash_bs = struct.unpack_from("<II", sb, 64)
    if data_bs != VERITY_BLOCK_BYTES or hash_bs != VERITY_BLOCK_BYTES:
        raise ImageAdmissionError("stored verity superblock block sizes must be 4096/4096")
    # S04: data_blocks is a 64-bit little-endian field at offset 72 (veritysetup
    # 2.4.3 device_superblock). Parsing it as 32 bits left the upper half
    # unchecked -- changing only superblock byte 76 changed the on-disk count
    # without changing this checker's count. The FULL count is validated
    # against the cmdline-derived geometry.
    stored_blocks = struct.unpack_from("<Q", sb, 72)[0]
    if stored_blocks != layout["data_blocks"]:
        raise ImageAdmissionError(
            "stored verity superblock data-block count %d does not equal the cmdline-derived %d"
            % (stored_blocks, layout["data_blocks"])
        )
    # S04: salt_size is a 16-bit field at offset 80, followed by 6 reserved
    # pad2 bytes (82..88) that must stay zero.
    salt_size = struct.unpack_from("<H", sb, 80)[0]
    if sb[82:88] != bytes(6):
        raise ImageAdmissionError(
            "stored verity superblock reserved padding after the salt-size field must be zero"
        )
    salt = sb[88:88 + salt_size] if salt_size <= 256 else None
    if salt_size != 32 or salt != VERITY_SALT_BYTES:
        raise ImageAdmissionError("stored verity superblock salt must be 32 zero bytes (16-bit salt_size field 32)")
    if sb[88 + 32:] != bytes(VERITY_BLOCK_BYTES - 88 - 32):
        raise ImageAdmissionError("stored verity superblock tail padding must be zero")

    # Tree byte-location + full content verification, bottom-up recomputed
    # and compared TOP-DOWN against the stored offsets. A node block holds
    # up to fanout digests OF THE CHILD LEVEL'S FULL PADDED 4096-BYTE BLOCKS,
    # zero-padded to the block size; padding must stay zero.
    def node_digest(chunk):
        return hashlib.sha256(VERITY_SALT_BYTES + chunk).digest()

    def pack_level(child_blocks):
        """Pack child-level 4096-byte blocks' digests into parent blocks."""
        digests = [node_digest(block) for block in child_blocks]
        return [
            b"".join(digests[k * VERITY_FANOUT:(k + 1) * VERITY_FANOUT]).ljust(VERITY_BLOCK_BYTES, b"\x00")
            for k in range((len(digests) + VERITY_FANOUT - 1) // VERITY_FANOUT)
        ]

    child_blocks = [image[i * VERITY_BLOCK_BYTES:(i + 1) * VERITY_BLOCK_BYTES] for i in range(layout["data_blocks"])]
    # recompute bottom-up (leaf level first), then compare against the
    # TOP-DOWN stored offsets (root block first, leaves last)
    recomputed = []
    while len(child_blocks) > 1:
        child_blocks = pack_level(child_blocks)
        recomputed.append(child_blocks)
    for level, parent_blocks in zip(layout["tree_levels"], reversed(recomputed)):
        if len(parent_blocks) != level["blocks"]:
            raise ImageAdmissionError("stored verity tree level block count does not equal the frozen fanout derivation")
        stored = image[level["offset"]:level["offset"] + level["blocks"] * VERITY_BLOCK_BYTES]
        if stored != b"".join(parent_blocks):
            raise ImageAdmissionError(
                "stored verity tree level at offset %d does not equal the recomputed level "
                "(wrong layout, tampered node, or nonzero padding)" % level["offset"]
            )
    # the single remaining block is the root block; root = H(salt||root block)
    root_digest = node_digest(child_blocks[0])
    if expected_root is not None and root_digest.hex() != expected_root:
        raise ImageAdmissionError("the stored verity tree root does not equal the expected root hash")
    return layout


def sniff_kernel_arch(kernel_bytes):
    """Architecture sniffed from boot image headers, or None.

    arm64 Image: magic b'ARM\\x64' at offset 0x38. x86_64 bzImage: b'HdrS'
    at offset 0x202. Unrecognized headers return None (the caller decides).
    """
    if not isinstance(kernel_bytes, (bytes, bytearray)) or len(kernel_bytes) < 0x206:
        return None
    if bytes(kernel_bytes[0x38:0x3C]) == b"ARM\x64":
        return "aarch64"
    if bytes(kernel_bytes[0x202:0x206]) == b"HdrS":
        return "x86_64"
    return None


# ------------------------------------------------------------------ identity + admission


def verify_base_vm_identity(base_vm, manifest_bytes, metadata_bytes):
    """Bind the COMPLETE boot tuple to the exact checksum-manifest + metadata bytes.

    Checks (E01): every base_vm component pin equals the manifest entry under
    its delivered name; the metadata bytes hash to metadata_sha256; the
    metadata cmdline equals base_vm.cmdline byte for byte; the cmdline carries
    dstack.rootfs_hash == base_vm.verity_root_hash, a block-aligned
    dstack.rootfs_size and dstack.rootfs_device == /dev/vda; the metadata
    component names match the delivered layout; the metadata platform agrees
    with base_vm.architecture; os_image_hash equals sha256(exact manifest
    bytes). Raises ImageAdmissionError on any violation.
    """
    from .manifest import CMDLINE_RE, HEX64_RE

    if not isinstance(base_vm, dict):
        raise ImageAdmissionError("base_vm must be an object")
    entries = parse_checksum_manifest(manifest_bytes)
    for field, path in sorted(COMPONENT_PATHS.items()):
        pin = base_vm.get(field)
        if not (isinstance(pin, str) and HEX64_RE.match(pin)):
            raise ImageAdmissionError("base_vm.%s must be a 64-hex pin" % field)
        if entries[path] != pin:
            raise ImageAdmissionError(
                "base_vm.%s does not match the checksum manifest entry for %s (image identity is the "
                "serialized manifest, and its component entries must equal the pins)" % (field, path)
            )
    identity = os_image_hash(manifest_bytes)
    declared = base_vm.get("os_image_hash")
    if not (isinstance(declared, str) and HEX64_RE.match(declared)):
        raise ImageAdmissionError("base_vm.os_image_hash must be a 64-hex pin")
    if declared != identity:
        raise ImageAdmissionError(
            "base_vm.os_image_hash does not equal the SHA256 of the exact checksum-manifest bytes"
        )
    # AUTHENTICATED METADATA (E01): the pinned metadata bytes are consumed.
    if base_vm.get("metadata_sha256") != sha256_hex(metadata_bytes):
        raise ImageAdmissionError("base_vm.metadata_sha256 does not equal the SHA256 of the metadata bytes")
    metadata = parse_metadata(metadata_bytes)
    if metadata["kernel"] != COMPONENT_PATHS["kernel_sha256"]:
        raise ImageAdmissionError("image metadata.kernel does not name the delivered kernel entry")
    if metadata["initrd"] != COMPONENT_PATHS["initrd_sha256"]:
        raise ImageAdmissionError("image metadata.initrd does not name the delivered initrd entry")
    if metadata["rootfs"] != COMPONENT_PATHS["rootfs_sha256"]:
        raise ImageAdmissionError("image metadata.rootfs does not name the delivered verity rootfs entry")
    cmdline = base_vm.get("cmdline")
    if not (isinstance(cmdline, str) and CMDLINE_RE.match(cmdline)):
        raise ImageAdmissionError("base_vm.cmdline must be bounded printable ASCII")
    if metadata["cmdline"] != cmdline:
        raise ImageAdmissionError("base_vm.cmdline does not equal the authenticated metadata cmdline (byte-exact)")
    root_hash = _cmdline_field(cmdline, "dstack.rootfs_hash")
    if root_hash is None or not HEX64_RE.match(root_hash):
        raise ImageAdmissionError("the metadata cmdline does not carry a 64-hex dstack.rootfs_hash")
    if root_hash != base_vm.get("verity_root_hash"):
        raise ImageAdmissionError("base_vm.verity_root_hash does not equal the cmdline dstack.rootfs_hash")
    rootfs_size = _cmdline_rootfs_size(cmdline)
    if rootfs_size is None or rootfs_size % VERITY_BLOCK_BYTES != 0:
        raise ImageAdmissionError("the metadata cmdline does not carry a block-aligned dstack.rootfs_size")
    if _cmdline_field(cmdline, "dstack.rootfs_device") != VERITY_ROOTFS_DEVICE:
        raise ImageAdmissionError("the metadata cmdline dstack.rootfs_device must be %s" % VERITY_ROOTFS_DEVICE)
    if METADATA_ARCH.get(metadata["platform"]) != base_vm.get("architecture"):
        raise ImageAdmissionError(
            "base_vm.architecture does not agree with the authenticated metadata platform"
        )
    verity = verity_layout(rootfs_size)
    verity["root_hash"] = root_hash
    return {
        "os_image_hash": identity,
        "components": dict(entries),
        # R02: the byte-exact authenticated command line is part of the
        # validated admission tuple (equality with base_vm.cmdline and the
        # metadata cmdline was verified above).
        "cmdline": cmdline,
        "metadata": {
            "version": metadata["version"],
            "git_revision": metadata["git_revision"],
            "builder": metadata["builder"],
            "shared_ro": metadata["shared_ro"],
            "platform": metadata["platform"],
        },
        "verity": verity,
    }


def parse_admission(admission_bytes):
    """Parse an external admission document (outside the signed app).

    Shape: {"admission_version": 1, "allowed_os_image_hashes": [<64hex>...]}
    Bounded, duplicates rejected, strictly typed (D01: the external
    admission-policy interface).
    """
    try:
        doc = load_json_bytes(admission_bytes, "image admission", max_bytes=MAX_ADMISSION_BYTES)
    except ContractError as exc:
        raise ImageAdmissionError("image admission document is invalid: %s" % exc) from None
    if not isinstance(doc, dict) or set(doc) != {"admission_version", "allowed_os_image_hashes"}:
        raise ImageAdmissionError("image admission must have exactly {admission_version, allowed_os_image_hashes}")
    if doc["admission_version"] != ADMISSION_VERSION:
        raise ImageAdmissionError("image admission_version must be %d" % ADMISSION_VERSION)
    allowed = doc["allowed_os_image_hashes"]
    if not isinstance(allowed, list) or not allowed or not all(isinstance(h, str) for h in allowed):
        raise ImageAdmissionError("image admission allowed_os_image_hashes must be a non-empty list of strings")
    from .manifest import HEX64_RE

    if any(not HEX64_RE.match(h) for h in allowed) or len(allowed) != len(set(allowed)):
        raise ImageAdmissionError("image admission hashes must be unique 64-hex digests")
    return {"admission_version": ADMISSION_VERSION, "allowed_os_image_hashes": list(allowed)}


def admit_image(base_vm, checksum_manifest_bytes, metadata_bytes, admission_bytes):
    """Fail-closed external admission of a base image by checksum identity.

    The admission document is EXTERNAL configuration (ledger 6.4: policy
    lives outside the signed app; updating the admitted image set never
    rebuilds or re-signs the app). The COMPLETE boot tuple is authenticated
    first (verify_base_vm_identity: pins + metadata + cmdline + verity root
    + architecture); the admission set is consulted only afterwards. Returns
    a decision record bound to the admission bytes; raises ImageAdmissionError
    when the identity is not admitted. The decision record goes into the
    receipt's base_vm_launch.admission (E02).
    """
    identity = verify_base_vm_identity(base_vm, checksum_manifest_bytes, metadata_bytes)
    policy = parse_admission(admission_bytes)
    if identity["os_image_hash"] not in policy["allowed_os_image_hashes"]:
        raise ImageAdmissionError(
            "image os_image_hash is not in the external admission set; execution fails closed (no "
            "silent substitution, no permissive default)"
        )
    # R02: the decision record carries the IMMUTABLE VALIDATED ADMISSION
    # TUPLE -- the admission identity, the exact authenticated cmdline
    # digest, the metadata digest and the derived verity geometry -- so a
    # boot observation can be constructed ONLY against this tuple and any
    # post-admission mutation of the boot inputs is detectable. The wire
    # receipt admission object remains the documented four-key shape; the
    # tuple fields are the admission-time validated values.
    return {
        "decision": "admitted",
        "os_image_hash": identity["os_image_hash"],
        "admission_sha256": sha256_hex(admission_bytes),
        "admission_version": ADMISSION_VERSION,
        # ---- validated tuple (R02) ----
        "components": identity["components"],
        "metadata_sha256": base_vm["metadata_sha256"],
        "cmdline": identity["cmdline"],
        "cmdline_sha256": sha256_hex(identity["cmdline"]),
        "architecture": base_vm["architecture"],
        "verity": identity["verity"],
    }


# ------------------------------------------------------------------ owned-copy route (authoritative)


def own_component(source_bytes, expected_sha256, what):
    """OWNED-COPY ROUTE, R1 (spike DESIGN): copy once, hash the OWNED COPY.

    source_bytes are the caller-supplied component bytes; they are copied
    into a new immutable bytes object and the hash is taken over THE COPY.
    The caller's buffer is read exactly once, here. Refusal happens before
    anything is returned; there is no partially-verified state.
    """
    from .manifest import HEX64_RE

    if not (isinstance(expected_sha256, str) and HEX64_RE.match(expected_sha256)):
        raise ImageAdmissionError("expected component digest must be 64-hex")
    if not isinstance(source_bytes, (bytes, bytearray)) or not source_bytes:
        raise ImageAdmissionError("%s bytes for the owned copy are missing or empty" % what)
    owned = bytes(source_bytes)
    digest = hashlib.sha256(owned).hexdigest()
    if digest != expected_sha256:
        raise ImageAdmissionError(
            "%s owned-copy bytes do not match the pinned digest; refusing to boot (fail closed)" % what
        )
    return {"bytes": owned, "sha256": digest, "size": len(owned)}


def own_component_from_file(staged_path, expected_sha256, what):
    """Own-copy acquisition from a staged path: read ONCE, hash the copy.

    The path is read exactly once into the owned copy; the hash is over the
    owned bytes, and consumption later uses the owned bytes -- the staged
    path is never re-read, so any post-copy mutation of it is irrelevant
    (this is the property the held-FD route lacks).
    """
    from .manifest import HEX64_RE

    if not (isinstance(expected_sha256, str) and HEX64_RE.match(expected_sha256)):
        raise ImageAdmissionError("expected component digest must be 64-hex")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(staged_path, flags)
    except OSError:
        raise ImageAdmissionError("%s staged source could not be opened safely" % what) from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ImageAdmissionError("%s staged source is not a regular file" % what)
        chunks = []
        while True:
            try:
                chunk = os.read(fd, READ_CHUNK)
            except OSError:
                raise ImageAdmissionError("%s staged source could not be read" % what) from None
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(fd)
    return own_component(b"".join(chunks), expected_sha256, what)


def consume(owned):
    """OWNED-COPY ROUTE, R2: the ONLY consumption route for verified bytes.

    Returns the owned bytes for the one consumer that populates guest RAM /
    attaches the VM disk. There is no host-path re-read anywhere on this
    route; a caller holding this return value holds exactly the verified
    bytes, immutable.
    """
    if not isinstance(owned, dict) or "bytes" not in owned or "sha256" not in owned:
        raise ImageAdmissionError("consume requires an owned copy from own_component")
    return owned["bytes"]


def build_boot_observation(admission_decision, kernel, initrd, rootfs, metadata, base_vm):
    """R3-R5 + R02: bind the owned copies to the VALIDATED ADMISSION TUPLE.

    kernel/initrd/rootfs/metadata are OWNED COPIES (own_component). The
    observation can only be constructed against the immutable tuple that
    ``admit_image`` returned: every check is made against THAT record, so a
    post-admission change of any boot input is rejected even when the root
    fields would still parse:

      - the decision record is the admitted one AND carries the tuple
        (os_image_hash, metadata_sha256, cmdline_sha256, verity);
      - admission identity == base_vm.os_image_hash (the executed image is
        the admitted one);
      - base_vm.cmdline hashes to the ADMISSION-TIME cmdline_sha256 (a
        post-admission cmdline edit fails here even if root fields match);
      - the OWNED METADATA COPY's declared cmdline equals base_vm.cmdline
        byte for byte, its component names equal the delivered layout, and
        its digest equals both the base_vm pin and the admission-time pin;
      - every owned copy digest equals the base_vm pin AND the admission
        tuple's component entry;
      - kernel header architecture agrees with the tuple architecture;
      - verity: the stored superblock/tree/padding are verified at the
        frozen offsets AND the recomputed data root equals the tuple's
        authenticated dstack.rootfs_hash; the recorded geometry
        (data_bytes, hash_offset, total) comes from the verified layout.

    Returns the exact receipt ``base_vm_launch.boot`` object (loader_mode
    owned-copy) with the observed digests, the exact cmdline and its
    digest, and the verified verity layout.
    """
    if not isinstance(admission_decision, dict) or admission_decision.get("decision") != "admitted":
        raise ImageAdmissionError("boot observation requires an admitted decision record")
    tuple_fields = {"components", "metadata_sha256", "cmdline_sha256", "verity", "os_image_hash"}
    if tuple_fields - set(admission_decision):
        raise ImageAdmissionError(
            "boot observation requires the immutable validated admission tuple from admit_image "
            "(decision record is missing tuple fields); a bare admitted flag is not bindable"
        )
    cmdline = base_vm["cmdline"]
    if sha256_hex(cmdline) != admission_decision["cmdline_sha256"]:
        raise ImageAdmissionError(
            "base_vm.cmdline changed after admission (does not hash to the admission-time cmdline "
            "digest); the boot tuple is immutable after admission"
        )
    if admission_decision["cmdline"] != cmdline:
        raise ImageAdmissionError("the admission tuple cmdline does not equal the boot cmdline byte for byte")
    if base_vm.get("os_image_hash") != admission_decision["os_image_hash"]:
        raise ImageAdmissionError(
            "base_vm.os_image_hash does not equal the admission decision's identity (the executed "
            "image must be the admitted one)"
        )
    if base_vm.get("architecture") != admission_decision["architecture"]:
        raise ImageAdmissionError(
            "base_vm.architecture does not equal the admitted architecture (the boot tuple is "
            "immutable after admission)"
        )
    # OWNED METADATA (R02): the metadata copy itself re-checks the tuple --
    # its declared cmdline must equal the boot cmdline byte for byte and its
    # component names the delivered layout, so only the pinned metadata
    # bytes can produce an observation.
    metadata_doc = parse_metadata(metadata["bytes"])
    if metadata_doc["cmdline"] != cmdline:
        raise ImageAdmissionError(
            "the owned metadata copy's declared cmdline does not equal the boot cmdline byte for "
            "byte (post-admission metadata substitution is refused)"
        )
    for key in ("kernel", "initrd", "rootfs"):
        if metadata_doc[key] != COMPONENT_PATHS[{"kernel": "kernel_sha256", "initrd": "initrd_sha256", "rootfs": "rootfs_sha256"}[key]]:
            raise ImageAdmissionError("the owned metadata copy does not name the delivered %s entry" % key)
    if metadata["sha256"] != base_vm["metadata_sha256"] or metadata["sha256"] != admission_decision["metadata_sha256"]:
        raise ImageAdmissionError("owned metadata copy does not match the pinned metadata digest")
    architecture = admission_decision["architecture"]
    sniffed = sniff_kernel_arch(kernel["bytes"])
    if sniffed is not None and sniffed != architecture:
        raise ImageAdmissionError(
            "kernel header architecture does not agree with the admitted architecture; refusing to boot"
        )
    rootfs_size = _cmdline_rootfs_size(cmdline)
    if rootfs_size is None:
        raise ImageAdmissionError("boot observation requires the cmdline dstack.rootfs_size")
    # R01: stored superblock/tree/padding inspection AND data-root
    # recomputation, both over the owned copy.
    layout = verify_stored_verity_image(rootfs["bytes"], rootfs_size, expected_root=None)
    if rootfs["size"] != layout["total_bytes"]:
        raise ImageAdmissionError("owned rootfs size does not equal the verified stored layout total")
    root = recompute_verity_root(rootfs["bytes"], rootfs_size)
    verity_root = _cmdline_field(cmdline, "dstack.rootfs_hash")
    if root != verity_root or verity_root != admission_decision["verity"]["root_hash"]:
        raise ImageAdmissionError(
            "the recomputed verity root over the owned rootfs data region does not equal the "
            "authenticated dstack.rootfs_hash; refusing to boot"
        )
    for owned, field, path in (
        (kernel, "kernel_sha256", "Image"),
        (initrd, "initrd_sha256", "initramfs.cpio.gz"),
        (rootfs, "rootfs_sha256", "rootfs.squashfs.verity"),
    ):
        if owned["sha256"] != base_vm.get(field) or owned["sha256"] != admission_decision["components"].get(path):
            raise ImageAdmissionError(
                "an owned component copy does not match the admitted pin for %s (post-admission "
                "substitution is refused)" % path
            )
    return {
        "loader_mode": LOADER_OWNED_COPY,
        "kernel_sha256": kernel["sha256"],
        "initrd_sha256": initrd["sha256"],
        "rootfs_sha256": rootfs["sha256"],
        "metadata_sha256": metadata["sha256"],
        "cmdline": cmdline,
        "cmdline_sha256": sha256_hex(cmdline),
        "verity": {
            "block_bytes": layout["block_bytes"],
            "data_bytes": layout["data_bytes"],
            "hash_offset_bytes": layout["hash_offset_bytes"],
            "root_hash": verity_root,
            "salt_hex": layout["salt_hex"],
            "total_bytes": layout["total_bytes"],
        },
    }


# ------------------------------------------------------------------ held-fd route (engineering transport)


def _fd_digest(fd):
    """Full read + SHA256 through an existing descriptor (no path use)."""
    os.lseek(fd, 0, os.SEEK_SET)
    h = hashlib.sha256()
    while True:
        chunk = os.read(fd, READ_CHUNK)
        if not chunk:
            break
        h.update(chunk)
    digest = h.hexdigest()
    os.lseek(fd, 0, os.SEEK_SET)
    return digest


def verify_and_hold(staged_path, expected_sha256):
    """HELD-FD ROUTE (ENGINEERING TRANSPORT): open once, hash, hold the FD.

    The descriptor is the only thing returned to the boot path. This closes
    the LOADER's path-swap TOCTOU, but a held ordinary-file descriptor does
    not prevent same-inode modification after the final hash (a writer with
    the file open can overwrite the contents in place), and a QEMU-style
    consumer re-reads through a path. Receipts from this route record
    ``loader_mode: "held-fd"`` -- engineering transport, never the
    verified-byte boot-binding claim (E02).
    """
    from .manifest import HEX64_RE

    if not (isinstance(expected_sha256, str) and HEX64_RE.match(expected_sha256)):
        raise ImageAdmissionError("expected component digest must be 64-hex")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(staged_path, flags)
    except OSError:
        raise ImageAdmissionError("staged component could not be opened safely (refusing to boot)") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ImageAdmissionError("staged component is not a regular file")
        if st.st_size <= 0:
            raise ImageAdmissionError("staged component is empty")
        digest = _fd_digest(fd)
        if digest != expected_sha256:
            raise ImageAdmissionError(
                "staged component bytes do not match the pinned digest; refusing to boot (fail closed)"
            )
    except Exception:
        os.close(fd)
        raise
    return {"fd": fd, "sha256": digest, "size": st.st_size, "inode": st.st_ino}


def reverify_fd(held):
    """Re-verify THROUGH THE HELD DESCRIPTOR immediately before boot."""
    fd = held["fd"]
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_size != held["size"] or st.st_ino != held["inode"]:
        raise ImageAdmissionError("held component descriptor changed identity since verification; refusing to boot")
    digest = _fd_digest(fd)
    if digest != held["sha256"]:
        raise ImageAdmissionError("held component bytes changed after verification; refusing to boot")
    return digest


def close_held(held):
    try:
        os.close(held["fd"])
    except OSError:
        pass


__all__ = [
    "ADMISSION_VERSION",
    "COMPONENT_PATHS",
    "CHECKSUM_MANIFEST_PATHS",
    "LOADER_HELD_FD",
    "LOADER_MODES",
    "LOADER_OWNED_COPY",
    "METADATA_KEYS",
    "VERITY_BLOCK_BYTES",
    "VERITY_REGION_ORDER",
    "VERITY_SALT_HEX",
    "admit_image",
    "build_boot_observation",
    "close_held",
    "consume",
    "os_image_hash",
    "own_component",
    "own_component_from_file",
    "parse_admission",
    "parse_checksum_manifest",
    "parse_metadata",
    "recompute_verity_root",
    "reverify_fd",
    "sniff_kernel_arch",
    "validate_verity_image_size",
    "verity_layout",
    "verify_and_hold",
    "verify_base_vm_identity",
    "verify_stored_verity_image",
]
