"""Normative bounds for the private-input transport (vde payload).

SINGLE source of truth for the guest reader.  These values MIRROR the
io-contract-reference normative module
(``io-contract-reference/candidate/runresult_ref/protocol.py``) for the
``dsmack.private-input-transport/1`` contract; the host builder
(``make_private_input.py``) and the host-unit tests assert byte-equality so a
drift between the measured reader and the reference protocol fails closed
rather than silently diverging.

No value here depends on, or reveals, any private input.
"""

# Contract identity (shared with io-contract-reference).
PRIVATE_TRANSPORT_CONTRACT = "dsmack.private-input-transport/1"

# Entry-type allowlist: regular file ('0' / NUL) and directory ('5') ONLY.
PT_ALLOWED_TYPEFLAGS = (b"0", b"\x00", b"5")

# Grammar + depth.
PT_SEGMENT_RE = r"^[A-Za-z0-9._-]{1,128}$"   # plus explicit '.'/'..'/'' refusal
PT_DEPTH_MAX = 4
PT_NAME_MAX = 256

# Counts and byte caps (checked BEFORE any byte is written).
PT_ENTRY_COUNT_MAX = 64
PT_FILE_BYTES_MAX = 16777216        # 16 MiB per regular file
PT_TOTAL_BYTES_MAX = 67108864       # 64 MiB expanded total

# Image framing.
PT_IMAGE_ALIGN = 512
PT_IMAGE_BYTES_MAX = 1073741824     # 1 GiB hard cap on the transport image
PT_BLOCK = 512

# Owned-copy private modes (umask-independent via explicit chmod).
PT_FILE_MODE = 0o600
PT_DIR_MODE = 0o700

# GIO01: CANONICAL per-member transport metadata. The host packer
# (launch_vm_dstack_arm64._pt_tar_filter) normalizes every member to exactly
# these values; the measured guest parser REFUSES any member whose mode or
# mtime differs, so a noncanonical mode (e.g. 07777) or mtime (e.g. 0) can never
# be admitted. These are the single source of truth shared by packer and parser
# (the uid/gid/uname/gname/device canonical values are the fixed zeros/empties
# already enforced inline).
PT_CANONICAL_MTIME = 1784592000       # SOURCE_DATE_EPOCH used across the build
PT_CANONICAL_FILE_MODE = 0o600        # regular-file member permission bits
PT_CANONICAL_DIR_MODE = 0o700         # directory member permission bits

# Header checksum field (ustar): 8 bytes at offset 148, computed over the
# whole 512-byte header with the checksum field itself read as ASCII spaces.
PT_CHKSUM_OFF = 148
PT_CHKSUM_LEN = 8

# Finite elapsed-time deadlines (local to the measured reader; NOT part of the
# reference-mirrored value set).  Read, parse and extraction each fail closed
# when they exceed their bound rather than running unbounded.
PT_READ_SECONDS = 60
PT_EXTRACT_SECONDS = 120
