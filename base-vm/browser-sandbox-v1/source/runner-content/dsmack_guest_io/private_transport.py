"""Safe bounded private-input transport parser (vde payload).

The UNMEASURED private-input disk (``vde``) carries a ustar stream at offset 0,
zero-padded to a 512-byte boundary.  It holds the default-uncommitted runtime
inputs (env / files / stdin / user_config envelopes) and the per-run broker
channel (config + 0600 credential) that USED to travel on the measured ``vdc``
public workload disk.  Moving them to ``vde`` keeps them OUT of every measured
image hash and admission decision.

This module is the guest reader half of the ``dsmack.private-input-transport/1``
contract.  It REPLACES both ``tar -tf`` type inspection (which cannot provide
the required metadata guarantees) and unrestricted root ``tar -x``.  It reads
raw 512-byte headers itself and enforces, BEFORE writing any byte:

  * entry types: regular file ('0'/NUL) and directory ('5') ONLY — links,
    symlinks, specials, FIFOs, GNU sparse/longname/longlink and pax ('x'/'g')
    metadata extensions are refusals;
  * the ustar header CHECKSUM must validate (unsigned or signed sum with the
    checksum field read as spaces); a corrupt header is refused;
  * exact per-segment name grammar (full-string match — a trailing newline or
    any out-of-class byte is refused), a depth bound, no '.'/'..'/'' segments,
    no absolute names, no duplicate names, parent-before-child ordering where
    the parent entry is itself a DIRECTORY;
  * typeflag and trailing-slash must agree: a '5' entry is a directory and
    carries a trailing slash, a '0'/NUL entry is a regular file and does not;
  * entry count, per-file byte and total expanded-byte caps;
  * size-field sanity (octal digits only, within caps; base-256 refused);
  * after the end-of-archive zero block, every remaining byte must be zero;
  * extraction into a FRESH private 0700 directory with O_EXCL 0600 files and
    0700 directories (umask-independent), COMPLETE checked writes, fsync per
    written file and a final destination-directory fsync, all under a finite
    elapsed-time deadline and full fail-closed cleanup.

No digest of any transport byte, no cache id and no content is computed or
logged here; refusal text carries entry NAMES and declared SIZES only, never
file contents.  The caller OWNS the returned tree and must delete it via
``cleanup_tree()`` on every path (the owned-copy lifecycle is exercised by the
host-unit tests, including the fail-closed, injected-I/O and cleanup cases).

Design note: the parser is byte-logic-equivalent to the io-contract-reference
normative reference (``runresult_ref/private_transport.py``).  It is
re-implemented here — rather than imported — because it must be installed as
MEASURED guest-image bytes that depend on NOTHING caller-provided and nothing
from the auxiliary verifier lane.
"""
from __future__ import annotations

import os
import re
import signal
import threading
import time

from . import pt_limits as L

_SEGMENT = re.compile(L.PT_SEGMENT_RE)


class TransportRefusal(Exception):
    """A fail-closed refusal of the private transport.  The string names the
    rule and (optionally) an entry name/size — never file content."""

    def __init__(self, rule: str, detail: str = ""):
        self.rule = rule
        self.detail = detail
        super().__init__(rule if not detail else "%s %s" % (rule, detail))


def _need(ok: bool, rule: str, detail: str = "") -> None:
    if not ok:
        raise TransportRefusal(rule, detail)


class _Deadline:
    """Monotonic elapsed-time bound shared across read/parse/extract."""

    def __init__(self, seconds: float):
        self._end = time.monotonic() + float(seconds)

    def check(self, rule: str = "pt_deadline") -> None:
        _need(time.monotonic() <= self._end, rule)


class _IOAlarm:
    """Hard upper bound on BLOCKING I/O (read/write/fsync) under the deadline.

    GIO01: the cooperative ``_Deadline.check`` cannot interrupt a syscall that
    is ALREADY blocked -- a stalled device read, a stalled write to a wedged
    destination, or a stalled fsync can never reach the next check, so the
    whole extraction could block unbounded.  This arms a real-time SIGALRM for
    exactly the time remaining on the shared deadline; its handler raises a
    ``TransportRefusal``.  Per PEP 475 a syscall whose signal handler RAISES is
    NOT retried, so a blocked read/write/fsync fails closed at the deadline
    rather than blocking forever.

    SIGALRM is only deliverable on the MAIN thread of the MAIN interpreter --
    which is exactly where the measured guest reader
    (``dsmack-guest-io extract-private``) runs.  When it is unavailable (a
    non-main thread, or a platform without setitimer) the context manager
    degrades to a single cooperative ``deadline.check`` rather than failing the
    whole operation; the per-chunk checks in the loops still bound the
    non-stalled path.  The bound is therefore ENFORCED where it matters (the
    measured reader) and never silently absent (the check still fires)."""

    def __init__(self, deadline: "_Deadline | None", rule: str = "pt_io_deadline"):
        self._deadline = deadline
        self._rule = rule
        self._armed = False
        self._prev = None

    def _usable(self) -> bool:
        return (self._deadline is not None
                and hasattr(signal, "SIGALRM") and hasattr(signal, "setitimer")
                and threading.current_thread() is threading.main_thread())

    def __enter__(self):
        if not self._usable():
            if self._deadline is not None:
                self._deadline.check(self._rule)
            return self
        remaining = self._deadline._end - time.monotonic()
        if remaining <= 0:
            raise TransportRefusal(self._rule)

        def _fire(_signum, _frame):
            raise TransportRefusal(self._rule)

        self._prev = signal.signal(signal.SIGALRM, _fire)
        signal.setitimer(signal.ITIMER_REAL, remaining)
        self._armed = True
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._armed:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, self._prev)
            self._armed = False
        return False


def _canon_numeric(field: bytes) -> int:
    """Parse a ustar numeric metadata field (octal, NUL/space padded).  An
    EMPTY field is canonical zero; a non-octal field returns -1 so the caller's
    canonical-zero check fails closed."""
    text = field.split(b"\x00")[0].strip()
    if text == b"":
        return 0
    if any(not (0x30 <= c <= 0x37) for c in text):
        return -1
    try:
        return int(text, 8)
    except ValueError:
        return -1


def _segment_ok(segment: str) -> bool:
    # fullmatch (not match) so a trailing newline or any out-of-class byte is
    # refused; the '$' alone would admit a trailing '\n' (GIO01).
    return _SEGMENT.fullmatch(segment) is not None


def _parse_name(raw_name: str):
    _need(len(raw_name) <= L.PT_NAME_MAX, "pt_name_too_long")
    _need(not raw_name.startswith("/"), "pt_absolute_name", raw_name)
    is_dir = raw_name.endswith("/")
    # Strip EXACTLY ONE trailing slash for a directory entry.  rstrip('/')
    # collapsed a NONCANONICAL name such as "a//" to "a" and admitted it as
    # directory "a"; stripping a single slash leaves "a/" whose empty final
    # segment the dot/empty check below refuses (GIO01).
    name = raw_name[:-1] if is_dir else raw_name
    _need(bool(name), "pt_empty_name")
    segments = name.split("/")
    _need(len(segments) <= L.PT_DEPTH_MAX, "pt_too_deep", raw_name)
    for segment in segments:
        _need(segment not in (".", "..", ""), "pt_dot_segment", raw_name)
        _need(_segment_ok(segment), "pt_name_grammar", raw_name)
    return name, is_dir


def _octal(field: bytes, what: str) -> int:
    text = field.split(b"\x00")[0].strip()
    # A leading high bit is GNU base-256 encoding — explicitly refused (the
    # caps make it unnecessary and it is an unbounded-size vector).
    _need(text != b"" and not (field and (field[0] & 0x80)), "pt_size_encoding", what)
    _need(all(0x30 <= c <= 0x37 or c == 0x20 for c in text), "pt_size_digits", what)
    try:
        return int(text, 8)
    except ValueError:
        raise TransportRefusal("pt_size_parse", what) from None


def _verify_checksum(header: bytes, name: str) -> None:
    """Validate the ustar header checksum (bytes 148..156).  The stored octal
    value must equal the sum of all 512 header bytes with the checksum field
    read as ASCII spaces — computed both unsigned and signed (historical
    writers differ); a mismatch refuses the header."""
    off, length = L.PT_CHKSUM_OFF, L.PT_CHKSUM_LEN
    stored = _octal(header[off:off + length], "chksum:" + name)
    probe = bytearray(header)
    for i in range(off, off + length):
        probe[i] = 0x20
    unsigned = sum(probe)
    signed = sum(c if c < 128 else c - 256 for c in probe)
    _need(stored == unsigned or stored == signed, "pt_bad_checksum", name)


def parse_entries(blob: bytes, deadline: "_Deadline | None" = None):
    """Validate the WHOLE transport and return [(name, is_dir, offset, size)].

    Nothing is written; this is the complete admission decision.  A single
    refusal rejects the entire image (no partial acceptance)."""
    _need(isinstance(blob, (bytes, bytearray)), "pt_not_bytes")
    blob = bytes(blob)
    _need(0 < len(blob) <= L.PT_IMAGE_BYTES_MAX, "pt_image_bytes")
    _need(len(blob) % L.PT_IMAGE_ALIGN == 0, "pt_image_align")
    entries, seen, seen_dirs, total, pos = [], set(), set(), 0, 0
    while True:
        if deadline is not None:
            deadline.check("pt_parse_deadline")
        _need(pos + L.PT_BLOCK <= len(blob), "pt_truncated_header")
        header = blob[pos:pos + L.PT_BLOCK]
        if header == b"\x00" * L.PT_BLOCK:
            # End-of-archive marker: every remaining byte must be zero padding;
            # nonzero trailing data (a smuggled second stream) is refused.
            _need(not any(blob[pos:]), "pt_trailing_data")
            break
        _need(len(entries) < L.PT_ENTRY_COUNT_MAX, "pt_entry_count")
        magic = header[257:263]
        _need(magic in (b"ustar\x00", b"ustar "), "pt_not_ustar")
        # Reject unsupported ustar header metadata explicitly (GIO01): an
        # independent probe admitted a header carrying version "99".  POSIX
        # ustar ("ustar\0") carries version "00"; GNU ("ustar ") carries
        # " \0".  Any other version field (e.g. "99") is a refusal.
        version = header[263:265]
        if magic == b"ustar\x00":
            _need(version == b"00", "pt_ustar_version", repr(version))
        else:
            _need(version in (b" \x00", b"00"), "pt_ustar_version", repr(version))
        typeflag = header[156:157]
        _need(typeflag in L.PT_ALLOWED_TYPEFLAGS, "pt_entry_type", repr(typeflag))
        prefix = header[345:500].split(b"\x00")[0].decode("ascii", "replace")
        raw = header[0:100].split(b"\x00")[0].decode("ascii", "replace")
        raw_name = (prefix + "/" + raw) if prefix else raw
        name, trailing_slash = _parse_name(raw_name)
        _verify_checksum(header, name)
        # typeflag and trailing-slash MUST agree: '5' is a directory with a
        # trailing slash; '0'/NUL is a regular file without one.  This refuses
        # both a regular entry carrying a directory suffix and a '5' lacking
        # the slash (GIO01).
        is_dir = typeflag == b"5"
        _need(trailing_slash == is_dir, "pt_dir_flag_mismatch", raw_name)
        # GIO01: CANONICAL archive metadata admission.  The host packer
        # (launch_vm_dstack_arm64._pt_tar_filter) normalizes every member to
        # uid/gid 0, EMPTY uname/gname, zero device fields and -- for the only
        # two admitted types, regular file and directory -- an EMPTY linkname.
        # A transport whose metadata is NOT canonical is refused BEFORE any
        # byte is written: an independent probe accepted a regular-file entry
        # carrying a nonempty linkname (bytes 157..257); a nonzero owner or a
        # populated uname/gname/device field is likewise a non-canonical, and
        # therefore refused, transport.  Links are already refused by type, so
        # the only legitimate linkname here is the empty one.
        _need(header[157:257].rstrip(b"\x00") == b"", "pt_linkname_present", name)
        # GIO01: the packer normalizes the MODE (0600 files / 0700 dirs) and the
        # MTIME (fixed SOURCE_DATE_EPOCH) too.  An independent probe admitted a
        # member carrying mode 07777 and a member carrying mtime 0 because the
        # parser checked uid/gid/uname/gname/device but NOT mode or mtime.  A
        # member whose permission bits or mtime are not the canonical packer
        # values is a non-canonical transport and is refused BEFORE any byte is
        # written.  _canon_numeric returns -1 for a non-octal field so a
        # malformed numeric fails closed here too.
        canon_mode = L.PT_CANONICAL_DIR_MODE if is_dir else L.PT_CANONICAL_FILE_MODE
        _need(_canon_numeric(header[100:108]) == canon_mode, "pt_noncanonical_mode", name)
        _need(_canon_numeric(header[136:148]) == L.PT_CANONICAL_MTIME, "pt_noncanonical_mtime", name)
        _need(_canon_numeric(header[108:116]) == 0, "pt_noncanonical_uid", name)
        _need(_canon_numeric(header[116:124]) == 0, "pt_noncanonical_gid", name)
        _need(header[265:297].rstrip(b"\x00") == b"", "pt_noncanonical_uname", name)
        _need(header[297:329].rstrip(b"\x00") == b"", "pt_noncanonical_gname", name)
        _need(_canon_numeric(header[329:337]) == 0, "pt_noncanonical_devmajor", name)
        _need(_canon_numeric(header[337:345]) == 0, "pt_noncanonical_devminor", name)
        _need(name not in seen, "pt_duplicate_entry", name)
        size = _octal(header[124:136], "size:" + name)
        if is_dir:
            _need(size == 0, "pt_dir_with_size", name)
        else:
            _need(size <= L.PT_FILE_BYTES_MAX, "pt_file_too_large", name)
            total += size
            _need(total <= L.PT_TOTAL_BYTES_MAX, "pt_total_bytes")
        # Regular ustar headers cannot describe holes; a sparse 'S' entry was
        # already refused, so declared size == stored size.
        data_blocks = (size + L.PT_BLOCK - 1) // L.PT_BLOCK
        data_start = pos + L.PT_BLOCK
        _need(data_start + data_blocks * L.PT_BLOCK <= len(blob), "pt_truncated_data", name)
        parent = name.rsplit("/", 1)[0] if "/" in name else None
        if parent is not None:
            # Parent must be a previously-seen DIRECTORY, not any seen entry
            # (a regular file cannot be a parent) (GIO01).
            _need(parent in seen_dirs, "pt_orphan_parent", name)
        seen.add(name)
        if is_dir:
            seen_dirs.add(name)
        entries.append((name, is_dir, data_start, size))
        pos = data_start + data_blocks * L.PT_BLOCK
    _need(bool(entries), "pt_empty_transport")
    return entries


def read_image(device_path: str, deadline: "_Deadline | None" = None) -> bytes:
    """Bounded read of the raw ``vde`` block device / image file.  Reads at
    most PT_IMAGE_BYTES_MAX bytes; a larger device fails closed (never a
    silent truncation of the transport)."""
    chunks = []
    remaining = L.PT_IMAGE_BYTES_MAX + L.PT_BLOCK  # read one extra block to detect overflow
    # GIO01: the OPEN itself is bounded by the watchdog.  The prior copy called
    # os.open BEFORE entering the _IOAlarm, so a stalled open (a wedged device
    # node that never returns from open(2)) could block unbounded before the
    # alarm was ever armed.  Arm the watchdog FIRST, then open and read under
    # it, so both the open and every blocking read fail closed at the deadline
    # (the cooperative check below still gives a precise rule on the fast path).
    with _IOAlarm(deadline, "pt_read_deadline"):
        fd = os.open(device_path, os.O_RDONLY)
        try:
            while remaining > 0:
                if deadline is not None:
                    deadline.check("pt_read_deadline")
                chunk = os.read(fd, min(1 << 20, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
        finally:
            os.close(fd)
    blob = b"".join(chunks)
    _need(len(blob) <= L.PT_IMAGE_BYTES_MAX, "pt_image_bytes")
    return blob


def _write_all(fd: int, data: bytes, deadline: "_Deadline | None" = None) -> None:
    """COMPLETE checked write: loop until every byte is written.  A short
    os.write (e.g. one byte of a three-byte buffer) must not be mistaken for a
    complete write (GIO01).  The elapsed-time bound is enforced ACROSS the
    (potentially blocking) write loop, not only between entries, so a stalled
    device fails closed rather than blocking unbounded (GIO01)."""
    view = memoryview(data)
    written = 0
    while written < len(view):
        if deadline is not None:
            deadline.check("pt_write_deadline")
        n = os.write(fd, view[written:])
        _need(n > 0, "pt_short_write")
        written += n


def extract(blob: bytes, destination: str, deadline: "_Deadline | None" = None):
    """Admission-then-write: ``parse_entries()`` first (full-transport refusal
    before any byte lands), then write with private modes.  Returns
    ``(entries, created)`` where ``created`` is the caller's owned copies,
    destination first.

    Every step after the first filesystem mutation — directory creation,
    per-entry writes, chmod and the final destination-directory fsync — is
    covered by fail-closed cleanup, under a finite elapsed-time deadline."""
    if deadline is None:
        deadline = _Deadline(L.PT_EXTRACT_SECONDS)
    entries = parse_entries(blob, deadline)
    _need(not os.path.lexists(destination), "pt_destination_exists", destination)
    created = []
    try:
        # GIO01: the entire filesystem-mutation section -- directory creation,
        # per-entry writes, chmod and the final directory fsync -- runs under a
        # single watchdog armed to the deadline, so a stalled mkdir/open/write/
        # fsync fails closed instead of blocking unbounded.  The per-chunk
        # cooperative checks below still give a precise rule on the fast path.
        with _IOAlarm(deadline, "pt_extract_deadline"):
            os.makedirs(destination, mode=L.PT_DIR_MODE)
            os.chmod(destination, L.PT_DIR_MODE)
            created.append(destination)
            for name, is_dir, offset, size in entries:
                deadline.check("pt_extract_deadline")
                path = os.path.join(destination, name)
                if is_dir:
                    os.mkdir(path, L.PT_DIR_MODE)
                    os.chmod(path, L.PT_DIR_MODE)
                else:
                    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, L.PT_FILE_MODE)
                    try:
                        _write_all(fd, blob[offset:offset + size], deadline)
                        deadline.check("pt_fsync_deadline")
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                    os.chmod(path, L.PT_FILE_MODE)
                created.append(path)
            # fsync the destination directory so the owned copies are durable
            # before the caller reads them.  Inside the try so a failure here is
            # also cleaned up.
            deadline.check("pt_dirsync_deadline")
            dfd = os.open(destination, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        # Final elapsed-time check: extraction as a WHOLE completed within the
        # bound (GIO01: extraction performed no final deadline check).
        deadline.check("pt_extract_final_deadline")
    except BaseException:
        # Never leave a partially-written private tree behind on any failure,
        # including directory creation, chmod and final synchronization.  The
        # original failure is the actionable one and MUST propagate; a cleanup
        # error here is best-effort so it never masks the root cause (the
        # caller re-checks residue against its owned-copy lifecycle).
        try:
            cleanup_tree(destination)
        except OSError:
            pass
        # GIO02: retain and REPORT ownership of a cleanup failure (names only,
        # never content). The original failure is the actionable one and
        # propagates; a residue left behind is surfaced, never silently
        # suppressed, so the caller's owned-copy lifecycle can act on it.
        if os.path.lexists(destination):
            import sys as _sys
            print("pt_cleanup_residue %s (owned private tree could not be fully removed; "
                  "residue ownership retained)" % destination, file=_sys.stderr)
        raise
    return entries, created


def extract_device(device_path: str, destination: str,
                   deadline: "_Deadline | None" = None):
    """Read the raw private-input device and extract it.  The two-step
    (admit-whole-transport, then write) ordering is preserved, under one shared
    finite deadline covering read, parse and extraction."""
    if deadline is None:
        deadline = _Deadline(L.PT_READ_SECONDS + L.PT_EXTRACT_SECONDS)
    blob = read_image(device_path, deadline)
    return extract(blob, destination, deadline)


def cleanup_tree(destination: str) -> int:
    """Owned-copy cleanup: remove every extracted byte without reading or
    logging content (names only).  Returns the number of removed paths."""
    removed = 0
    if not os.path.lexists(destination):
        return removed
    for root, dirs, files in os.walk(destination, topdown=False):
        for file_name in files:
            os.unlink(os.path.join(root, file_name))
            removed += 1
        for dir_name in dirs:
            os.rmdir(os.path.join(root, dir_name))
            removed += 1
    os.rmdir(destination)
    removed += 1
    return removed
