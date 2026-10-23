"""R04 — staged, bounded, confined result-image extraction
(dsmack.safe-extract-result/1).

Replaces extract_export.py, which is NOT a safe parser and is never part of
verification (shell interpolation, unchecked pipelines, no bounds).

Stages (normative order; every cap is FIXED before the receipt exists):
  S0 SNAPSHOT: copy the caller's image once into a fresh private 0600 file,
     hashing DURING the copy; digest must equal the expected image digest
     (D) and the size the expected byte count; chmod 0400; every later
     operation uses that immutable snapshot.  Deadline EXTRACT_SNAPSHOT_SECONDS.
  S1 BOOTSTRAP (fixed caps): stat+dump EXPORT-COMPLETE (cap
     EXTRACT_MARKER_CAP, content must equal EXTRACT_MARKER_BYTES) and
     <selector>/receipt.json (cap EXTRACT_RECEIPT_CAP).
  S2 RECEIPT VALIDATION: the caller validates the frozen receipt (manifest
     binding + validate_receipt_bytes) and hands back the parsed receipt.
  S3 OUTPUTS: only receipt-recorded outputs are extracted — streams for
     each NON-NULL stdout/stderr, artifacts not listed in outputs.missing —
     per-file cap = the receipt-declared byte count (+0 slack, enforced by
     RLIMIT_FSIZE in the tool process), then exact size equality.
     Missing/null/failed/cancelled semantics are PRESERVED: a null stream
     or a recorded-missing artifact is never demanded.

Tool contract: debugfs pinned by sha256, argv list (no shell), executed in
fresh user+net+mount+pid namespaces chrooted to a minimal jail
(sandbox_exec.py) with empty environment, /dev/null stdin, rlimits and a
wall timeout.  debugfs exits 0 even on lookup failure, so BOTH streams are
parsed: any stderr line beyond the version banner, or unexpected stdout, is
a refusal.  Source-inode metadata is read with `stat` through the same
confined tool: type must be regular, link count 1 — symlinks, hardlinks and
specials are refused at the SOURCE, not inferred from the dump destination.
Every dumped path is also lstat'd (regular, nlink 1, size == declared).
Name grammar: segments ^[A-Za-z0-9._-]{1,128}$ with '.' and '..' explicitly
refused, depth <= 4, count <= 256, total bytes <= 64 MiB.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import time

from . import protocol
from .errors import Refusal, need

SANDBOX_EXEC = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "sandbox_exec.py")
UNSHARE = "/usr/bin/unshare"
PYTHON3 = "/usr/bin/python3"

_SEGMENT = re.compile(protocol.EXTRACT_SEGMENT_RE)
_BANNER = re.compile(rb"^debugfs [0-9][0-9a-z.-]* \([^)]*\)$")
_STAT_TYPE = re.compile(rb"Type:\s+(\S+)")
_STAT_LINKS = re.compile(rb"Links:\s+(\d+)")
_STAT_SIZE = re.compile(rb"Size:\s+(\d+)")


def validate_image_path(path):
    """Protocol name grammar for in-image paths (R04)."""
    need(isinstance(path, str) and 0 < len(path) <= 512, "ex_bad_path")
    need(not path.startswith("/"), "ex_absolute_path", path)
    segments = path.split("/")
    need(len(segments) <= protocol.EXTRACT_DEPTH_MAX, "ex_too_deep", path)
    for segment in segments:
        need(segment not in (".", "..", ""), "ex_dot_segment", path)
        need(bool(_SEGMENT.match(segment)), "ex_name_grammar", path)
    return path


def sandbox_available():
    try:
        probe = subprocess.run(
            [UNSHARE, "--user", "--map-root-user", "--net", "--mount",
             "--pid", "--fork", "/bin/true"],
            capture_output=True, timeout=10)
        return probe.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


class SafeExtractor:
    def __init__(self, workdir, tool_path="/usr/sbin/debugfs",
                 tool_sha256=None):
        self.workdir = os.path.abspath(workdir)
        need(not os.path.exists(self.workdir), "ex_workdir_exists")
        os.makedirs(self.workdir, mode=0o700)
        self.tool_path = tool_path
        actual = hashlib.sha256(open(tool_path, "rb").read()).hexdigest()
        need(tool_sha256 is not None, "ex_tool_not_pinned")
        need(actual == tool_sha256, "ex_tool_hash_mismatch",
             "%s != %s" % (actual, tool_sha256))
        self.tool_sha256 = tool_sha256
        need(sandbox_available(), "ex_sandbox_unavailable",
             "user+net+mount+pid namespaces are required; no fallback")
        self.snapshot_path = None
        self.dest = os.path.join(self.workdir, "extracted")
        os.mkdir(self.dest, 0o700)
        self._deadline = None
        self._extracted_total = 0
        self._extracted_count = 0
        self._invocations = 0

    # ---- S0 ----
    def snapshot(self, image_path, expected_sha256, expected_bytes):
        start = time.monotonic()
        snap = os.path.join(self.workdir, "snapshot.img")
        fd = os.open(snap, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        digest = hashlib.sha256()
        copied = 0
        try:
            with open(image_path, "rb") as src:
                while True:
                    need(time.monotonic() - start
                         <= protocol.EXTRACT_SNAPSHOT_SECONDS,
                         "ex_snapshot_deadline")
                    chunk = src.read(1 << 20)
                    if not chunk:
                        break
                    copied += len(chunk)
                    need(copied <= expected_bytes, "ex_image_oversize")
                    digest.update(chunk)
                    # REF06: complete write — os.write may be short.
                    view = memoryview(chunk)
                    sent = 0
                    while sent < len(view):
                        n = os.write(fd, view[sent:])
                        need(n > 0, "ex_short_write")
                        sent += n
            os.fsync(fd)
        finally:
            os.close(fd)
        need(copied == expected_bytes, "ex_image_size_mismatch",
             "%d != %d" % (copied, expected_bytes))
        need(digest.hexdigest() == expected_sha256, "ex_image_digest_mismatch")
        os.chmod(snap, 0o400)
        self.snapshot_path = snap
        self._deadline = time.monotonic() + protocol.EXTRACT_WALL_SECONDS
        return snap

    # ---- confined tool invocation ----
    def _tool(self, request, fsize_cap):
        need(self.snapshot_path is not None, "ex_no_snapshot")
        need(time.monotonic() <= self._deadline, "ex_wall_deadline")
        self._invocations += 1
        jail = os.path.join(self.workdir, "jail-%d" % self._invocations)
        os.mkdir(jail, 0o700)
        config_path = os.path.join(self.workdir,
                                   "toolcfg-%d.json" % self._invocations)
        with open(config_path, "w") as fh:
            json.dump({
                "jail": jail,
                "snapshot": self.snapshot_path,
                "workdir": self.dest,
                "tool": self.tool_path,
                "tool_args": ["-R", request, "/snap.img"],
                "rlimit_as": protocol.EXTRACT_TOOL_RLIMIT_AS,
                "rlimit_cpu": protocol.EXTRACT_TOOL_RLIMIT_CPU,
                "rlimit_fsize": int(fsize_cap),
            }, fh)
        argv = [UNSHARE, "--user", "--map-root-user", "--net", "--mount",
                "--pid", "--fork", PYTHON3, SANDBOX_EXEC, config_path]
        try:
            completed = subprocess.run(
                argv, stdin=subprocess.DEVNULL, capture_output=True,
                timeout=protocol.EXTRACT_TOOL_TIMEOUT_SECONDS, env={})
        except subprocess.TimeoutExpired:
            raise Refusal("ex_tool_timeout", request) from None
        need(len(completed.stdout) <= protocol.EXTRACT_TOOL_STDOUT_CAP,
             "ex_tool_stdout_overflow")
        need(len(completed.stderr) <= protocol.EXTRACT_TOOL_STDERR_CAP,
             "ex_tool_stderr_overflow")
        need(completed.returncode == 0, "ex_tool_status",
             "rc=%d" % completed.returncode)
        # debugfs reports errors on stderr WITH exit status 0: parse it.
        lines = [line for line in completed.stderr.split(b"\n") if line]
        need(len(lines) >= 1 and _BANNER.match(lines[0]),
             "ex_tool_banner", repr(completed.stderr[:200]))
        need(len(lines) == 1, "ex_tool_stderr",
             repr(b"\n".join(lines[1:])[:300]))
        return completed.stdout

    def _stat_source(self, image_path):
        """Source-inode metadata through the confined tool: regular, one
        link; returns the source size."""
        stdout = self._tool("stat /" + image_path, fsize_cap=1)
        type_match = _STAT_TYPE.search(stdout)
        links_match = _STAT_LINKS.search(stdout)
        size_match = _STAT_SIZE.search(stdout)
        need(type_match is not None and links_match is not None
             and size_match is not None, "ex_stat_unparseable", image_path)
        need(type_match.group(1) == b"regular", "ex_source_not_regular",
             "%s: %s" % (image_path, type_match.group(1).decode()))
        need(links_match.group(1) == b"1", "ex_source_link_count", image_path)
        return int(size_match.group(1))

    def _dump(self, image_path, cap):
        validate_image_path(image_path)
        need(self._extracted_count < protocol.EXTRACT_FILE_COUNT_MAX,
             "ex_file_count")
        source_size = self._stat_source(image_path)
        need(source_size <= cap, "ex_source_over_cap",
             "%s: %d > %d" % (image_path, source_size, cap))
        need(self._extracted_total + source_size
             <= protocol.EXTRACT_TOTAL_BYTES_MAX, "ex_total_bytes")
        dest_name = "f%04d.bin" % self._extracted_count
        self._tool("dump /%s %s" % (image_path, dest_name), fsize_cap=cap)
        dest_path = os.path.join(self.dest, dest_name)
        need(os.path.lexists(dest_path), "ex_dump_missing", image_path)
        stat = os.lstat(dest_path)
        need(os.path.stat.S_ISREG(stat.st_mode), "ex_dump_not_regular")
        need(stat.st_nlink == 1, "ex_dump_link_count")
        need(stat.st_size == source_size, "ex_dump_size_mismatch",
             "%s: %d != %d" % (image_path, stat.st_size, source_size))
        self._extracted_count += 1
        self._extracted_total += stat.st_size
        return dest_path

    # ---- staged protocol ----
    def extract_bootstrap(self, selector):
        """S1: marker + receipt under FIXED caps (no receipt-derived value
        exists yet).

        CANONICAL GUEST LAYOUT (CROSS-LANE-VERIFIED-FINDINGS.layout): the
        per-selector completion marker lives at ``<selector>/outputs/
        EXPORT-COMPLETE`` (NOT a shared root marker) and the frozen receipt at
        ``<selector>/receipt.json``, one level ABOVE the outputs subtree.  The
        marker is dumped and byte-compared BEFORE the receipt so an export
        without its completion marker fails closed before any receipt parse."""
        marker_rel = "%s/outputs/%s" % (selector, protocol.EXTRACT_MARKER_NAME)
        marker_path = self._dump(marker_rel, protocol.EXTRACT_MARKER_CAP)
        marker = open(marker_path, "rb").read()
        need(marker == protocol.EXTRACT_MARKER_BYTES, "ex_bad_marker",
             repr(marker[:64]))
        receipt_rel = "%s/receipt.json" % selector
        receipt_path = self._dump(receipt_rel, protocol.EXTRACT_RECEIPT_CAP)
        return receipt_rel, open(receipt_path, "rb").read()

    def extract_index(self, selector):
        """S2b: dump and parse the producer's ``<selector>/outputs/index.json``
        binding index FROM THE IMAGE (not an in-memory value the producer
        returned).  The relying party reconciles the layout the producer wrote
        against the bytes the extractor delivers using THIS extracted index, so
        the two layouts are reconciled by retained data rather than by two code
        paths merely agreeing in memory."""
        index_rel = "%s/outputs/index.json" % selector
        index_path = self._dump(index_rel, protocol.EXTRACT_RECEIPT_CAP)
        raw = open(index_path, "rb").read()
        self.last_index_bytes = raw
        try:
            index = json.loads(raw)
        except ValueError as exc:
            raise Refusal("ex_index_unreadable", str(exc)) from exc
        need(isinstance(index, dict)
             and index.get("schema") == "dsmack.run-output-export/1",
             "ex_index_schema", index_rel)
        return index_rel, index

    def extract_outputs(self, selector, receipt):
        """S3: receipt-recorded outputs only; declared byte counts are the
        per-file caps; frozen missing/null semantics preserved.  Canonical
        guest paths: ``<selector>/outputs/streams/<stream>`` (NO .bin suffix)
        and ``<selector>/outputs/artifacts/<name>``."""
        outputs = receipt.get("outputs")
        need(isinstance(outputs, dict), "ex_receipt_outputs")
        missing = set(outputs.get("missing") or [])
        collected = {}
        for stream in ("stdout", "stderr"):
            declared = outputs.get(stream)
            if declared is None:
                continue  # null stream: never demanded, never extracted
            path = "%s/outputs/streams/%s" % (selector, stream)
            collected["stream:" + stream] = (
                self._dump(path, declared["bytes"]), declared)
        for artifact in outputs.get("artifacts") or []:
            name = artifact["name"]
            if name in missing:
                continue  # recorded-missing artifacts are not demanded
            path = "%s/outputs/artifacts/%s" % (selector, name)
            collected["artifact:" + name] = (
                self._dump(path, artifact["bytes"]), artifact)
        # exact byte + digest verification from the DELIVERED bytes
        for label, (path, declared) in collected.items():
            data = open(path, "rb").read()
            need(len(data) == declared["bytes"], "ex_output_length", label)
            need(hashlib.sha256(data).hexdigest() == declared["sha256"],
                 "ex_output_digest", label)
        return collected

    def cleanup(self):
        shutil.rmtree(self.workdir, ignore_errors=True)
