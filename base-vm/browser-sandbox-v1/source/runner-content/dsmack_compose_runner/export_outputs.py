"""Real output export through the compose-runner lifecycle (guest-io-integration).

The runner already captures the completion service's ACTUAL demuxed stdout /
stderr bytes and the collected artifact bytes (lifecycle.py) and records their
digests + lengths in the v4 receipt (receipting.py).  This module writes those
EXACT bytes out to a STABLE, self-describing RESULT-IMAGE tree BEFORE the
private workspace is destroyed, so a consumer can recompute every recorded
output from retained bytes -- rather than depending on the supervisor's shell
``run.out``/``run.err`` redirection (which is neither stable nor part of the
receipt's identity, and may carry process diagnostics).

RESULT-IMAGE layout (ONE versioned producer/consumer layout; the CANONICAL
GUEST layout the cross-lane coordinator fixed -- GIO04.  The selector is the
MANIFEST NAME (a confined single segment), supporting explicit MULTI-SELECTOR
completion: several manifests write independent ``<selector>/`` subtrees under
one shared result root, each with its OWN per-selector completion marker):

    <result-root>/
        <selector>/                     # == manifest name
            receipt.json                # the frozen v4 receipt bytes (committed FIRST)
            summary.json                # optional run summary (producer diagnostic)
            outputs/
                index.json              # dsmack.run-output-export/1 binding index
                streams/stdout          # exact completion stdout bytes (if captured; NO .bin)
                streams/stderr          # exact completion stderr bytes (if captured; NO .bin)
                artifacts/<name>        # exact recorded artifact bytes
                EXPORT-COMPLETE         # per-selector marker, written LAST (dsmack-export/1\n)

The smoke consumer (launch_vm_dstack_arm64.verify_exported_receipts) and the
host fixture generator consume THIS tree directly: per selector it checks
``<selector>/receipt.json``, ``<selector>/outputs/EXPORT-COMPLETE`` (exact
bytes), ``<selector>/outputs/index.json`` bound to the receipt, and each
NON-NULL stream at ``<selector>/outputs/streams/<stream>`` and artifact at
``<selector>/outputs/artifacts/<name>``.

Durability / completion / failure semantics (GIO05):
  * the receipt.json, summary.json, every stream/artifact and the index are
    each O_EXCL-created, fully written and fsync'd, and the streams/artifacts
    and the ``outputs`` directory plus the selector directory are fsync'd,
    BEFORE the completion marker is written;
  * the per-selector ``outputs/EXPORT-COMPLETE`` marker is the LAST durable
    write.  It is published through an EXPLICIT fail-distinguishable protocol:
    the marker bytes are written and fsync'd and the ``outputs`` directory is
    fsync'd, and if EITHER synchronization boundary raises (the exact fault
    the review injected) the marker is ROLLED BACK (unlinked + the directory
    re-fsync'd) so a synchronization failure can NEVER leave an
    apparently-complete marker.  Its presence therefore means every byte of
    the package is already durably on disk;
  * any failure (short write, digest mismatch vs the receipt, fsync/IO error,
    directory-sync error) raises and leaves NO marker: a consumer that does
    not find the marker treats the export as incomplete and fails closed.  A
    failed publication is distinguishable from a completed one.

Digest/length semantics are EXACT and bound to the receipt:
  * a stream the manifest did not declare for capture is null (no file);
  * a captured stream's exported bytes MUST hash to the receipt's recorded
    sha256 and match its byte length (mismatch is a fail-closed runner bug);
  * ``truncated`` is true only for an output-limit CANCEL that retained the
    bounded bytes (status=cancelled, cancel.reason=limit-output); the index
    records it faithfully rather than presenting a bounded digest as complete;
  * a missing artifact is listed in ``missing`` with NO file and NO digest;
  * failed/cancelled runs still export whatever WAS captured (the receipt and
    its outputs are preserved), so failed/cancelled receipts are retrievable.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat as stat_module

from .errors import RunnerError

EXPORT_SCHEMA = "dsmack.run-output-export/1"
EXPORT_MARKER_NAME = "EXPORT-COMPLETE"
EXPORT_MARKER_BYTES = b"dsmack-export/1\n"   # matches io-contract-reference R04
# selector grammar mirrors the reference extractor segment grammar.
_SELECTOR_RE = re.compile(r"^[A-Za-z0-9._-]{1,63}$")
# artifact-name grammar: a single confined path segment (no traversal).
_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def _write_file_checked(dir_path: str, name: str, data: bytes, mode: int = 0o644) -> str:
    """O_EXCL create + complete write + fsync.  A short write raises."""
    path = os.path.join(dir_path, name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        offset = 0
        view = memoryview(data)
        while offset < len(data):
            written = os.write(fd, view[offset:])
            if written <= 0:
                raise RunnerError("export-short-write", "a checked export write made no progress")
            offset += written
        os.fsync(fd)
    finally:
        os.close(fd)
    return path


def _fsync_dir(dir_path: str) -> None:
    fd = os.open(dir_path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _publish_marker(outputs_dir: str) -> None:
    """GIO05: publish the per-selector EXPORT-COMPLETE marker through a DURABLE
    ACCEPTANCE protocol in which the FINAL marker name only ever appears AFTER
    its bytes are already durably on disk -- so the marker's presence requires
    SUCCESSFUL CLOSURE and a failed publication can never read as complete, even
    on a filesystem the supervisor later syncs and unmounts cleanly.

    The previous protocol wrote the marker AT ITS FINAL NAME and only THEN
    fsync'd it; when the fsync failed and the rollback unlink ALSO failed -- the
    exact combined fault the review injected -- the exact marker bytes were left
    present at the final name, and the disk-only consumer (which checks marker
    presence + exact bytes + index binding) accepted the failed export on an
    otherwise-clean filesystem.  Raising a distinct Python exception did not
    alter the surviving marker, so the defect survived.

    The durable protocol instead:
      1. writes the marker bytes to a ``.pending`` TEMP file and fsyncs the
         temp fd (A) -- the bytes are durable in a NON-final name;
      2. fsyncs the directory so the temp entry is durable (B);
      3. os.rename()s the temp to the FINAL name -- rename is atomic, so the
         final marker either does not exist or carries fully-durable bytes;
      4. fsyncs the directory so the rename is durable (C).
    If ANY boundary (A/B/rename/C) raises, the FINAL marker name was never
    created, so a consumer sees NO marker and fails closed -- the clean-fs
    false-complete is structurally impossible.  Rollback removes the temp (and,
    defensively, the final name); if the final name somehow survives and cannot
    be removed, its content is NEUTRALIZED (so the consumer's exact-byte check
    rejects it) and a DISTINCT chained error is raised."""
    final_path = os.path.join(outputs_dir, EXPORT_MARKER_NAME)
    tmp_path = os.path.join(outputs_dir, EXPORT_MARKER_NAME + ".pending")
    try:
        if os.path.lexists(tmp_path):
            os.unlink(tmp_path)
    except OSError:
        pass
    try:
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        try:
            offset = 0
            view = memoryview(EXPORT_MARKER_BYTES)
            while offset < len(EXPORT_MARKER_BYTES):
                written = os.write(fd, view[offset:])
                if written <= 0:
                    raise RunnerError("export-short-write", "a checked marker write made no progress")
                offset += written
            os.fsync(fd)              # (A) the marker bytes are durable in the temp
        finally:
            os.close(fd)
        _fsync_dir(outputs_dir)       # (B) the temp dir entry is durable
        os.rename(tmp_path, final_path)   # atomic: the final name appears only now
        _fsync_dir(outputs_dir)       # (C) the rename is durable
    except BaseException as publish_exc:
        # Roll back BOTH names.  A failure before the rename means the final
        # marker never existed (the consumer sees incomplete).  Best-effort
        # removals; the original failure is the actionable one.
        for path in (tmp_path, final_path):
            try:
                if os.path.lexists(path):
                    os.unlink(path)
            except OSError:
                pass
        try:
            _fsync_dir(outputs_dir)
        except OSError:
            pass
        if os.path.lexists(final_path):
            # The final marker survives and could not be removed.  NEUTRALIZE
            # its content so the consumer's exact-byte check rejects it, then
            # raise a DISTINCT chained error: a failed publication can never
            # read as complete.
            neutralized = False
            try:
                nfd = os.open(final_path, os.O_WRONLY | os.O_TRUNC)
                try:
                    os.write(nfd, b"dsmack-export/INCOMPLETE\n")
                    os.fsync(nfd)
                finally:
                    os.close(nfd)
                _fsync_dir(outputs_dir)
                neutralized = True
            except OSError:
                pass
            raise RunnerError(
                "export-marker-rollback-failed",
                "the completion marker publication failed AND the final marker could not be "
                "removed; its content was %s so the export is explicitly incomplete (no false "
                "complete on a clean filesystem)" % ("neutralized" if neutralized else "NOT neutralized"),
            ) from publish_exc
        # The final marker is absent -> the export is cleanly incomplete.
        if isinstance(publish_exc, RunnerError):
            raise
        raise RunnerError(
            "export-marker-publish-failed",
            "the completion marker could not be durably published; no final marker exists so the "
            "export is incomplete (fail-closed)",
        ) from publish_exc


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def export_run_outputs(result_root: str, *, selector: str, receipt: dict,
                       receipt_bytes: bytes, streams: dict, artifact_sources: dict,
                       stream_truncated: dict | None = None,
                       summary_bytes: bytes | None = None) -> dict:
    """Write the stable result-image package under ``result_root`` and publish
    the root completion marker LAST.

    ``selector`` is the receipt selector subdirectory; ``streams`` maps
    'stdout'/'stderr' to the exact captured bytes (or is missing a key when the
    stream was not captured); ``artifact_sources`` maps a recorded artifact name
    to its source path inside the (not-yet-destroyed) private workspace;
    ``stream_truncated`` optionally maps a stream to a bool (output-limit
    truncation).  Returns the index dict that was written.  Raises on any
    failure, leaving NO marker."""
    stream_truncated = stream_truncated or {}
    outputs = receipt["outputs"]
    if not (isinstance(selector, str) and _SELECTOR_RE.match(selector)):
        raise RunnerError("export-bad-selector", "the receipt selector is not a confined single segment")
    if not os.path.isdir(result_root):
        raise RunnerError("export-root-missing", "the result-image root directory does not exist")
    # Per-SELECTOR collision only: a shared result root legitimately carries
    # many selectors (multi-selector completion), so a sibling selector dir is
    # fine -- but THIS selector's dir must be fresh.
    selector_dir = os.path.join(result_root, selector)
    if os.path.lexists(selector_dir):
        raise RunnerError("export-dir-collision", "the per-selector directory already exists")
    os.makedirs(selector_dir, mode=0o755)
    os.chmod(selector_dir, 0o755)
    outputs_dir = os.path.join(selector_dir, "outputs")
    streams_dir = os.path.join(outputs_dir, "streams")
    artifacts_dir = os.path.join(outputs_dir, "artifacts")
    os.makedirs(outputs_dir, mode=0o755)
    os.makedirs(streams_dir, mode=0o755)
    os.makedirs(artifacts_dir, mode=0o755)

    # -- receipt.json FIRST: the package is committed before the marker ------
    _write_file_checked(selector_dir, "receipt.json", receipt_bytes, 0o644)
    if summary_bytes is not None:
        _write_file_checked(selector_dir, "summary.json", summary_bytes, 0o644)

    index = {
        "schema": EXPORT_SCHEMA,
        "selector": selector,
        "run_id": receipt["run_id"],
        "manifest_sha256": receipt["manifest_sha256"],
        "environment": receipt["environment"],
        "status": outputs["status"],
        "exit_code": outputs["exit_code"],
        "cancel": outputs["cancel"],
        # receipt.json lives at the selector root, one level ABOVE outputs/.
        "receipt_path": "../receipt.json",
        "streams": {"stdout": None, "stderr": None},
        "artifacts": [],
        "missing": list(outputs["missing"]),
        "receipt_sha256": _sha256(receipt_bytes),
    }

    # -- streams: exact bytes, digest/length bound to the receipt -----------
    # A captured stream records a real digest even when empty (sha256(b"")); a
    # NON-captured stream is null (no file).  Paths are relative to outputs/
    # and carry NO .bin suffix (canonical guest layout, GIO04).
    for stream in ("stdout", "stderr"):
        recorded = outputs[stream]            # {sha256,bytes} or None
        if recorded is None:
            continue                          # not declared/captured -> null
        if stream not in streams or streams[stream] is None:
            raise RunnerError("export-stream-missing",
                              "the receipt records stream %s but no captured bytes were provided" % stream)
        data = streams[stream]
        digest = _sha256(data)
        if digest != recorded["sha256"] or len(data) != recorded["bytes"]:
            raise RunnerError("export-stream-mismatch",
                              "exported %s bytes do not match the receipt digest/length" % stream)
        _write_file_checked(streams_dir, stream, data, 0o644)
        index["streams"][stream] = {
            "path": "streams/%s" % stream,
            "sha256": digest,
            "bytes": len(data),
            "truncated": bool(stream_truncated.get(stream, False)),
        }

    # -- artifacts: exact bytes, digest/length bound to the receipt ---------
    # Artifacts always carry the SHA256 of their exact bytes, including an
    # empty file. The frozen receipt validator requires a digest for artifacts.
    for entry in outputs["artifacts"]:
        name = entry["name"]
        if not _NAME_RE.match(name) or name in (".", ".."):
            raise RunnerError("export-bad-artifact-name", "a recorded artifact name is not a confined segment")
        source = artifact_sources.get(name)
        if source is None:
            raise RunnerError("export-artifact-source-missing",
                              "the receipt records an artifact with no provided source path")
        st = os.lstat(source)
        if stat_module.S_ISLNK(st.st_mode) or not stat_module.S_ISREG(st.st_mode):
            raise RunnerError("export-refused", "refusing to export a non-regular artifact entry")
        with open(source, "rb") as handle:
            data = handle.read()
        digest = _sha256(data)
        if digest != entry["sha256"] or len(data) != entry["bytes"]:
            raise RunnerError("export-artifact-mismatch",
                              "exported artifact bytes do not match the receipt digest/length")
        _write_file_checked(artifacts_dir, name, data, 0o644)
        index["artifacts"].append({
            "name": name,
            "path": "artifacts/%s" % name,
            "sha256": digest,
            "bytes": len(data),
        })

    # -- index.json, durable, then the per-selector completion marker LAST ---
    index_bytes = json.dumps(index, indent=1, sort_keys=True).encode("utf-8") + b"\n"
    _write_file_checked(outputs_dir, "index.json", index_bytes, 0o644)
    _fsync_dir(streams_dir)
    _fsync_dir(artifacts_dir)
    _fsync_dir(outputs_dir)
    _fsync_dir(selector_dir)
    # GIO05: PRESERVE result-root synchronization -- the repair had dropped it,
    # so the new <selector>/ directory entry itself was not durably recorded in
    # the shared result root before the marker was published.  fsync the result
    # root so the selector subtree's existence is durable before completion.
    _fsync_dir(result_root)
    _publish_marker(outputs_dir)
    return index
