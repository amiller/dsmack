#!/usr/bin/env python3
"""CROSS-LANE-SOURCE / REF02 — the complete Mini->Zed evidence transfer+check
entry (CROSS-LANE-VERIFIED-FINDINGS.evidence_transport).

The genuine Linux verifier/checker and the ARM64 extractor run on Zed; the
signing/ceremony runs on the Apple Mini.  This module is the explicit private
transfer of the COMPLETE exact evidence bundle (image / console / receipt /
outputs / statement / envelope / enrollment / assertions / report) from the
Mini to Zed, plus the Zed-side check:

  * ``package(evidence_dir, out_tar)`` — Mini side.  Writes a tar of the exact
    retained evidence bytes and a TRANSFER-MANIFEST.json that hashes ONLY the
    PUBLIC outputs; the EXCLUDED private input (``runtime_envelope_private``) is
    still transferred but its bytes are NEVER hashed into the public transport
    manifest (R05 excluded transport — no digest of the private envelope).

  * ``receive(tar_path, dest_dir)`` — Zed side.  SAFELY extracts the tar
    (regular files / directories only; confined segment names; no traversal,
    symlink, hardlink, absolute path or device; bounded count/size), then
    verifies every public file's retained bytes hash + length EXACTLY against
    the transport manifest and that no undeclared public file was injected.

  * ``zed_check(dest_dir, context_path)`` — Zed side.  Runs the INDEPENDENT
    relying-party checker (checker.check) over the received retained bytes with
    a Zed-admitted expected context, reporting evidence validity separately from
    task success (exit 0 vs 3), identically to the operator ``check`` command.

The transport moves exact bytes and checks RETAINED bytes on arrival; it never
re-derives a digest from a value it was told — the whole point of the gate.
"""
import base64
import hashlib
import json
import os
import stat
import io
import tempfile
import sys
import tarfile

HERE = os.path.dirname(os.path.abspath(__file__))
CANDIDATE = os.path.dirname(HERE)
sys.path.insert(0, CANDIDATE)

from runresult_ref import checker as checker_mod  # noqa: E402
from runresult_ref import retained_evidence       # noqa: E402
from runresult_ref.frozen import core
from runresult_ref.errors import Refusal, need    # noqa: E402

TRANSFER_SCHEMA = "dsmack.mini-to-zed-evidence-transfer/1"
MANIFEST_NAME = "TRANSFER-MANIFEST.json"
# the private runtime envelope is EXCLUDED from the public transport hash set
# (its bytes are bound only by frozen receipt validation, never digested here).
EXCLUDED_PRIVATE = ("runtime_envelope_private",)
# assertions needed by the checker are carried in the request.
REQUEST_NAME = "request.json"

_SEGMENT_MAX = 128
_ENTRY_COUNT_MAX = 4096
_FILE_BYTES_MAX = 1 << 30            # 1 GiB (the result image dominates)
_TOTAL_BYTES_MAX = 2 << 30


def _safe_relpath(relpath):
    need(isinstance(relpath, str) and relpath and not relpath.startswith("/"),
         "transfer_name_unsafe", str(relpath))
    for seg in relpath.split("/"):
        need(seg not in ("", ".", "..") and len(seg) <= _SEGMENT_MAX
             and all(c.isalnum() or c in "._-" for c in seg),
             "transfer_name_unsafe", relpath)
    return relpath


def _walk_files(root_fd, directory_admit=None):
    """Bounded descriptor-relative traversal; reject every special entry."""
    count = [0]
    def walk(fd, prefix, depth):
        need(depth <= 8, "transfer_depth")
        with os.scandir(fd) as entries:
            for entry in entries:
                count[0] += 1
                need(count[0] <= _ENTRY_COUNT_MAX, "transfer_entry_count")
                rel = prefix + entry.name
                _safe_relpath(rel)
                st = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(st.st_mode):
                    if directory_admit is not None: directory_admit(rel)
                    sub = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        yield from walk(sub, rel + "/", depth + 1)
                    finally:
                        os.close(sub)
                else:
                    need(stat.S_ISREG(st.st_mode), "transfer_non_regular", rel)
                    if rel != MANIFEST_NAME:
                        leaf = retained_evidence._open_leaf_nofollow(fd, entry.name, rel)
                        try:
                            need(stat.S_ISREG(os.fstat(leaf).st_mode), "transfer_non_regular", rel)
                            yield rel, leaf
                        finally:
                            os.close(leaf)
    yield from walk(root_fd, "", 0)


def _enumerate(evidence_dir):
    fd = os.open(evidence_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        return sorted(rel for rel, _leaf in _walk_files(fd))
    finally:
        os.close(fd)


# Auxiliary retained originals are transport-only diagnostics. These finite
# names do not become checker inputs or substitute for canonical evidence.
APP_DIAGNOSTICS = frozenset(("statement.json", "envelope.json", "launch-assertion.cbor",
    "result-assertion.cbor", "launch-client-data.bin", "result-client-data.bin",
    "backend-receipt-v3.json", "backend-run-result-v3.json", "pair-retention.json",
    "keyId.txt", "trace.jsonl", "compose-manifest.bin", "admission.json", "policy.json",
    "image-manifest.json", "checksum-manifest.txt", "metadata.json", "admitted-inputs.json",
    "result.img", "console-v3.log"))
LOG_DIAGNOSTICS = frozenset(("stdout.txt", "stderr.txt", "launch-status.json",
    "helper.stdout", "helper.stderr", "helper-status.json"))


def _diagnostic_format(rel):
    if rel in {"closure-context.json", "checker-context.json", "RETENTION-STATUS.json"}: return "json"
    if not rel.startswith(("app/", "logs/")): return None
    parts = rel.split("/")
    allowed = APP_DIAGNOSTICS if parts[0] == "app" else LOG_DIAGNOSTICS
    need(len(parts) == 2 and parts[1] in allowed, "transfer_unknown_diagnostic", rel)
    name = parts[1]
    if name.endswith(".json") or name == "compose-manifest.bin": return "json"
    if name.endswith(".jsonl"): return "jsonl"
    if name.endswith(".cbor"): return "cbor"
    if name in ("keyId.txt", "checksum-manifest.txt"): return "ascii"
    if name == "result.img": return "image"
    if name in ("launch-client-data.bin", "result-client-data.bin"): return "binary"
    return "raw-log"


def _diagnostic_cap(rel):
    kind = _diagnostic_format(rel)
    return (1 << 30) if kind == "image" else (16 << 20) if kind == "raw-log" else (1 << 20) if kind else _FILE_BYTES_MAX


def _validate_diagnostic(rel, stream, size):
    kind = _diagnostic_format(rel)
    if kind is None: return
    need(size <= _diagnostic_cap(rel), "transfer_diagnostic_oversize", rel)
    if kind in ("image", "raw-log", "binary"): return
    stream.seek(0); data = stream.read((1 << 20) + 1); stream.seek(0)
    try:
        if kind in ("json", "jsonl"):
            values = data.splitlines() if kind == "jsonl" else [data]
            for value in values:
                need(isinstance(core.unique_json(value.decode("utf-8")), dict), "transfer_diagnostic_format", rel)
        elif kind == "cbor":
            need(isinstance(core.decode(data), dict), "transfer_diagnostic_format", rel)
        else:
            need(data.isascii() and b"\x00" not in data, "transfer_diagnostic_format", rel)
    except (ValueError, UnicodeError, core.Reject) as exc:
        raise Refusal("transfer_diagnostic_format", "%s: %s" % (rel, exc)) from exc


def _is_excluded_private(rel):
    if rel in EXCLUDED_PRIVATE:
        return True
    parts = rel.split("/")
    return (len(parts) == 3 and parts[0] == "selectors" and
            parts[2] == "runtime_envelope_private" and
            bool(retained_evidence.schemas.SELECTOR_RE.fullmatch(parts[1])))


def _canonical_directory(rel):
    parts = rel.split("/")
    selector_dir = (parts[0] == "selectors" and (
        len(parts) == 1 or
        (2 <= len(parts) <= 4 and bool(retained_evidence.schemas.SELECTOR_RE.fullmatch(parts[1])) and
         (len(parts) == 2 or parts[2] == "outputs") and
         (len(parts) < 4 or parts[3] in ("streams", "artifacts")))))
    need(selector_dir or rel in {"outputs", "outputs/streams", "outputs/artifacts", "app", "logs"},
         "transfer_unexpected_directory", rel)


def package(evidence_dir, out_tar):
    """Transfer one bounded descriptor snapshot; manifest hashes those bytes.

    A private envelope is copied but never hashed into a transport record.
    Directory/name replacement cannot redirect an admitted file descriptor.
    """
    root = os.open(evidence_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    public = {}; private = []; total = 0
    try:
        with tarfile.open(out_tar, "w") as tar:
            for rel, fd in _walk_files(root, _canonical_directory):
                excluded = _is_excluded_private(rel)
                digest = None if excluded else hashlib.sha256()
                size = 0
                per_file_cap = min(_FILE_BYTES_MAX, _diagnostic_cap(rel))
                with tempfile.SpooledTemporaryFile(max_size=1 << 20, dir=os.path.dirname(os.path.abspath(out_tar))) as snapshot:
                    while True:
                        data = os.read(fd, min(1 << 20, per_file_cap + 1 - size, _TOTAL_BYTES_MAX + 1 - total))
                        if not data: break
                        size += len(data); total += len(data)
                        need(size <= per_file_cap, "transfer_file_oversize", rel)
                        need(total <= _TOTAL_BYTES_MAX, "transfer_total_oversize", rel)
                        snapshot.write(data)
                        if digest is not None: digest.update(data)
                    _validate_diagnostic(rel, snapshot, size)
                    snapshot.seek(0)
                    info = tarfile.TarInfo(rel); info.size = size; info.mode = 0o600
                    tar.addfile(info, snapshot)
                if excluded: private.append(rel)
                else: public[rel] = {"sha256": digest.hexdigest(), "bytes": size}
            manifest = {"schema": TRANSFER_SCHEMA, "public": public,
                        "excluded_private": sorted(private)}
            wire = json.dumps(manifest, indent=1, sort_keys=True).encode()
            info = tarfile.TarInfo(MANIFEST_NAME); info.size = len(wire); info.mode = 0o600
            tar.addfile(info, io.BytesIO(wire))
    finally:
        os.close(root)
    return manifest


# ---------------------------------------------------------------------------
# Zed side
# ---------------------------------------------------------------------------
def _parent_fd(root, rel, create=False):
    fd = os.dup(root)
    try:
        for part in rel.split("/")[:-1]:
            if create:
                try: os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError: pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def receive(tar_path, dest_dir):
    """Bounded extraction and verification relative to one retained root fd."""
    need(not os.path.lexists(dest_dir), "transfer_dest_exists", dest_dir)
    os.mkdir(dest_dir, 0o700)
    root = os.open(dest_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    count = 0; total = 0; seen = set()
    try:
        with tarfile.open(tar_path, "r") as tar:
            for member in tar:
                count += 1
                need(count <= _ENTRY_COUNT_MAX, "transfer_entry_count")
                need(member.isreg() or member.isdir(), "transfer_bad_entry_type", member.name)
                rel = _safe_relpath(member.name)
                need(rel not in seen, "transfer_duplicate_entry", rel); seen.add(rel)
                parent = _parent_fd(root, rel, create=True)
                name = rel.split("/")[-1]
                try:
                    if member.isdir():
                        try: os.mkdir(name, 0o700, dir_fd=parent)
                        except FileExistsError: pass
                        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                        os.close(child)
                        continue
                    need(0 <= member.size <= _FILE_BYTES_MAX, "transfer_file_oversize", rel)
                    total += member.size
                    need(total <= _TOTAL_BYTES_MAX, "transfer_total_oversize")
                    src = tar.extractfile(member)
                    need(src is not None, "transfer_unreadable", rel)
                    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
                    with src, os.fdopen(fd, "wb") as out:
                        remaining = member.size
                        while remaining:
                            data = src.read(min(1 << 20, remaining))
                            need(bool(data), "transfer_truncated", rel)
                            out.write(data); remaining -= len(data)
                        out.flush(); os.fsync(out.fileno())
                    os.fsync(parent)
                finally:
                    os.close(parent)
        manifest = retained_evidence._load_wire_json_at(root, MANIFEST_NAME, 1 << 20, MANIFEST_NAME)
        need(isinstance(manifest, dict) and set(manifest) == {"schema", "public", "excluded_private"}, "transfer_manifest_shape")
        need(manifest["schema"] == TRANSFER_SCHEMA, "transfer_schema")
        public = manifest["public"]; excluded = manifest["excluded_private"]
        need(isinstance(public, dict) and isinstance(excluded, list)
             and all(isinstance(x, str) for x in excluded), "transfer_manifest_shape")
        need(len(excluded) == len(set(excluded)) and all(isinstance(rel, str) and _is_excluded_private(rel) for rel in excluded), "transfer_excluded_private")
        need(not any(_is_excluded_private(rel) for rel in public), "transfer_private_public_digest")
        actual = set()
        for rel, fd in _walk_files(root, _canonical_directory):
            actual.add(rel)
            if rel in excluded: continue
            need(rel in public, "transfer_undeclared_public", rel)
            declared = public[rel]
            need(isinstance(declared, dict) and set(declared) == {"sha256", "bytes"}, "transfer_manifest_shape")
            digest = hashlib.sha256(); size = 0
            per_file_cap = min(_FILE_BYTES_MAX, _diagnostic_cap(rel))
            while True:
                data = os.read(fd, min(1 << 20, per_file_cap + 1 - size))
                if not data: break
                size += len(data)
                need(size <= per_file_cap, "transfer_file_oversize", rel)
                digest.update(data)
            with os.fdopen(os.dup(fd), "rb") as diagnostic:
                _validate_diagnostic(rel, diagnostic, size)
            need(size == declared["bytes"], "transfer_public_length", rel)
            need(digest.hexdigest() == declared["sha256"], "transfer_public_digest", rel)
        need(actual == set(public) | set(excluded), "transfer_membership")
        os.fsync(root)
        return manifest
    except OSError as exc:
        raise Refusal("transfer_io_refused", str(exc)) from None
    finally:
        os.close(root)


def zed_check(dest_dir, context_path):
    """Run the INDEPENDENT checker over the received retained bytes with a
    Zed-admitted expected context.  Returns the checker result dict; a Refusal
    propagates (evidence invalid).  task_success distinguishes evidence validity
    from the pinned workload outcome exactly as the operator ``check`` does.

    REF02: the retained evidence is loaded through the SAME confined, bounded
    loader the operator ``check`` command uses (complete outputs-tree
    membership, entry-count + aggregate-byte bounds before content accumulation,
    descriptor-safe reads) — the transfer check no longer uses unbounded
    ordinary reads or an incomplete enumeration.  The launch/result assertions
    and the report/context are the only inputs read here, each bounded + safe."""
    def _p(*parts):
        return os.path.join(dest_dir, *parts)

    request = retained_evidence.load_wire_json(
        _p(REQUEST_NAME), 1 << 20, REQUEST_NAME)
    need(isinstance(request, dict)
         and isinstance(request.get("launch_assertion_b64"), str)
         and isinstance(request.get("result_assertion_b64"), str),
         "transfer_request_assertions_missing")
    evidence = retained_evidence.load_retained_check_evidence(dest_dir)
    evidence["launch_assertion_b64"] = request["launch_assertion_b64"]
    evidence["result_assertion_b64"] = request["result_assertion_b64"]
    context = retained_evidence.load_wire_json(
        context_path, 1 << 20, "checker_context")
    report_bytes = retained_evidence.read_regular_file(
        _p("report.json"), 1 << 20, "report.json")
    return checker_mod.check(report_bytes, context, evidence)


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="evidence-transfer",
                                 description="Mini->Zed evidence transfer+check")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("package", help="Mini: package an evidence dir")
    p.add_argument("--evidence", required=True)
    p.add_argument("--out", required=True)
    r = sub.add_parser("receive", help="Zed: safely extract + verify manifest")
    r.add_argument("--tar", required=True)
    r.add_argument("--dest", required=True)
    c = sub.add_parser("check", help="Zed: receive + independent checker verdict")
    c.add_argument("--tar", required=True)
    c.add_argument("--dest", required=True)
    c.add_argument("--context", required=True)
    args = ap.parse_args(argv)
    try:
        if args.cmd == "package":
            m = package(args.evidence, args.out)
            print(json.dumps({"packaged": True,
                              "public_files": len(m["public"]),
                              "excluded_private": m["excluded_private"]},
                             sort_keys=True))
            return 0
        if args.cmd == "receive":
            m = receive(args.tar, args.dest)
            print(json.dumps({"received": True,
                              "verified_public_files": len(m["public"])},
                             sort_keys=True))
            return 0
        receive(args.tar, args.dest)
        result = zed_check(args.dest, args.context)
        print(json.dumps({"checked": result["checked"],
                          "task_success": result["task_success"],
                          "workload_outcome": result["workload_outcome"],
                          "verification_level": result["verification_level"]},
                         sort_keys=True))
        return 0 if result["task_success"] else 3
    except Refusal as exc:
        sys.stderr.write("REFUSED %s: %s\n" % (exc.code, exc))
        return 2


if __name__ == "__main__":
    sys.exit(main())
