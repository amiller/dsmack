"""Bounded, descriptor-relative loader for retained run evidence used by operator ``check``."""
import hashlib
import errno
import json
import os
import stat as stat_module

from . import protocol, schemas
from .errors import Refusal, need
from .frozen import core, load_json_bytes, ContractError

# aggregate / count bounds (mirror the extractor's confined output budget).
OUTPUT_ENTRY_COUNT_MAX = protocol.EXTRACT_FILE_COUNT_MAX        # 256
OUTPUT_AGGREGATE_BYTES_MAX = protocol.EXTRACT_TOTAL_BYTES_MAX   # 64 MiB
PER_OUTPUT_FILE_BYTES_MAX = protocol.EXTRACT_TOTAL_BYTES_MAX    # 64 MiB

# per-document byte caps
MAX_ENROLLMENT_JSON_BYTES = schemas.ATTACHMENT_BYTE_CAPS["enrollment"]
MAX_PRIVATE_ENVELOPE_BYTES = schemas.ATTACHMENT_BYTE_CAPS["runtime_envelope_private"]
MAX_MANIFEST_BYTES = schemas.ATTACHMENT_BYTE_CAPS["manifest"]
MAX_RECEIPT_JSON_BYTES = protocol.EXTRACT_RECEIPT_CAP

_OUTPUT_STREAM_NAMES = ("stdout", "stderr")

# canonical artifact segment name
_ARTIFACT_SEGMENT_OK = lambda n: (  # noqa: E731
    bool(n) and n not in (".", "..") and "/" not in n and len(n) <= 128
    and all(c.isalnum() or c in "._-" for c in n))


# ---------------------------------------------------------------------------
# descriptor-safe bounded reads
# ---------------------------------------------------------------------------
def read_regular_file(path, cap, what):
    """Descriptor-safe bounded read by PATHNAME (used by the transfer/adapter
    for request/report/assertion files that live OUTSIDE the evidence bundle):
    O_NOFOLLOW|O_NONBLOCK, fstat regular-file admission BEFORE any blocking
    read, at most ``cap`` bytes."""
    fd = _open_leaf_nofollow(None, path, what)
    return _read_fd(fd, cap, what)


def load_wire_json(path, cap, what):
    raw = read_regular_file(path, cap, what)
    try:
        return core.unique_json(raw.decode("utf-8"))
    except core.Reject as exc:
        raise Refusal("wire_json_invalid", "%s: %s" % (what, exc)) from exc
    except UnicodeDecodeError:
        raise Refusal("wire_json_invalid", "%s: not utf-8" % what) from None


def _open_leaf_nofollow(dir_fd, name, what):
    """Open ``name`` (relative to ``dir_fd`` when given, else by pathname) for
    reading with O_NOFOLLOW|O_NONBLOCK and return the fd (symlink -> ELOOP and a
    writer-less FIFO -> ENXIO are refused as non-regular, never followed or
    blocked on)."""
    try:
        return os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                       dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENXIO):
            raise Refusal("input_not_regular_file", what) from None
        raise Refusal("input_open_failed", "%s: %s" % (what, exc.strerror)) \
            from None


def _read_fd(fd, cap, what):
    try:
        st = os.fstat(fd)
        need(stat_module.S_ISREG(st.st_mode), "input_not_regular_file", what)
        data = b""
        want = cap + 1
        while len(data) < want:
            try:
                chunk = os.read(fd, min(1 << 20, want - len(data)))
            except BlockingIOError:
                raise Refusal("input_would_block", what) from None
            if not chunk:
                break
            data += chunk
        need(len(data) <= cap, "input_too_large", what)
    finally:
        os.close(fd)
    return data


def _read_doc_at(root_fd, name, cap, what):
    """Descriptor-relative bounded read of a top-level evidence DOCUMENT,
    O_NOFOLLOW relative to the admitted evidence-directory descriptor."""
    return _read_fd(_open_leaf_nofollow(root_fd, name, what), cap, what)


def _read_output_content(dir_fd, name, cap, what):
    """Descriptor-relative bounded read of an ADMITTED delivered output file
    (phase 2 only — never reached for a pre-admission refusal).  Distinct name
    so instrumentation can prove zero output-content reads occur before the
    membership/shape/count admission."""
    return _read_fd(_open_leaf_nofollow(dir_fd, name, what), cap, what)


def _open_dir_at(parent_fd, name, what):
    """Open ``name`` as a directory relative to ``parent_fd`` with per-component
    symlink refusal (O_NOFOLLOW|O_DIRECTORY|dir_fd).  Returns the dir fd, or None
    when genuinely absent (ENOENT).  A symlink in ``name``'s place
    (ELOOP) refuses — even the top-level ``outputs`` directory, so a symlinked
    ``outputs`` can never be followed outside the admitted bundle."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        return os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            return None
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise Refusal("output_entry_not_regular_file", what) from None
        raise Refusal("output_dir_unreadable",
                      "%s: %s" % (what, exc.strerror)) from None


# ---------------------------------------------------------------------------
# receipt-declared membership (parsed + type-checked BEFORE any content read)
# ---------------------------------------------------------------------------
def _declared_outputs(receipt_bytes):
    """Parse the retained receipt with the SAME strict, bounded,
    duplicate-key-rejecting parser ``checker.check`` uses and derive the
    membership facts the output admission needs BEFORE any delivered content is
    read: which byte streams the receipt declares (non-null), which artifact
    NAMES it declares, and which it declares MISSING.

    A malformed receipt, or a ``missing``/``artifacts`` of the wrong type (or a
    member of the wrong type), is a structured REFUSAL here — never an uncaught
    TypeError (which previously escaped the loader after output content had
    already been read) nor a silent drop.  This is a PRE-ADMISSION gate only;
    ``checker.check`` independently re-validates the full receipt shape."""
    try:
        receipt = load_json_bytes(receipt_bytes, "receipt.json",
                                  max_bytes=MAX_RECEIPT_JSON_BYTES)
    except ContractError as exc:
        raise Refusal("receipt_json_invalid", str(exc)) from exc
    outputs = receipt.get("outputs") if isinstance(receipt, dict) else None
    if not isinstance(outputs, dict):
        # No well-formed outputs object -> the receipt declares no delivered
        # output; any physically delivered file is therefore undeclared and is
        # refused before its content is read (the checker refuses the malformed
        # receipt independently).
        return {"streams": {n: False for n in _OUTPUT_STREAM_NAMES},
                "artifact_names": frozenset(), "missing": frozenset()}
    streams = {n: (outputs.get(n) is not None) for n in _OUTPUT_STREAM_NAMES}
    raw_missing = outputs.get("missing")
    if raw_missing is None:
        raw_missing = []
    need(isinstance(raw_missing, list),
         "receipt_outputs_missing_not_list", type(raw_missing).__name__)
    for m in raw_missing:
        need(isinstance(m, str),
             "receipt_outputs_missing_member_not_str", type(m).__name__)
    missing = frozenset(raw_missing)
    raw_artifacts = outputs.get("artifacts")
    if raw_artifacts is None:
        raw_artifacts = []
    need(isinstance(raw_artifacts, list),
         "receipt_outputs_artifacts_not_list", type(raw_artifacts).__name__)
    names = set()
    for artifact in raw_artifacts:
        need(isinstance(artifact, dict),
             "receipt_outputs_artifact_not_object", type(artifact).__name__)
        need(isinstance(artifact.get("name"), str),
             "receipt_outputs_artifact_name_not_str",
             type(artifact.get("name")).__name__)
        names.add(artifact["name"])
    return {"streams": streams, "artifact_names": frozenset(names),
            "missing": missing}


# ---------------------------------------------------------------------------
# the ONE descriptor-relative outputs loader (two-pass: admit, then read)
# ---------------------------------------------------------------------------
def _enumerate_outputs(root_fd, declared):
    return _load_outputs(root_fd, declared)


def _load_outputs(root_fd, declared, *, preflight=False, budget=None):
    """Descriptor-relative, two-pass outputs loader.  Returns
    ``{label: (bytes, None)}`` for the admitted members.

    Phase 1 (NO content read): open ``outputs`` O_NOFOLLOW relative to the
    admitted evidence descriptor; enumerate the COMPLETE subtree validating
    directory shape (only ``streams``/``artifacts`` dirs), file membership (only
    ``stdout``/``stderr`` regular files under ``streams``; valid-segment regular
    files under ``artifacts``), entry COUNT (refused during enumeration, before
    any read) and the receipt-declared membership (a file for a null stream, an
    undeclared artifact, a file for a declared-missing artifact — each refused
    before any read).  A pre-read aggregate stat-size bound is applied too.

    Phase 2: read ONLY the admitted members' content, each capped by the
    REMAINING aggregate budget, subtracting the ACTUAL bytes read (so a file
    that grew past its stat size still cannot exceed the aggregate)."""
    outputs = {}
    open_subfds = []
    outputs_fd = _open_dir_at(root_fd, "outputs", "outputs")
    if outputs_fd is None:
        need(not _expected_output_labels(declared), "output_membership_incomplete")
        return (0, 0) if preflight else outputs
    try:
        # --- phase 1a: outputs/ may contain ONLY streams/ and artifacts/ dirs.
        top = _bounded_names(outputs_fd, OUTPUT_ENTRY_COUNT_MAX)
        for name in top:
            entry_st = os.lstat(name, dir_fd=outputs_fd)
            need(name in ("streams", "artifacts")
                 and stat_module.S_ISDIR(entry_st.st_mode),
                 "unexpected_output_entry", name)
        # --- phase 1b: enumerate stream + artifact MEMBERS (shape + count),
        #     recording stat sizes; NO content read yet.
        members = []        # (label, sub, name, stat_size)
        count = 0
        for sub, allowed in (("streams", _OUTPUT_STREAM_NAMES),
                             ("artifacts", None)):
            sub_fd = _open_dir_at(outputs_fd, sub, "outputs/" + sub)
            if sub_fd is None:
                continue
            try:
                for name in _bounded_names(sub_fd, OUTPUT_ENTRY_COUNT_MAX):
                    rel = "%s/%s" % (sub, name)
                    entry_st = os.lstat(name, dir_fd=sub_fd)
                    need(stat_module.S_ISREG(entry_st.st_mode),
                         "output_entry_not_regular_file", rel)
                    if allowed is not None:
                        need(name in allowed, "unexpected_output_entry", rel)
                        label = "stream:" + name
                    else:
                        need(_ARTIFACT_SEGMENT_OK(name),
                             "unexpected_output_entry", rel)
                        label = "artifact:" + name
                    # COUNT admitted during enumeration — refused before any
                    # content read (the earlier loader read-then-counted).
                    count += 1
                    need(count <= OUTPUT_ENTRY_COUNT_MAX, "output_entry_count",
                         "%d > %d" % (count, OUTPUT_ENTRY_COUNT_MAX))
                    members.append((label, sub_fd, name, entry_st.st_size))
            except BaseException:
                os.close(sub_fd)
                raise
            else:
                # keep sub_fd open for phase-2 reads (closed below).
                open_subfds.append(sub_fd)
        # --- phase 1c: receipt-declared membership pre-check (mirrors the
        #     checker's classification), refusing forbidden deliveries BEFORE
        #     any content read.  Nothing is silently dropped.
        for label, _sub_fd, name, _sz in members:
            if label.startswith("stream:"):
                if not declared["streams"].get(name):
                    raise Refusal("null_stream_delivered", name)
            else:
                art = label[len("artifact:"):]
                if art not in declared["artifact_names"]:
                    raise Refusal("unexpected_delivered_output",
                                  "artifact:" + art)
                if art in declared["missing"]:
                    raise Refusal("missing_artifact_delivered",
                                  "artifact:" + art)
        need({label for label, _fd, _name, _size in members}
             == _expected_output_labels(declared), "output_membership_incomplete")
        # --- phase 1d: pre-read aggregate stat-size bound.
        stat_total = sum(sz for _l, _fd, _n, sz in members)
        need(stat_total <= OUTPUT_AGGREGATE_BYTES_MAX, "output_aggregate_bytes",
             "%d > %d (stat)" % (stat_total, OUTPUT_AGGREGATE_BYTES_MAX))
        # --- phase 2: read ONLY admitted members; decreasing actual-byte budget.
        if preflight:
            return count, stat_total
        remaining = OUTPUT_AGGREGATE_BYTES_MAX if budget is None else budget[0]
        for label, sub_fd, name, _sz in members:
            cap = min(PER_OUTPUT_FILE_BYTES_MAX, remaining)
            data = _read_output_content(sub_fd, name, cap, "outputs/%s"
                                        % label.replace(":", "/", 1))
            need(len(data) <= remaining, "output_aggregate_bytes",
                 "%d > remaining %d" % (len(data), remaining))
            remaining -= len(data)
            outputs[label] = (data, None)
        if budget is not None:
            budget[0] = remaining
    finally:
        while open_subfds:
            os.close(open_subfds.pop())
        os.close(outputs_fd)
    return outputs


def load_retained_check_evidence(evidence_dir):
    """Load the retained evidence bundle for ``checker.check`` from disk through
    the single confined, bounded, descriptor-relative loader.  Returns the
    ``evidence`` dict with ``launch_assertion_b64``/``result_assertion_b64`` set
    to None — the caller supplies those from its independently admitted context
    (operator ``check`` args; transfer request.json)."""
    # Open the evidence directory as the trust-boundary ROOT descriptor once;
    # every child is opened O_NOFOLLOW relative to it.
    try:
        root_fd = os.open(evidence_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise Refusal("evidence_dir_unreadable",
                      "%s: %s" % (evidence_dir, exc.strerror)) from None
    try:
        rst = os.fstat(root_fd)
        need(stat_module.S_ISDIR(rst.st_mode), "evidence_dir_not_directory",
             evidence_dir)

        # 1) RECEIPT metadata parsed + type-checked FIRST (before any delivered
        #    content is read), so membership/budget are decided with the receipt
        #    in hand.
        receipt_bytes = _read_doc_at(
            root_fd, "receipt.json", MAX_RECEIPT_JSON_BYTES, "receipt.json")
        declared = _declared_outputs(receipt_bytes)

        # 2) COMPLETE outputs-tree: descriptor-relative enumeration + membership
        #    + count admitted BEFORE any content read, then bounded reads with a
        #    decreasing aggregate budget.
        # Pre-admit every selector before ANY delivered output content read.
        selector_items, selector_fds = _admit_selector_sets(root_fd)
        try:
            count, total = _load_outputs(root_fd, declared, preflight=True)
            for selector, fd, item, item_declared in selector_items:
                n, size = _load_outputs(fd, item_declared, preflight=True)
                count += n; total += size
            need(count <= OUTPUT_ENTRY_COUNT_MAX, "output_entry_count")
            need(total <= OUTPUT_AGGREGATE_BYTES_MAX, "output_aggregate_bytes")
            budget = [OUTPUT_AGGREGATE_BYTES_MAX]
            outputs = (_load_outputs(root_fd, declared, budget=budget) if selector_items
                       else _enumerate_outputs(root_fd, declared))
            selector_evidence = {}
            for selector, fd, item, item_declared in selector_items:
                item["outputs"] = _load_outputs(fd, item_declared, budget=budget)
                selector_evidence[selector] = item
        finally:
            for fd in selector_fds:
                os.close(fd)

        # Hash the image ONLY through the admitted directory descriptor.
        # Carry digest + actual length, never a pathname for later resolution.
        image_digest, image_total = _hash_image_at(root_fd)
        evidence = {
            "manifest_bytes": _read_doc_at(
                root_fd, "manifest", MAX_MANIFEST_BYTES, "manifest"),
            "statement_bytes": _read_doc_at(
                root_fd, "statement.json", protocol.MAX_STATEMENT_B64,
                "statement.json"),
            "envelope_bytes": _read_doc_at(
                root_fd, "result-envelope.json", protocol.MAX_ENVELOPE_B64,
                "result-envelope.json"),
            "enrollment_obj": _load_wire_json_at(
                root_fd, "enrollment.json", MAX_ENROLLMENT_JSON_BYTES,
                "enrollment.json"),
            "launch_assertion_b64": None,   # supplied by the independent context
            "result_assertion_b64": None,
            "receipt_bytes": receipt_bytes,
            "export_index_bytes": _read_doc_at(
                root_fd, "export-index.json", protocol.EXTRACT_RECEIPT_CAP,
                "export-index.json"),
            "console_bytes": _read_doc_at(
                root_fd, "console", protocol.MAX_CONSOLE_BYTES, "console"),
            "outputs": outputs,
            "result_image_sha256_precomputed": image_digest,
            "result_image_bytes_precomputed": image_total,
        }
        if selector_items:
            evidence["selector_evidence"] = selector_evidence
        if _exists_at(root_fd, "runtime_envelope_private"):
            evidence["private_envelope_bytes"] = _read_doc_at(
                root_fd, "runtime_envelope_private", MAX_PRIVATE_ENVELOPE_BYTES,
                "runtime_envelope_private")
    finally:
        os.close(root_fd)
    return evidence



def _admit_selector_sets(root_fd):
    """Versioned auxiliary package, confined descriptors and full metadata first.

    Keep all admitted selector descriptors open through content reads. Exact
    membership includes empty directories and special entries; unknown members
    cannot silently bypass admission. No content is read until all sets pass.
    """
    fds = []
    try:
        if not _exists_at(root_fd, "retained-selectors.json"):
            need(not _exists_at(root_fd, "selectors"), "retained_selectors_version_absent")
            return [], fds
        index = _load_wire_json_at(root_fd, "retained-selectors.json", 8192, "retained-selectors.json")
        need(isinstance(index, dict) and set(index) == {"schema", "selectors"}, "retained_selectors_keys")
        need(index["schema"] == "dsmack-retained-selectors/1", "retained_selectors_schema")
        names = index["selectors"]
        from .closure import validate_context
        validate_context(dict(schema="dsmack-result-closure-context/1", attempt_id="0" * 32, selectors=names))
        for name in names:
            need(schemas.SELECTOR_RE.fullmatch(name) is not None, "retained_selector_name")
        parent = _open_dir_at(root_fd, "selectors", "selectors")
        need(parent is not None, "retained_selectors_absent")
        fds.append(parent)
        need(_bounded_names(parent, 32) == names, "retained_selectors_membership")
        items = []
        for selector in names:
            fd = _open_dir_at(parent, selector, selector)
            need(fd is not None, "retained_selector_absent")
            fds.append(fd)
            members = set(_bounded_names(fd, 5))
            required = {"manifest", "receipt.json", "export-index.json", "outputs"}
            need(members in (required, required | {"runtime_envelope_private"}), "retained_selector_membership", selector)
            item = {
                "manifest_bytes": _read_doc_at(fd, "manifest", MAX_MANIFEST_BYTES, "selector manifest"),
                "receipt_bytes": _read_doc_at(fd, "receipt.json", MAX_RECEIPT_JSON_BYTES, "selector receipt"),
                "export_index_bytes": _read_doc_at(fd, "export-index.json", protocol.EXTRACT_RECEIPT_CAP, "selector index"),
            }
            declared = _declared_outputs(item["receipt_bytes"])
            if "runtime_envelope_private" in members:
                item["private_envelope_bytes"] = _read_doc_at(fd, "runtime_envelope_private", MAX_PRIVATE_ENVELOPE_BYTES, "selector private envelope")
            items.append((selector, fd, item, declared))
        return items, fds
    except BaseException:
        for fd in fds:
            os.close(fd)
        raise

def _load_wire_json_at(root_fd, name, cap, what):
    raw = _read_doc_at(root_fd, name, cap, what)
    try:
        return core.unique_json(raw.decode("utf-8"))
    except core.Reject as exc:
        raise Refusal("wire_json_invalid", "%s: %s" % (what, exc)) from exc
    except UnicodeDecodeError:
        raise Refusal("wire_json_invalid", "%s: not utf-8" % what) from None


def _require_regular_at(root_fd, name, missing_code):
    """Require ``name`` to be present as a REGULAR file relative to the admitted
    evidence descriptor (a symlink is refused, never followed)."""
    try:
        st = os.lstat(name, dir_fd=root_fd)
    except OSError as exc:
        if exc.errno in (errno.ENOENT, errno.ENOTDIR):
            raise Refusal(missing_code) from None
        raise Refusal("input_open_failed", "%s: %s" % (name, exc.strerror)) \
            from None
    need(stat_module.S_ISREG(st.st_mode), "input_not_regular_file", name)


def _exists_at(root_fd, name):
    try:
        os.lstat(name, dir_fd=root_fd)
        return True
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            return False
        raise Refusal("input_open_failed", "%s: %s" % (name, exc.strerror)) from None


def _hash_image_at(root_fd):
    fd = _open_leaf_nofollow(root_fd, "result_image", "result_image")
    try:
        st = os.fstat(fd)
        need(stat_module.S_ISREG(st.st_mode), "input_not_regular_file", "result_image")
        cap = protocol.RESULT_TEMPLATE_BYTES_MAX
        need(st.st_size <= cap, "input_too_large", "result_image")
        digest = hashlib.sha256()
        total = 0
        while True:
            data = os.read(fd, min(1 << 20, cap + 1 - total))
            if not data:
                break
            total += len(data)
            need(total <= cap, "input_too_large", "result_image")
            digest.update(data)
        return digest.hexdigest(), total
    finally:
        os.close(fd)


def _bounded_names(fd, cap):
    names = []
    with os.scandir(fd) as entries:
        for entry in entries:
            names.append(entry.name)
            need(len(names) <= cap, "output_entry_count", str(cap))
    return sorted(names)


def _expected_output_labels(declared):
    return ({"stream:" + name for name, present in declared["streams"].items()
             if present}
            | {"artifact:" + name for name in declared["artifact_names"]
               if name not in declared["missing"]})
