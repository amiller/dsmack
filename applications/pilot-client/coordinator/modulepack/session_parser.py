#!/usr/bin/env python3
"""session_parser.py -- faithful pure-Python port of the `mar hvf-v3` session/3
admission checks in V3Launch.swift (runHvFV3, lines 32-103) and main.swift
(canonical(), read() size caps, challenge() 32-byte rule, keyId read).

WHY A PORT, NOT THE BINARY: the signed `mar` app is Darwin-only
(`#if canImport(Darwin)`) and there is no Swift toolchain on Zed/Linux, so the
actual Swift parser cannot execute here. This module reproduces the EXACT key
set, bounds, canonical-JSON rule and refusal CONDITIONS from the actual current
source so the aux driver and its tests can (a) self-check every generated
session BEFORE it is ever handed to the real app, and (b) reproduce the reviewer
/ FEEDBACK counterexamples read-only. It is a parser mirror, never a substitute
for the real admission core: the real app re-validates every byte. Each refusal
carries a `swift_ref` to the V3Launch.swift line it mirrors so drift is auditable.

The default mode mirrors historical App3. A separately reviewed explicit
scratch_max_bytes=4<<30 mode mirrors the new role-split V3TemplateCapacity
admission in the browser-capacity candidate. Result/private bounds are unchanged.
This optional Python mode is never proof that a selected signed app supports it.

Historical pins taken verbatim from the source:
  V3Launch.swift:32   v3SessionSchema  = "dsmack-general-launcher/session/3"
  V3Launch.swift:37   v3TemplateMaxBytes = 1 << 30            (1 GiB)
  V3Launch.swift:47-55 the exact 20-key set
  V3Launch.swift:98-100 template bytes: >0, %512==0, <= 1 GiB
  V3Launch.swift:103  runtime_seconds in 1...86400
  V2Launch.swift:44   v2PathMaxBytes = 1024
  main.swift:45       canonical = JSONSerialization .sortedKeys,.withoutEscapingSlashes
  main.swift:48-50    session read cap 65536 (read(sessionPath, max: 65536))
  main.swift:109-113  challenge file MUST be exactly 32 bytes
"""
import json

V3_SESSION_SCHEMA = "dsmack-general-launcher/session/3"
V3_TEMPLATE_MAX_BYTES = 1 << 30          # 1 GiB  (V3Launch.swift:37)
V2_PATH_MAX_BYTES = 1024                 # V2Launch.swift:44
SESSION_READ_MAX = 65536                 # main.swift read(sessionPath, max: 65536)
CHALLENGE_BYTES = 32                     # main.swift challenge()

# V3Launch.swift:47-55 -- requireExactKeys over exactly these keys.
SESSION_KEYS = (
    "schema", "policy_path", "image_manifest_path", "checksum_manifest_path",
    "metadata_path", "admission_path", "compose_manifest_path", "profile",
    "workload_disk_path", "workload_sha256", "workload_id", "runtime_seconds",
    "scratch_template_path", "scratch_template_sha256", "scratch_template_bytes",
    "result_template_path", "result_template_sha256", "result_template_bytes",
    "private_input_path", "net_socket_path",
)

# V3Launch.swift:60-62 -- the required absolute-path document keys (NOT the two
# optional vde/NIC keys, which may be the empty string meaning "none").
DOC_PATH_KEYS = (
    "policy_path", "image_manifest_path", "checksum_manifest_path", "metadata_path",
    "admission_path", "compose_manifest_path", "workload_disk_path",
    "scratch_template_path", "result_template_path",
)


class Refusal(Exception):
    """Mirrors a Swift `throw Fail(...)`. `reason` is a stable machine tag; the
    message text echoes the Swift condition; `swift_ref` names the source line."""
    def __init__(self, reason, message, swift_ref=""):
        super().__init__(message)
        self.reason = reason
        self.message = message
        self.swift_ref = swift_ref


def canonical_bytes(obj):
    """Byte-for-byte match for Swift `canonical()` =
    JSONSerialization.data(.sortedKeys, .withoutEscapingSlashes).
    Swift emits compact (no spaces) sorted-key JSON with '/' unescaped. Python's
    json.dumps(sort_keys=True, separators=(',',':'), ensure_ascii=False) is the
    exact same byte stream for ASCII scalar content (all our paths/hex are ASCII;
    '/' is not escaped by json by default)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _printable_ascii(s, max_bytes):
    """main.swift printable()/printableASCII: 0x20..0x7e only, <= max_bytes."""
    b = s.encode("utf-8")
    if len(b) > max_bytes:
        return False
    return all(0x20 <= c <= 0x7e for c in b)


def _is_hex64(s):
    return len(s) == 64 and all(c in "0123456789abcdef" for c in s)


def _strict_int(v, what):
    """Swift strictJSONInt: must be a JSON integer, not a bool, not a float."""
    if isinstance(v, bool) or not isinstance(v, int):
        raise Refusal("not_integer", f"{what}: strict JSON integer required",
                      "V3Launch.swift strictJSONInt")
    return v


def parse_session_bytes(raw, *, scratch_max_bytes=V3_TEMPLATE_MAX_BYTES):
    """Validate the EXACT bytes of a session.json the way `mar hvf-v3` does.
    Returns a normalized dict of the admitted scalars on success; raises Refusal
    on the first failing check, mirroring the Swift fail-closed order."""
    # main.swift read(sessionPath, max: 65536) -- bytes beyond the cap are refused.
    if len(raw) > SESSION_READ_MAX:
        raise Refusal("session_too_large",
                      f"session exceeds {SESSION_READ_MAX} bytes",
                      "main.swift read cap")
    # V3Launch.swift:45 JSONSerialization.jsonObject(with:)
    try:
        obj = json.loads(raw)
    except Exception as e:
        raise Refusal("not_json", f"session is not JSON: {e}", "V3Launch.swift:45")
    if not isinstance(obj, dict):
        raise Refusal("not_object", "session is not a JSON object", "V3Launch.swift:45")
    # V3Launch.swift:46 guard canonical(sessionObject) == sessionBytes
    if canonical_bytes(obj) != raw:
        raise Refusal("not_canonical", "session is not canonical JSON "
                      "(sorted keys, compact, slashes unescaped)", "V3Launch.swift:46")
    # V3Launch.swift:47-55 requireExactKeys
    keys = set(obj.keys())
    if keys != set(SESSION_KEYS):
        missing = sorted(set(SESSION_KEYS) - keys)
        extra = sorted(keys - set(SESSION_KEYS))
        raise Refusal("exact_keys",
                      f"session keys mismatch (missing={missing} extra={extra})",
                      "V3Launch.swift:47")
    # V3Launch.swift:56-58 schema
    if not isinstance(obj["schema"], str) or not obj["schema"]:
        raise Refusal("schema_empty", "session.schema: non-empty string required",
                      "V3Launch.swift:56")
    if obj["schema"] != V3_SESSION_SCHEMA:
        raise Refusal("schema_mismatch",
                      f"session schema != {V3_SESSION_SCHEMA}", "V3Launch.swift:56")
    # V3Launch.swift:60-68 required absolute printable-ASCII doc paths
    for k in DOC_PATH_KEYS:
        p = obj[k]
        if not isinstance(p, str) or not p:
            raise Refusal("path_empty", f"session.{k}: non-empty string required",
                          "V3Launch.swift:63")
        if not _printable_ascii(p, V2_PATH_MAX_BYTES) or not p.startswith("/"):
            raise Refusal("path_bad",
                          f"session.{k}: absolute printable-ASCII path required "
                          f"(<= {V2_PATH_MAX_BYTES} bytes)", "V3Launch.swift:64")
    # V3Launch.swift:72-81 optional vde + NIC: key REQUIRED, empty = none.
    def optional_path(k):
        p = obj[k]
        if not isinstance(p, str):
            raise Refusal("opt_path_type",
                          f"session.{k}: string required (empty = none)",
                          "V3Launch.swift:467")
        if p == "":
            return None
        if not _printable_ascii(p, V2_PATH_MAX_BYTES) or not p.startswith("/"):
            raise Refusal("opt_path_bad",
                          f"session.{k}: absolute printable-ASCII path required "
                          f"(or empty for none)", "V3Launch.swift:75")
        return p
    private_input_path = optional_path("private_input_path")
    net_socket_path = optional_path("net_socket_path")
    # V3Launch.swift:83-84 profile
    profile = obj["profile"]
    if not isinstance(profile, str) or not profile:
        raise Refusal("profile_empty", "session.profile: non-empty string required",
                      "V3Launch.swift:83")
    if not _printable_ascii(profile, 128):
        raise Refusal("profile_bad", "session.profile: printable ASCII <=128 required",
                      "V3Launch.swift:84")
    # V3Launch.swift:85-88 workload sha + id
    workload_sha = obj["workload_sha256"]
    if not isinstance(workload_sha, str) or not _is_hex64(workload_sha):
        raise Refusal("workload_sha_bad",
                      "session.workload_sha256: lowercase hex sha256 required",
                      "V3Launch.swift:86")
    workload_id = obj["workload_id"]
    if not isinstance(workload_id, str) or not workload_id \
            or not _printable_ascii(workload_id, 128):
        raise Refusal("workload_id_bad",
                      "session.workload_id: printable ASCII <=128 required",
                      "V3Launch.swift:88")
    # V3Launch.swift:89-93 template shas
    for k in ("scratch_template_sha256", "result_template_sha256"):
        v = obj[k]
        if not isinstance(v, str) or not _is_hex64(v):
            raise Refusal("template_sha_bad",
                          f"session.{k}: lowercase hex sha256 required",
                          "V3Launch.swift:91")
    # V3Launch.swift:94-101 template bytes: >0, %512==0, <= 1 GiB
    scratch_bytes = _strict_int(obj["scratch_template_bytes"], "session.scratch_template_bytes")
    result_bytes = _strict_int(obj["result_template_bytes"], "session.result_template_bytes")
    # Default preserves the historical app3 cap. Only a separately reviewed
    # selected app/profile may ask this mirror to admit the new 4-GiB scratch.
    if type(scratch_max_bytes) is not int or scratch_max_bytes not in (1 << 30, 4 << 30):
        raise Refusal("scratch_cap_bad", "unqualified scratch parser cap")
    for name, nb, cap in (("scratch_template_bytes", scratch_bytes, scratch_max_bytes),
                          ("result_template_bytes", result_bytes, V3_TEMPLATE_MAX_BYTES)):
        if not (nb > 0 and nb % 512 == 0 and nb <= cap):
            raise Refusal("template_bytes_bad",
                          f"session.{name}={nb}: must be a positive 512-multiple "
                          f"<= {cap} (selected role-specific cap)",
                          "V3Launch.swift:98")
    # V3Launch.swift:102-103 runtime_seconds 1..86400
    runtime = _strict_int(obj["runtime_seconds"], "session.runtime_seconds")
    if not (1 <= runtime <= 86400):
        raise Refusal("runtime_bad", "session.runtime_seconds: 1..86400 required",
                      "V3Launch.swift:103")
    return {
        "schema": obj["schema"],
        "profile": profile,
        "workload_sha256": workload_sha,
        "workload_id": workload_id,
        "scratch_template_bytes": scratch_bytes,
        "result_template_bytes": result_bytes,
        "runtime_seconds": runtime,
        "private_input_present": private_input_path is not None,
        "net_present": net_socket_path is not None,
        "net_socket_path": net_socket_path,
        "private_input_path": private_input_path,
        "doc_paths": {k: obj[k] for k in DOC_PATH_KEYS},
    }


def parse_session_file(path):
    with open(path, "rb") as fh:
        raw = fh.read(SESSION_READ_MAX + 1)
    return parse_session_bytes(raw)


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        sys.stderr.write("usage: session_parser.py <session.json>\n")
        sys.exit(2)
    try:
        res = parse_session_file(sys.argv[1])
    except Refusal as r:
        sys.stderr.write(json.dumps({"admitted": False, "reason": r.reason,
                                     "message": r.message, "swift_ref": r.swift_ref}) + "\n")
        sys.exit(2)
    print(json.dumps({"admitted": True, "session": res}, sort_keys=True, indent=2))
    sys.exit(0)
