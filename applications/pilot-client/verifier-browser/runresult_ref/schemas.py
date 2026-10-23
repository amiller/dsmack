"""Bounded schema validation for every protocol document (R02).

Exact key sets; unknown or missing key = refusal; every string/int bounded.
"""
import base64
import binascii
import re

from . import protocol
from .errors import Refusal, need

HEX64_RE = re.compile(r"[0-9a-f]{64}")
SELECTOR_RE = re.compile(r"[a-z][a-z0-9-]{0,62}")

# REF04: per-role attachment byte caps (reject oversized BEFORE reading).
ATTACHMENT_BYTE_CAPS = {
    "manifest": protocol.EXTRACT_SUMMARY_CAP,          # 1 MiB
    "enrollment": 262144,
    "result_image": protocol.RESULT_TEMPLATE_BYTES_MAX,  # 1 GiB
    "runtime_envelope_private": protocol.PT_IMAGE_BYTES_MAX,
}


def is_hex64(value):
    # REF04: fullmatch so a trailing newline ("<64hex>\n") is NOT accepted
    # (re.match + '$' would match before a trailing newline).
    return isinstance(value, str) and bool(HEX64_RE.fullmatch(value))


def need_hex64(value, what):
    need(is_hex64(value), "bad_hex64", what)
    return value


def need_int(value, what, lo=0, hi=2**63 - 1):
    need(isinstance(value, int) and not isinstance(value, bool)
         and lo <= value <= hi, "bad_int", what)
    return value


def need_str(value, what, max_len, pattern=None, allow_empty=False):
    need(isinstance(value, str), "bad_str", what)
    need(allow_empty or value, "empty_str", what)
    need(len(value) <= max_len, "str_too_long", what)
    need("\x00" not in value, "nul_in_str", what)
    if pattern is not None:
        # REF04: full-string match (rejects trailing newlines/whitespace).
        need(bool(re.fullmatch(pattern, value)), "str_pattern", what)
    return value


def need_b64(value, what, max_chars, max_decoded=None, exact_decoded=None):
    need(isinstance(value, str) and len(value) <= max_chars, "bad_b64", what)
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise Refusal("bad_b64", what) from None
    need(base64.b64encode(raw).decode() == value, "noncanonical_b64", what)
    if exact_decoded is not None:
        # REF04: exact decoded length, not an upper bound.
        need(len(raw) == exact_decoded, "b64_bad_length", what)
    elif max_decoded is not None:
        need(len(raw) <= max_decoded, "b64_too_large", what)
    return raw


def need_exact_keys(obj, keys, what):
    need(isinstance(obj, dict), "not_object", what)
    got = set(obj.keys())
    need(got == set(keys), "key_set_mismatch",
         "%s: missing=%s unknown=%s" % (what, sorted(set(keys) - got),
                                        sorted(got - set(keys))))
    return obj


def validate_request(obj):
    """dsmack.runresult-request/2 — bounded, exact keys."""
    need_exact_keys(obj, protocol.REQUEST_KEYS, "request")
    need(type(obj["runresult_request_version"]) is int
         and obj["runresult_request_version"] == protocol.REQUEST_VERSION,
         "bad_request_version")
    need_hex64(obj["manifest_sha256"], "request.manifest_sha256")
    need_str(obj["receipt_selector"], "request.receipt_selector",
             protocol.MAX_SELECTOR_CHARS, SELECTOR_RE.pattern)
    need_str(obj["challenge"], "request.challenge", protocol.MAX_CHALLENGE_CHARS)
    need_b64(obj["key_id_b64"], "request.key_id_b64", protocol.MAX_KEY_ID_B64, exact_decoded=32)
    need_b64(obj["launch_statement_b64"], "request.launch_statement_b64",
             protocol.MAX_STATEMENT_B64)
    need_b64(obj["launch_assertion_b64"], "request.launch_assertion_b64",
             protocol.MAX_ASSERTION_B64)
    need_int(obj["launch_counter"], "request.launch_counter")
    need_b64(obj["envelope_b64"], "request.envelope_b64", protocol.MAX_ENVELOPE_B64)
    need_b64(obj["result_assertion_b64"], "request.result_assertion_b64",
             protocol.MAX_ASSERTION_B64)
    need_int(obj["result_counter"], "request.result_counter")
    need_hex64(obj["result_image_sha256"], "request.result_image_sha256")
    need_int(obj["result_image_bytes"], "request.result_image_bytes", lo=512)
    return obj


def validate_attachment_index(obj):
    """dsmack.runresult-attachments/1 — content-addressed bulk evidence.

    Exactly one entry per required role; the optional private runtime
    envelope entry carries NO digest (excluded transport, R05)."""
    need_exact_keys(obj, {"schema", "entries"}, "attachments")
    need(obj["schema"] == protocol.ATTACHMENT_INDEX_SCHEMA, "bad_attachment_schema")
    entries = obj["entries"]
    need(isinstance(entries, list) and len(entries) <= 8, "bad_attachment_entries")
    seen = {}
    for i, entry in enumerate(entries):
        need(isinstance(entry, dict), "bad_attachment_entry", str(i))
        role = entry.get("role")
        need(role in protocol.ATTACHMENT_ROLES_REQUIRED
             or role in protocol.ATTACHMENT_ROLES_OPTIONAL,
             "unknown_attachment_role", str(role))
        need(role not in seen, "duplicate_attachment_role", str(role))
        if role == "runtime_envelope_private":
            need_exact_keys(entry, protocol.ATTACHMENT_PRIVATE_ENTRY_KEYS,
                            "attachment[%s]" % role)
            need_int(entry["bytes"], "attachment.bytes", lo=1,
                     hi=ATTACHMENT_BYTE_CAPS["runtime_envelope_private"])
        else:
            need_exact_keys(entry, protocol.ATTACHMENT_ENTRY_KEYS,
                            "attachment[%s]" % role)
            need_hex64(entry["sha256"], "attachment.sha256")
            # REF04: per-role byte cap so a 2^62 size is refused up front.
            need_int(entry["bytes"], "attachment.bytes", lo=1,
                     hi=ATTACHMENT_BYTE_CAPS[role])
        seen[role] = entry
    for role in protocol.ATTACHMENT_ROLES_REQUIRED:
        need(role in seen, "missing_attachment_role", role)
    return seen


def validate_envelope_body(obj):
    """run-result-envelope/1 body — exact keys, §5.3 shape."""
    need_exact_keys(obj, protocol.ENVELOPE_KEYS, "envelope")
    need(obj["schema"] == protocol.ENVELOPE_SCHEMA, "bad_envelope_schema")
    launch = need_exact_keys(obj["launch"], protocol.ENVELOPE_LAUNCH_KEYS,
                             "envelope.launch")
    need_hex64(launch["evidence_sha256"], "envelope.launch.evidence_sha256")
    need_hex64(launch["manifest_sha256"], "envelope.launch.manifest_sha256")
    need_str(launch["challenge"], "envelope.launch.challenge",
             protocol.MAX_CHALLENGE_CHARS)
    need_b64(launch["key_id_b64"], "envelope.launch.key_id_b64",
             protocol.MAX_KEY_ID_B64, exact_decoded=32)
    need_int(launch["counter"], "envelope.launch.counter")
    disk = need_exact_keys(obj["result_disk"], protocol.ENVELOPE_RESULT_DISK_KEYS,
                           "envelope.result_disk")
    need(disk["role"] == "vdd", "bad_result_disk_role")
    need_hex64(disk["template_sha256"], "envelope.result_disk.template_sha256")
    need_int(disk["template_bytes"], "envelope.result_disk.template_bytes",
             lo=512, hi=protocol.RESULT_TEMPLATE_BYTES_MAX)
    need_hex64(disk["sha256"], "envelope.result_disk.sha256")
    need_int(disk["bytes"], "envelope.result_disk.bytes", lo=512)
    need(disk["bytes"] == disk["template_bytes"], "result_disk_size_mismatch")
    console = need_exact_keys(obj["console"], protocol.ENVELOPE_CONSOLE_KEYS,
                              "envelope.console")
    need_hex64(console["sha256"], "envelope.console.sha256")
    need_int(console["bytes"], "envelope.console.bytes")
    need(isinstance(console["truncated"], bool), "bad_console_truncated")
    need_int(console["limit_bytes"], "envelope.console.limit_bytes", lo=1)
    need(console["limit_bytes"] == protocol.MAX_CONSOLE_BYTES,
         "bad_console_limit")
    need(console["bytes"] <= console["limit_bytes"] + protocol.CONSOLE_SLACK_BYTES,
         "console_over_limit")
    rti = need_exact_keys(obj["runtime_input"], protocol.ENVELOPE_RUNTIME_INPUT_KEYS,
                          "envelope.runtime_input")
    need(isinstance(rti["present"], bool), "bad_runtime_input_present")
    need_int(rti["max_bytes"], "envelope.runtime_input.max_bytes")
    claim = rti["commitment_claim"]
    if claim is not None:
        need_exact_keys(claim, {"alg", "scope", "inputs_sha256"},
                        "envelope.runtime_input.commitment_claim")
        need_str(claim["alg"], "claim.alg", 128)
        need_hex64(claim["inputs_sha256"], "claim.inputs_sha256")
        need(isinstance(claim["scope"], dict), "bad_claim_scope")
    life = need_exact_keys(obj["lifecycle"], protocol.ENVELOPE_LIFECYCLE_KEYS,
                           "envelope.lifecycle")
    need(type(life["vmm_code"]) is int and life["vmm_code"] == 0, "nonzero_vmm_code")
    need_int(life["run_ms"], "envelope.lifecycle.run_ms")
    need(type(life["backend_abi"]) is int and life["backend_abi"] == 3, "bad_backend_abi")
    need(obj["status"] == "halted", "bad_envelope_status")
    return obj


def validate_enrollment(obj):
    """dsmack.runresult-enrollment/1 — authenticated enrollment provenance
    plus opaque Apple receipt retention (R02)."""
    need_exact_keys(obj, protocol.ENROLLMENT_KEYS, "enrollment")
    need(obj["schema"] == protocol.ENROLLMENT_SCHEMA, "bad_enrollment_schema")
    need(obj["enrollment_class"] in protocol.ENROLLMENT_CLASSES,
         "bad_enrollment_class")
    need_b64(obj["key_id_b64"], "enrollment.key_id_b64", protocol.MAX_KEY_ID_B64, exact_decoded=32)
    pk = need_exact_keys(obj["assertion_public_key"],
                         {"alg", "encoding", "key_b64"},
                         "enrollment.assertion_public_key")
    need(pk["alg"] == "es256", "bad_key_alg")
    need(pk["encoding"] == "x9.62-uncompressed", "bad_key_encoding")
    raw = need_b64(pk["key_b64"], "enrollment.key_b64", 128, 65)
    need(len(raw) == 65 and raw[0] == 4, "bad_p256_point")
    need_str(obj["app_id"], "enrollment.app_id", 256)
    need("." in obj["app_id"], "bad_app_id")
    need_str(obj["team_id"], "enrollment.team_id", 64)
    need(obj["app_id"].startswith(obj["team_id"] + "."), "app_team_mismatch")
    need_str(obj["environment"], "enrollment.environment", 32)
    need(obj["environment"] in ("production", "development"), "bad_environment")
    prov = need_exact_keys(obj["provenance"], protocol.ENROLLMENT_PROVENANCE_KEYS,
                           "enrollment.provenance")
    if obj["enrollment_class"] == protocol.ENROLLMENT_CLASS_PRODUCTION:
        # Production: attestation + opaque Apple receipt are REQUIRED retained
        # evidence; provenance must name the pinned core that verified it.
        need_b64(obj["apple_attestation_b64"], "enrollment.apple_attestation_b64",
                 262144)
        need_b64(obj["apple_receipt_b64"], "enrollment.apple_receipt_b64", 262144)
        need(obj["apple_receipt_status"] == protocol.APPLE_RECEIPT_STATUS,
             "bad_apple_receipt_status")
        need(prov["verified_by_core_sha256"] == protocol.CORE_SHA256,
             "enrollment_core_not_pinned")
        need_int(prov["verified_at_unix_s"], "provenance.verified_at_unix_s", lo=1)
        need_str(prov["attestation_challenge"], "provenance.attestation_challenge",
                 protocol.MAX_CHALLENGE_CHARS)
        need(obj["environment"] == "production", "production_class_environment")
    else:
        # Fixture: Apple members must be EXPLICIT null — a fixture that
        # carries fabricated Apple evidence is refused outright.
        for member in ("apple_attestation_b64", "apple_receipt_b64",
                       "apple_receipt_status"):
            need(obj[member] is None, "fixture_with_apple_evidence", member)
    return obj


def validate_checker_context(obj):
    need_exact_keys(obj, protocol.CHECKER_CONTEXT_KEYS, "checker_context")
    need(obj["schema"] in (protocol.CHECKER_CONTEXT_SCHEMA, "dsmack.runresult-checker-context/3"), "bad_context_schema")
    need(obj["verifier_id"] == protocol.VERIFIER_ID, "bad_context_verifier_id")
    need_str(obj["verifier_version"], "context.verifier_version", 16)
    need_b64(obj["report_verify_key_b64"], "context.report_verify_key_b64", 64, exact_decoded=32)
    need_str(obj["report_key_id"], "context.report_key_id", 128)
    need_hex64(obj["core_sha256"], "context.core_sha256")
    need_hex64(obj["extractor_tool_sha256"], "context.extractor_tool_sha256")
    expected_keys = protocol.CHECKER_EXPECTED_KEYS
    if obj["schema"] == "dsmack.runresult-checker-context/3":
        expected_keys = expected_keys | {"selector_manifests"}
    expected = need_exact_keys(obj["expected"], expected_keys,
                               "context.expected")
    need_str(expected["challenge"], "expected.challenge", protocol.MAX_CHALLENGE_CHARS)
    need_hex64(expected["manifest_sha256"], "expected.manifest_sha256")
    need_str(expected["receipt_selector"], "expected.receipt_selector",
             protocol.MAX_SELECTOR_CHARS, SELECTOR_RE.pattern)
    need_b64(expected["key_id_b64"], "expected.key_id_b64", protocol.MAX_KEY_ID_B64, exact_decoded=32)
    need(expected["enrollment_class"] in protocol.ENROLLMENT_CLASSES,
         "bad_expected_enrollment_class")
    need_str(expected["app_id"], "expected.app_id", 256)
    need_str(expected["team_id"], "expected.team_id", 64)
    need_str(expected["environment"], "expected.environment", 32)
    # REF03: externally pinned expected workload outcome + VM environment.
    need(expected["workload_status"] in protocol.WORKLOAD_STATUSES,
         "bad_expected_workload_status")
    need(isinstance(expected["exit_code"], int)
         and not isinstance(expected["exit_code"], bool),
         "bad_expected_exit_code")
    need_str(expected["receipt_environment"], "expected.receipt_environment", 32)
    from .closure import validate_context
    validate_context(expected["closure_context"])
    need(expected["receipt_selector"] in expected["closure_context"]["selectors"], "closure_expected_selector")
    if obj["schema"] == "dsmack.runresult-checker-context/3":
        manifests = expected["selector_manifests"]
        need(isinstance(manifests, dict) and set(manifests) == set(expected["closure_context"]["selectors"]), "expected_selector_manifests_membership")
        for selector, item in manifests.items():
            need_str(selector, "expected.selector", protocol.MAX_SELECTOR_CHARS, SELECTOR_RE.pattern)
            need_exact_keys(item, {"manifest_sha256", "workload_status", "exit_code", "receipt_environment"}, "expected.selector_manifest")
            need_hex64(item["manifest_sha256"], "expected.selector_manifest.manifest_sha256")
            need(item["workload_status"] in protocol.WORKLOAD_STATUSES, "bad_expected_workload_status")
            need(type(item["exit_code"]) is int, "bad_expected_exit_code")
            need_str(item["receipt_environment"], "expected.selector_manifest.receipt_environment", 32)
        primary = manifests[expected["receipt_selector"]]
        need(all(primary[key] == expected[key] for key in primary), "expected_primary_selector_mismatch")
    return obj


def validate_report_shape(obj):
    """dsmack.runresult-report/3 structural validation (shape only; the
    signature/trust checks live in checker.py)."""
    need_exact_keys(obj, protocol.REPORT_KEYS, "report")
    need(type(obj["runresult_report_version"]) is int
         and obj["runresult_report_version"] == protocol.REPORT_VERSION,
         "bad_report_version")
    verifier = need_exact_keys(obj["verifier"], protocol.REPORT_VERIFIER_KEYS,
                               "report.verifier")
    need_str(verifier["id"], "verifier.id", 64)
    need_str(verifier["version"], "verifier.version", 16)
    need_str(verifier["key_id"], "verifier.key_id", 128)
    context = need_exact_keys(obj["verifier_context"], protocol.REPORT_CONTEXT_KEYS,
                              "report.verifier_context")
    need_hex64(context["core_sha256"], "context.core_sha256")
    need_hex64(context["extractor_tool_sha256"], "context.extractor_tool_sha256")
    need(context["extraction_contract"] == protocol.EXTRACTION_CONTRACT,
         "bad_extraction_contract")
    need_hex64(context["enrollment_sha256"], "context.enrollment_sha256")
    need(obj["verified"] is True, "verified_not_literal_true")
    subject = need_exact_keys(obj["subject"], protocol.REPORT_SUBJECT_KEYS,
                              "report.subject")
    need_hex64(subject["manifest_sha256"], "subject.manifest_sha256")
    need_str(subject["receipt_selector"], "subject.receipt_selector",
             protocol.MAX_SELECTOR_CHARS, SELECTOR_RE.pattern)
    need_str(subject["challenge"], "subject.challenge", protocol.MAX_CHALLENGE_CHARS)
    need_b64(subject["key_id_b64"], "subject.key_id_b64", protocol.MAX_KEY_ID_B64, exact_decoded=32)
    for member in ("launch_evidence_sha256", "envelope_sha256",
                   "pair_evidence_sha256", "result_image_sha256",
                   "console_sha256", "receipt_sha256", "receipt_evidence_sha256", "export_index_sha256"):
        need_hex64(subject[member], "subject." + member)
    need_int(subject["launch_counter"], "subject.launch_counter")
    need_int(subject["result_counter"], "subject.result_counter")
    need(subject["result_counter"] > subject["launch_counter"], "counter_order")
    need_int(subject["result_image_bytes"], "subject.result_image_bytes", lo=512)
    need_int(subject["console_bytes"], "subject.console_bytes")
    need_str(subject["receipt_path"], "subject.receipt_path", 512)
    need_str(subject["receipt_environment"], "subject.receipt_environment", 32)
    need_str(subject["receipt_status"], "subject.receipt_status", 16)
    need(subject["outputs_verified"] is True, "outputs_not_verified")
    need(subject["commitment_status"] in protocol.COMMITMENT_STATUSES,
         "bad_commitment_status")
    need(subject["evidence_class"] in (protocol.EVIDENCE_CLASS_PRODUCTION,
                                       protocol.EVIDENCE_CLASS_FIXTURE),
         "bad_evidence_class")
    apple = need_exact_keys(obj["apple"], protocol.REPORT_APPLE_KEYS, "report.apple")
    need(apple["assertion_counters_authenticated"] is True,
         "counters_not_authenticated")
    need_str(apple["environment"], "apple.environment", 32)
    need_int(apple["verified_at_unix_s"], "apple.verified_at_unix_s")
    sig = need_exact_keys(obj["report_sig"], protocol.REPORT_SIG_KEYS,
                          "report.report_sig")
    need(sig["alg"] == "ed25519", "bad_sig_alg")
    need_str(sig["key_id"], "report_sig.key_id", 128)
    need(sig["key_id"] == verifier["key_id"], "sig_key_id_mismatch")
    need_b64(sig["sig_b64"], "report_sig.sig_b64", 128, exact_decoded=64)
    return obj
