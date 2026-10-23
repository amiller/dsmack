"""runresult independent checker /2 and auxiliary multi-selector context /3 — the relying party's own validation.

The checker trusts ONLY its externally pinned context (verifier identity,
version, report-signing key, core and extractor identities) plus its OWN
expected request (challenge it issued, manifest digest it submitted,
enrolled key it provisioned, selector, app/team/environment policy and
enrollment class).  A report signature alone, a self-declared verifier
identity, or any caller-supplied digest is never sufficient.

From the retained evidence package the checker RECONSTRUCTS every bound
digest — L from statement bytes, E from envelope bytes, M from manifest
bytes, D from the result image, receipt/stream/artifact digests from the
delivered bytes, pair_evidence_sha256 and enrollment_sha256 from retained
assertions + enrollment provenance — and refuses on ANY disagreement with
the report subject or with its expected context.  Authentic reports for a
DIFFERENT request (other challenge/manifest/key/selector/policy) are
refused by the expected-context comparison, not merely by signature
checking.  Report signature verification uses the frozen pure-Python
ed25519 (independent of the verifier's signer).
"""
import base64
import errno
import hashlib
import json
import os
import stat

from . import protocol, schemas, statement as statement_mod
from .errors import Refusal, need
from .frozen import (canonical_bytes, execution_evidence_digest, frozen_ed25519,
                     load_json_bytes, report_body, validate_receipt_bytes, ContractError)


def _hash_regular_file_streaming(path, cap, what):
    """Descriptor-safe, nonblocking, bounded streaming hash of a retained
    regular file (OPCLI04, merged from the operator lane).  The path is opened
    ONCE O_NOFOLLOW|O_NONBLOCK — a symlink or writer-less FIFO is refused, never
    followed or blocked on — fstat-admitted as a regular file BEFORE any
    blocking read, and hashed on that descriptor (no TOCTOU reopen).  At most
    ``cap`` bytes are consumed; a larger file is refused."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENXIO):
            raise Refusal("image_not_regular_file", what) from None
        raise Refusal("image_open_failed", "%s: %s" % (what, exc.strerror)) \
            from None
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode), "image_not_regular_file", what)
        digest = hashlib.sha256()
        total = 0
        while total <= cap:
            try:
                chunk = os.read(fd, min(1 << 20, cap + 1 - total))
            except BlockingIOError:
                raise Refusal("image_would_block", what) from None
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
        need(total <= cap, "image_too_large", what)
    finally:
        os.close(fd)
    return digest.hexdigest(), total


def _check_delivered_outputs(receipt, evidence):
    """Validate exact delivered membership and every byte for one selector."""
    outputs = receipt["outputs"]
    missing = set(outputs.get("missing") or [])
    delivered = dict(evidence["outputs"])
    consumed = set()
    for stream in ("stdout", "stderr"):
        declared = outputs.get(stream)
        label = "stream:" + stream
        if declared is None:
            need(label not in delivered, "null_stream_delivered", stream)
            continue
        need(label in delivered, "stream_not_delivered", stream)
        data, _ = delivered[label]
        need(len(data) == declared["bytes"], "stream_length", stream)
        need(hashlib.sha256(data).hexdigest() == declared["sha256"],
             "stream_digest", stream)
        consumed.add(label)
    for artifact in outputs.get("artifacts") or []:
        label = "artifact:" + artifact["name"]
        if artifact["name"] in missing:
            need(label not in delivered, "missing_artifact_delivered", label)
            continue
        need(label in delivered, "artifact_not_delivered", label)
        data, _ = delivered[label]
        need(len(data) == artifact["bytes"], "artifact_length", label)
        need(hashlib.sha256(data).hexdigest() == artifact["sha256"],
             "artifact_digest", label)
        consumed.add(label)
    unexpected = sorted(set(delivered) - consumed)
    need(not unexpected, "unexpected_delivered_output", ",".join(unexpected))



def check(report_bytes, context_obj, evidence, *, allow_reduced=False):
    """evidence: dict with retained bytes —
       manifest_bytes, statement_bytes, envelope_bytes, enrollment_obj,
       launch_assertion_b64, result_assertion_b64, receipt_bytes,
       outputs: {label: (bytes, declared)}, console_bytes (REQUIRED for a FULL
       verdict — REF03: the checker recomputes the console digest/length from
       retained bytes rather than trusting the envelope copy),
       result_image_path and/or result_image_sha256_precomputed (REF03: a FULL
       verdict now REQUIRES image evidence; the documented precomputed digest
       is honoured when present).

    Context /3 additionally requires selector_evidence: a mapping for EXACTLY
    closure_context.selectors, each containing manifest_bytes, receipt_bytes,
    export_index_bytes, outputs and optional private_envelope_bytes. Each own
    manifest/outcome/environment is independently pinned in selector_manifests;
    authenticated console closure binds every receipt and index. The primary
    selector remains bound to the signed report and top-level retained bytes.

    REF03: a FULL verdict requires the result image (path or caller-computed
    precomputed digest) AND retained console bytes.  Without image evidence the
    checker REFUSES unless allow_reduced=True, in which case it returns an
    explicitly labelled verification_level='reduced-no-image' verdict — never a
    silent full-check verdict with the image omitted.  When the context's
    expected block pins workload_status / exit_code / receipt_environment, the
    checker enforces those EXTERNAL expectations against the validated
    receipt."""
    context = schemas.validate_checker_context(context_obj)
    report = load_json_bytes(report_bytes, max_bytes=protocol.MAX_REQUEST_BYTES)
    schemas.validate_report_shape(report)

    # ---- pinned verifier identity + signature ----
    need(report["verifier"]["id"] == context["verifier_id"],
         "verifier_id_mismatch")
    need(report["verifier"]["version"] == context["verifier_version"],
         "verifier_version_mismatch")
    need(report["verifier"]["key_id"] == context["report_key_id"],
         "verifier_key_id_mismatch")
    need(report["report_sig"]["key_id"] == context["report_key_id"],
         "sig_key_id_mismatch")
    public_key = base64.b64decode(context["report_verify_key_b64"])
    signature = base64.b64decode(report["report_sig"]["sig_b64"])
    need(frozen_ed25519.verify(public_key, signature, report_body(report)),
         "report_signature_invalid")
    need(report["verifier_context"]["core_sha256"] == context["core_sha256"],
         "core_identity_mismatch")
    need(report["verifier_context"]["extractor_tool_sha256"]
         == context["extractor_tool_sha256"], "extractor_identity_mismatch")

    # ---- the relying party's OWN expected request ----
    subject = report["subject"]
    expected = context["expected"]
    need(subject["challenge"] == expected["challenge"],
         "expected_challenge_mismatch")
    need(subject["manifest_sha256"] == expected["manifest_sha256"],
         "expected_manifest_mismatch")
    need(subject["receipt_selector"] == expected["receipt_selector"],
         "expected_selector_mismatch")
    need(subject["key_id_b64"] == expected["key_id_b64"],
         "expected_key_mismatch")

    enrollment = evidence["enrollment_obj"]
    schemas.validate_enrollment(enrollment)
    need(enrollment["enrollment_class"] == expected["enrollment_class"],
         "expected_enrollment_class_mismatch")
    need(enrollment["app_id"] == expected["app_id"], "expected_app_mismatch")
    need(enrollment["team_id"] == expected["team_id"], "expected_team_mismatch")
    need(enrollment["environment"] == expected["environment"],
         "expected_environment_mismatch")
    need(enrollment["key_id_b64"] == expected["key_id_b64"],
         "enrollment_key_mismatch")
    if expected["enrollment_class"] == protocol.ENROLLMENT_CLASS_PRODUCTION:
        need(subject["evidence_class"] == protocol.EVIDENCE_CLASS_PRODUCTION,
             "fixture_report_for_production_context")

    # ---- reconstruct EVERY bound digest from retained bytes ----
    manifest_bytes = evidence["manifest_bytes"]
    need(hashlib.sha256(manifest_bytes).hexdigest()
         == subject["manifest_sha256"], "manifest_bytes_mismatch")

    envelope_bytes = evidence["envelope_bytes"]
    envelope = load_json_bytes(envelope_bytes, max_bytes=protocol.MAX_ENVELOPE_B64)
    need(canonical_bytes(envelope) == envelope_bytes, "envelope_not_canonical")
    schemas.validate_envelope_body(envelope)
    native_body, evidence_sha256 = statement_mod.authenticate_statement(
        evidence["statement_bytes"], manifest_bytes, expected["challenge"],
        expected["key_id_b64"], result_envelope=envelope)
    need(evidence_sha256 == subject["launch_evidence_sha256"],
         "launch_evidence_reconstruction_mismatch")

    need(statement_mod.envelope_digest(envelope) == subject["envelope_sha256"],
         "envelope_reconstruction_mismatch")
    need(envelope["launch"]["evidence_sha256"] == evidence_sha256
         and envelope["launch"]["manifest_sha256"] == subject["manifest_sha256"]
         and envelope["launch"]["challenge"] == expected["challenge"]
         and envelope["launch"]["key_id_b64"] == expected["key_id_b64"]
         and envelope["launch"]["counter"] == subject["launch_counter"],
         "envelope_binding_mismatch")
    need(envelope["result_disk"]["sha256"] == subject["result_image_sha256"]
         and envelope["result_disk"]["bytes"] == subject["result_image_bytes"],
         "envelope_image_binding_mismatch")
    need(envelope["console"]["sha256"] == subject["console_sha256"]
         and envelope["console"]["bytes"] == subject["console_bytes"],
         "envelope_console_binding_mismatch")

    # pair evidence from RETAINED assertions + enrollment provenance
    launch_client_data = statement_mod.launch_client_data(
        subject["manifest_sha256"], evidence_sha256, expected["challenge"])
    result_client_data = statement_mod.result_client_data(
        evidence_sha256, subject["envelope_sha256"], expected["challenge"])
    pair_evidence = {
        "schema": protocol.PAIR_DOMAIN,
        "challenge": expected["challenge"],
        "key_id_b64": expected["key_id_b64"],
        "enrollment_sha256": statement_mod.enrollment_digest(enrollment),
        "enrollment_class": enrollment["enrollment_class"],
        "launch_assertion_b64": evidence["launch_assertion_b64"],
        "result_assertion_b64": evidence["result_assertion_b64"],
        "launch_counter": subject["launch_counter"],
        "result_counter": subject["result_counter"],
        "launch_client_data_sha256":
            hashlib.sha256(launch_client_data).hexdigest(),
        "result_client_data_sha256":
            hashlib.sha256(result_client_data).hexdigest(),
    }
    need(statement_mod.pair_evidence_digest(pair_evidence)
         == subject["pair_evidence_sha256"],
         "pair_evidence_reconstruction_mismatch")
    need(report["verifier_context"]["enrollment_sha256"]
         == pair_evidence["enrollment_sha256"],
         "enrollment_digest_mismatch")

    # receipt: full-byte digest, /4 evidence digest, frozen validation
    receipt_bytes = evidence["receipt_bytes"]
    need(hashlib.sha256(receipt_bytes).hexdigest() == subject["receipt_sha256"],
         "receipt_bytes_mismatch")
    receipt = load_json_bytes(receipt_bytes,
                              max_bytes=protocol.EXTRACT_RECEIPT_CAP)
    need(execution_evidence_digest(receipt)
         == subject["receipt_evidence_sha256"],
         "receipt_evidence_reconstruction_mismatch")
    # fragment-for-full substitution refusal: the subject's receipt evidence
    # digest must come from R, and must NOT equal the launch (fragment)
    # digest unless they genuinely coincide — they cannot, because R carries
    # populated outputs/run_id while the native body has them null.
    need(subject["receipt_evidence_sha256"]
         != subject["launch_evidence_sha256"],
         "fragment_for_full_substitution")
    try:
        validate_receipt_bytes(manifest_bytes, receipt_bytes,
                               evidence.get("private_envelope_bytes"))
    except Exception as exc:
        if not isinstance(exc, ContractError):
            raise
        raise Refusal("frozen_receipt_invalid", str(exc)) from exc
    need(receipt.get("environment") == subject["receipt_environment"],
         "receipt_environment_mismatch")
    need(receipt["outputs"]["status"] == subject["receipt_status"],
         "receipt_status_mismatch")

    # ---- REF03: receipt_path must address the receipt selector ----
    need(subject["receipt_path"]
         == "%s/receipt.json" % subject["receipt_selector"],
         "receipt_path_selector_mismatch")

    # ---- REF03 + CROSS-LANE-VERIFIED-FINDINGS.outcome: EXTERNAL expected
    # VM environment (BINDING) + workload outcome (TASK SUCCESS, distinct from
    # evidence validity) ----
    # The VM environment is a BINDING property pinned by the relying party: a
    # report attesting a run in a DIFFERENT environment is REFUSED (never
    # silently relabelled — e.g. 'vm' vs the software fixture's 'linux-test').
    need(receipt.get("environment") == expected["receipt_environment"],
         "expected_receipt_environment_mismatch")
    # The workload OUTCOME is a DISTINCT judgement from evidence validity: a
    # cryptographically VALID report may faithfully attest a workload that did
    # NOT meet the relying party's expected outcome.  Per the authoritative
    # outcome decision, a verified failed/cancelled trace stays EVIDENCE-VALID
    # but CANNOT claim task success; the relying party pins completed/exit0 for
    # the success demo (or an explicit baseline-failure outcome), and the
    # mismatch is reported as task_success=False — NOT a refusal — so the demo
    # can never silently read a non-success trace as success.
    task_success = (receipt["outputs"]["status"] == expected["workload_status"]
                    and receipt["outputs"]["exit_code"] == expected["exit_code"])

    # ---- REF03: commitment-status consistency ----
    # Reconstruct the runtime-input commitment status from the RETAINED
    # envelope + receipt (shared source of truth with the verifier) and require
    # the report's claim to equal it.  A report that advertises
    # bound-to-validated-envelope without a matching receipt commitment, or any
    # malformed scope, refuses here — it is not trusted on the report's say-so.
    reconstructed_commitment = statement_mod.reconcile_commitment_status(
        envelope, receipt, evidence.get("private_envelope_bytes") is not None)
    need(subject["commitment_status"] == reconstructed_commitment,
         "commitment_status_mismatch",
         "report %r != reconstructed %r"
         % (subject["commitment_status"], reconstructed_commitment))
    need(subject["outputs_verified"] is True, "subject_outputs_not_verified")

    # ---- REF03: Apple receipt-status + environment consistency ----
    # The checker binds the enrollment to the report via enrollment_sha256
    # above; it therefore reconstructs the Apple block the same way the verifier
    # produced it (from the enrollment class/environment/receipt status) and
    # refuses any disagreement.  retained_not_validated is PRESERVED verbatim;
    # it is never upgraded to a validated status.
    apple = report["apple"]
    need(apple["environment"] == enrollment["environment"],
         "apple_environment_mismatch")
    if subject["evidence_class"] == protocol.EVIDENCE_CLASS_PRODUCTION:
        expected_apple_status = enrollment["apple_receipt_status"]
        need(expected_apple_status == protocol.APPLE_RECEIPT_STATUS,
             "apple_receipt_status_not_retained")
    else:
        expected_apple_status = (enrollment["apple_receipt_status"]
                                 or "no-apple-receipt-fixture")
    need(apple["receipt_status"] == expected_apple_status,
         "apple_receipt_status_mismatch")

    # shared facts against the AUTHENTICATED native body (R01)
    statement_mod.compare_shared_facts(receipt, native_body)

    # outputs: recompute digest AND length of every delivered byte stream, and
    # validate delivered-output MEMBERSHIP (merged OPCLI03): every delivered
    # file must correspond to a declared, non-null, non-missing receipt output.
    # A null stream or a missing artifact that nevertheless ships a file, or an
    # undeclared delivered artifact, is a REFUSAL — nothing is silently
    # discarded before validation.
    outputs = receipt["outputs"]
    _check_delivered_outputs(receipt, evidence)

    # ---- REF03: result-image evidence is REQUIRED for a FULL verdict ----
    image_verified = False
    precomputed = evidence.get("result_image_sha256_precomputed")
    if precomputed is not None:
        # REF03: the trusted precomputed-image contract is a PAIR — the
        # caller's OWN digest AND its OWN byte length (never the report's).
        # A digest alone can no longer earn 'full': an attacker that keeps the
        # subject digest but changes the length is caught here.
        precomputed_bytes = evidence.get("result_image_bytes_precomputed")
        need(precomputed_bytes is not None, "precomputed_image_length_absent")
        need(isinstance(precomputed_bytes, int)
             and not isinstance(precomputed_bytes, bool),
             "precomputed_image_length_bad")
        need(precomputed == subject["result_image_sha256"],
             "precomputed_image_mismatch")
        need(precomputed_bytes == subject["result_image_bytes"],
             "precomputed_image_bytes_mismatch")
        image_verified = True
    if evidence.get("result_image_path") is not None:
        # Descriptor-safe, nonblocking, bounded streaming hash (merged OPCLI04):
        # the image is opened O_NOFOLLOW|O_NONBLOCK, fstat-admitted regular and
        # hashed on that descriptor with a hard size cap — a symlink/FIFO or an
        # oversized image is refused rather than followed/blocked/exhausting.
        image_digest, image_total = _hash_regular_file_streaming(
            evidence["result_image_path"], protocol.RESULT_TEMPLATE_BYTES_MAX,
            "result_image")
        need(image_digest == subject["result_image_sha256"],
             "image_digest_mismatch")
        need(image_total == subject["result_image_bytes"], "image_bytes_mismatch")
        image_verified = True

    if image_verified:
        verification_level = "full"
    else:
        # No image evidence: REFUSE a full verdict.  Only an explicitly opted-in
        # caller gets a reduced verdict, and it is LABELLED, never a silent
        # checked=True full-check (the REF03 headline defect).
        need(allow_reduced, "image_evidence_absent")
        verification_level = "reduced-no-image"

    # ---- REF03: console digest/length recomputed from RETAINED bytes ----
    # Console verification is MANDATORY in BOTH 'full' and 'reduced-no-image'
    # modes: reduced-no-image omits ONLY the result image, never the console.
    # (The envelope's console digest is cross-checked against the subject
    # above; here the actual retained console bytes are independently hashed.)
    # The earlier defect skipped console entirely in reduced mode, even when
    # console bytes were supplied.
    need("console_bytes" in evidence and evidence["console_bytes"] is not None,
         "console_bytes_absent")
    console_bytes = evidence["console_bytes"]
    need(len(console_bytes) == subject["console_bytes"],
         "console_length_mismatch")
    need(hashlib.sha256(console_bytes).hexdigest()
         == subject["console_sha256"], "console_digest_mismatch")

    # Positive closure is authenticated by the SAME native envelope above.
    # Retained index is reconstructed from the real image by the verifier and
    # reconciled again here against the delivered receipt/output bytes.
    from . import closure
    from .verifier import _reconcile_export_index
    need("export_index_bytes" in evidence, "closure_index_absent")
    need(hashlib.sha256(evidence["export_index_bytes"]).hexdigest() == subject["export_index_sha256"], "closure_image_index_mismatch")
    export_index = load_json_bytes(evidence["export_index_bytes"])
    _reconcile_export_index(export_index, receipt, receipt_bytes,
                            {key: (None, outputs[key.split(":", 1)[1]] if key.startswith("stream:") else next(a for a in outputs["artifacts"] if a["name"] == key.split(":",1)[1])) for key in evidence["outputs"]}, expected["receipt_selector"])
    retained = {expected["receipt_selector"]:
                (receipt_bytes, evidence["export_index_bytes"])}
    selector_outcomes = {expected["receipt_selector"]: task_success}
    if context["schema"] == "dsmack.runresult-checker-context/3":
        selector_evidence = evidence.get("selector_evidence")
        need(isinstance(selector_evidence, dict) and
             set(selector_evidence) == set(expected["selector_manifests"]),
             "selector_evidence_membership")
        for selector, selector_expected in expected["selector_manifests"].items():
            item = selector_evidence[selector]
            need(isinstance(item, dict) and
                 set(item) in ({"manifest_bytes", "receipt_bytes", "export_index_bytes", "outputs"},
                               {"manifest_bytes", "receipt_bytes", "export_index_bytes", "outputs", "private_envelope_bytes"}),
                 "selector_evidence_keys", selector)
            if selector == expected["receipt_selector"]:
                need(all(item.get(key) == evidence.get(key) for key in
                         ("manifest_bytes", "receipt_bytes", "export_index_bytes", "outputs", "private_envelope_bytes")),
                     "primary_selector_evidence_mismatch")
            need(hashlib.sha256(item["manifest_bytes"]).hexdigest() ==
                 selector_expected["manifest_sha256"], "selector_manifest_bytes_mismatch", selector)
            try:
                validate_receipt_bytes(item["manifest_bytes"], item["receipt_bytes"],
                                       item.get("private_envelope_bytes"))
            except Exception as exc:
                if not isinstance(exc, ContractError):
                    raise
                raise Refusal("frozen_receipt_invalid", str(exc)) from exc
            other_receipt = load_json_bytes(item["receipt_bytes"], max_bytes=protocol.EXTRACT_RECEIPT_CAP)
            need(other_receipt.get("environment") == selector_expected["receipt_environment"],
                 "expected_receipt_environment_mismatch", selector)
            # Native statement authenticates common VM/admission/boot facts.
            # Its manifest field names the selected launch manifest; each other
            # manifest is independently pinned above, never inferred from it.
            comparison_body = dict(native_body)
            comparison_body["manifest_sha256"] = selector_expected["manifest_sha256"]
            statement_mod.compare_shared_facts(other_receipt, comparison_body)
            _check_delivered_outputs(other_receipt, item)
            other_outputs = other_receipt["outputs"]
            collected = {}
            for key in item["outputs"]:
                kind, name = key.split(":", 1)
                declared = (other_outputs[name] if kind == "stream" else
                            next(a for a in other_outputs["artifacts"] if a["name"] == name))
                collected[key] = (None, declared)
            other_index = load_json_bytes(item["export_index_bytes"], max_bytes=protocol.EXTRACT_SUMMARY_CAP)
            _reconcile_export_index(other_index, other_receipt, item["receipt_bytes"], collected, selector)
            retained[selector] = (item["receipt_bytes"], item["export_index_bytes"])
            selector_outcomes[selector] = (
                other_outputs["status"] == selector_expected["workload_status"] and
                other_outputs["exit_code"] == selector_expected["exit_code"])
        task_success = all(selector_outcomes.values())
    closure.reconcile(console_bytes, expected["closure_context"], retained)

    return {"checked": True, "subject": subject,
            "verification_level": verification_level,
            "evidence_class": subject["evidence_class"],
            # CROSS-LANE-VERIFIED-FINDINGS.outcome: evidence validity (checked)
            # is reported SEPARATELY from workload task success.
            "task_success": task_success,
            "selector_task_success": selector_outcomes,
            "workload_outcome": subject["receipt_status"],
            "expected_workload_status": expected["workload_status"],
            "expected_exit_code": expected["exit_code"],
            "receipt_environment": subject["receipt_environment"]}
