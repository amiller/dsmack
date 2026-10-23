"""runresult verifier /2 — the closed fail-closed verification procedure.

A refusal at ANY step means NO report exists (there is no failure report
and no fake success flag).  Modes:

  * mode="production": enrollment MUST be class apple-appattest-production
    with retained Apple attestation + opaque receipt and pinned-core
    provenance.  TEST fixtures are refused before any assertion is touched.
  * mode="fixture": enrollment MUST be class software-test-fixture-
    nonhardware; the report subject carries evidence_class
    software-fixture-nonhardware, so no fixture report can ever be read as
    hardware evidence.  The production CLI never accepts this mode.

Steps (exact order):
  1  bounded request parse + attachment index load (sha256+size checked for
     every public attachment; the optional private runtime envelope is
     loaded WITHOUT any digest computation — excluded transport).
  2  enrollment record validation + mode gate; enrollment_sha256 computed.
  3  statement authentication (R01): N := assertion.receipt_evidence_body,
     L recomputed, bound duplicates enforced, diagnostics ignored.
  4  envelope: canonical-bytes equality, exact §5.3 shape, E recomputed;
     envelope.launch must equal {L, M, challenge, key_id, launch_counter}.
  5  launch assertion through the PINNED core over the native 4-part
     preimage; authenticated counter must equal the claimed launch_counter.
  6  result assertion over the 4-part result preimage, same key;
     authenticated == claimed result_counter; result > launch.
  7  result image: sha256(bytes) == envelope.result_disk.sha256 ==
     request.result_image_sha256; exact byte count == template_bytes.
  8  confined staged extraction (R04) by receipt_selector.
  9  receipt: sha256(R bytes), execution_evidence_digest(R), frozen
     validate_receipt_bytes(manifest, R[, private envelope]); R.manifest == M.
 10  shared-fact comparison guest R vs authenticated N (R01).
 11  outputs: every non-null stream/artifact digest+length recomputed from
     delivered bytes (inside extraction); CLI diagnostics can never
     substitute (they are never extracted).
 12  commitment claim mapping (frozen semantics; status absent /
     recorded-unchecked / bound-to-validated-envelope).
 13  pair evidence + report build, ed25519 signature, then the ATOMIC replay
     commit (R03) stores the signed report durably in the outbox.  The
     commit is the LAST step: a refusal inside it leaves no consumed
     challenge and no report.
"""
import base64
import hashlib
import json
import time

from cryptography.hazmat.primitives import serialization

from . import protocol, schemas, statement as statement_mod
from . import enrollment_store as enrollment_store_mod
from .errors import Refusal, need
from .frozen import (COMMITMENT_ALGS, ReceiptError, canonical_bytes, core,
                     load_json_bytes, report_body, sha256_obj,
                     validate_commitment_scope_shape, validate_receipt_bytes)


def _read_attachment(directory, entry, role):
    # REF04: regular-file check + stat-bounded read.  The expected size is an
    # already-capped index value (schemas.ATTACHMENT_BYTE_CAPS); we refuse if
    # the on-disk size disagrees and read AT MOST that many bytes +1 so an
    # attacker cannot make us allocate from an unbounded/larger file.
    import os as _os
    import stat as _stat
    path = "%s/%s" % (directory, role)
    fd = _os.open(path, _os.O_RDONLY)
    try:
        st = _os.fstat(fd)
        need(_stat.S_ISREG(st.st_mode), "attachment_not_regular_file", role)
        need(st.st_size == entry["bytes"], "attachment_size_mismatch", role)
        data = b""
        want = entry["bytes"] + 1
        while len(data) < want:
            chunk = _os.read(fd, min(1 << 20, want - len(data)))
            if not chunk:
                break
            data += chunk
    finally:
        _os.close(fd)
    need(len(data) == entry["bytes"], "attachment_size_mismatch", role)
    if "sha256" in entry:
        need(hashlib.sha256(data).hexdigest() == entry["sha256"],
             "attachment_digest_mismatch", role)
    return data


EXPORT_INDEX_SCHEMA = "dsmack.run-output-export/1"


def _reconcile_export_index(index, receipt, receipt_bytes, collected, selector):
    """REF11: reconcile the IMAGE-EXTRACTED producer binding index against the
    validated receipt AND the exact output bytes the extractor delivered.

    Every binding the index asserts — the receipt digest + relative path, the
    run identity, the workload status/exit/cancel/environment, and each
    non-null stream / non-missing artifact's sha256 + byte length + in-outputs
    path — must EQUAL both the receipt the verifier validated and the bytes the
    confined extractor actually delivered (``collected`` maps the delivered
    label to ``(path, declared)`` where ``declared`` was already proven equal to
    the delivered bytes in extract_outputs).  The delivered set and the
    index-bound set must be identical, so neither a dropped nor an extra binding
    survives.  Any disagreement is a fail-closed refusal."""
    need(isinstance(index, dict), "ex_index_not_object")
    need(index.get("schema") == EXPORT_INDEX_SCHEMA, "index_schema",
         str(index.get("schema")))
    outputs = receipt["outputs"]
    need(index.get("selector") == selector, "index_selector_mismatch")
    need(index.get("run_id") == receipt.get("run_id"), "index_run_id_mismatch")
    need(index.get("manifest_sha256") == receipt.get("manifest_sha256"),
         "index_manifest_mismatch")
    need(index.get("environment") == receipt.get("environment"),
         "index_environment_mismatch")
    need(index.get("status") == outputs.get("status"), "index_status_mismatch")
    need(index.get("exit_code") == outputs.get("exit_code"),
         "index_exit_code_mismatch")
    need(index.get("cancel") == outputs.get("cancel"), "index_cancel_mismatch")
    need(index.get("receipt_sha256")
         == hashlib.sha256(receipt_bytes).hexdigest(),
         "index_receipt_digest_mismatch")
    need(index.get("receipt_path") == "../receipt.json",
         "index_receipt_path_mismatch", str(index.get("receipt_path")))
    need(sorted(index.get("missing") or []) == sorted(outputs.get("missing") or []),
         "index_missing_mismatch")

    index_bound = set()
    idx_streams = index.get("streams")
    need(isinstance(idx_streams, dict), "index_streams_malformed")
    # EXACT stream membership: the index binds EXACTLY the non-null declared
    # streams — an unknown or extra stream key (e.g. 'stdout.bin', 'sneaky') is
    # a refusal, not silently ignored.  The earlier loop only READ the two known
    # keys, so any additional key survived unvalidated.
    expected_streams = set()
    for stream in ("stdout", "stderr"):
        declared = outputs.get(stream)
        idx = idx_streams.get(stream)
        if declared is None:
            need(idx is None, "index_stream_unexpected", stream)
            continue
        expected_streams.add(stream)
        need(isinstance(idx, dict), "index_stream_absent", stream)
        need(idx.get("path") == "streams/%s" % stream,
             "index_stream_path", stream)
        need(idx.get("sha256") == declared["sha256"]
             and idx.get("bytes") == declared["bytes"],
             "index_stream_binding", stream)
        index_bound.add("stream:" + stream)
    need(set(idx_streams.keys()) == expected_streams,
         "index_streams_membership",
         "index=%s expected=%s"
         % (sorted(idx_streams.keys()), sorted(expected_streams)))

    missing = set(outputs.get("missing") or [])
    # EXACT artifact membership + DUPLICATE detection: the index's artifacts
    # list must be well-formed, carry no duplicate names (dict construction
    # previously collapsed them silently) and bind EXACTLY the declared,
    # non-missing artifacts — an undeclared artifact name is a refusal.
    idx_artifacts_list = index.get("artifacts")
    need(isinstance(idx_artifacts_list, list), "index_artifacts_malformed")
    idx_names = []
    idx_artifacts = {}
    for entry in idx_artifacts_list:
        need(isinstance(entry, dict), "index_artifact_entry_malformed")
        name = entry.get("name")
        need(isinstance(name, str) and name, "index_artifact_name_malformed",
             str(name))
        idx_names.append(name)
        idx_artifacts[name] = entry
    need(len(idx_names) == len(set(idx_names)), "index_artifact_duplicate",
         ",".join(sorted({n for n in idx_names if idx_names.count(n) > 1})))
    expected_artifacts = set()
    for artifact in outputs.get("artifacts") or []:
        name = artifact["name"]
        if name in missing:
            need(name not in idx_artifacts, "index_missing_artifact_bound", name)
            continue
        expected_artifacts.add(name)
        idx = idx_artifacts.get(name)
        need(idx is not None, "index_artifact_absent", name)
        need(idx.get("path") == "artifacts/%s" % name,
             "index_artifact_path", name)
        need(idx.get("sha256") == artifact["sha256"]
             and idx.get("bytes") == artifact["bytes"],
             "index_artifact_binding", name)
        index_bound.add("artifact:" + name)
    need(set(idx_names) == expected_artifacts, "index_artifacts_membership",
         "index=%s expected=%s"
         % (sorted(set(idx_names)), sorted(expected_artifacts)))
    # the index-bound set must EQUAL the delivered set (no dropped/extra entry)
    need(index_bound == set(collected), "index_delivered_set_mismatch",
         "index=%s delivered=%s" % (sorted(index_bound), sorted(collected)))
    # and each index binding equals the DELIVERED declared digest/length
    for label, (_path, declared) in collected.items():
        if label.startswith("stream:"):
            idx = idx_streams.get(label.split(":", 1)[1])
        else:
            idx = idx_artifacts.get(label.split(":", 1)[1])
        need(idx is not None and idx.get("sha256") == declared["sha256"]
             and idx.get("bytes") == declared["bytes"],
             "index_delivered_binding", label)


def verify(request_obj, attachment_index_obj, attachments_dir, enrollment_obj,
           replay_store, report_signing_key, report_key_id,
           extractor_factory, mode, now_unix_s=None,
           crash_before_commit=False, enrollment_store=None,
           admitted_policy=None):
    """Returns the signed report bytes (also durably stored in the replay
    outbox).  extractor_factory() -> SafeExtractor (R04, confined)."""
    need(mode in ("production", "fixture"), "bad_mode")
    now = int(now_unix_s if now_unix_s is not None else time.time())

    # 1 ---- request + attachments ----
    request = schemas.validate_request(request_obj)
    index = schemas.validate_attachment_index(attachment_index_obj)
    manifest_bytes = _read_attachment(attachments_dir, index["manifest"],
                                      "manifest")
    need(hashlib.sha256(manifest_bytes).hexdigest()
         == request["manifest_sha256"], "manifest_attachment_mismatch")
    need(index["result_image"]["sha256"] == request["result_image_sha256"]
         and index["result_image"]["bytes"] == request["result_image_bytes"],
         "image_attachment_mismatch")
    enrollment_bytes = _read_attachment(attachments_dir, index["enrollment"],
                                        "enrollment")
    private_envelope_bytes = None
    if "runtime_envelope_private" in index:
        # Excluded transport: size-checked only; NO digest is computed,
        # recorded or compared anywhere (R05).
        path = "%s/%s" % (attachments_dir, "runtime_envelope_private")
        private_envelope_bytes = open(path, "rb").read()
        need(len(private_envelope_bytes)
             == index["runtime_envelope_private"]["bytes"],
             "private_envelope_size")

    # 2 ---- enrollment + mode gate ----
    # REF04: reject duplicate JSON keys in the enrollment document (the frozen
    # core's duplicate-rejecting parser), consistent with every other wire doc.
    try:
        loaded_enrollment = core.unique_json(enrollment_bytes.decode("utf-8"))
    except core.Reject as exc:
        raise Refusal("enrollment_bad_json", str(exc)) from exc
    need(loaded_enrollment == enrollment_obj, "enrollment_attachment_mismatch")
    enrollment = schemas.validate_enrollment(enrollment_obj)
    need(enrollment["key_id_b64"] == request["key_id_b64"],
         "enrollment_key_mismatch")
    enrollment_sha256 = statement_mod.enrollment_digest(enrollment)
    # The caller-supplied point/provenance/Apple blobs are METADATA — never
    # trust.  We still require internal consistency (key id == sha256(point))
    # so a malformed record is refused early.
    caller_point_b64 = enrollment["assertion_public_key"]["key_b64"]
    need(core.b64(hashlib.sha256(base64.b64decode(caller_point_b64)).digest())
         == request["key_id_b64"], "key_id_point_mismatch")
    if mode == "production":
        need(enrollment["enrollment_class"]
             == protocol.ENROLLMENT_CLASS_PRODUCTION,
             "production_requires_apple_enrollment",
             enrollment["enrollment_class"])
        need("TESTFIXTURE" not in enrollment["team_id"],
             "production_fixture_team")
        # REF02: production trust comes ONLY from the authenticated enrollment
        # store (populated by the pinned-core attestation ceremony).  A
        # caller's self-asserted key, provenance string naming the pinned core
        # and fabricated Apple blobs are REFUSED — they never enter trust.
        need(enrollment_store is not None,
             "production_requires_authenticated_store")
        record = enrollment_store.resolve(request["key_id_b64"])
        need(record is not None, "production_enrollment_not_authenticated")
        need(record["trust_tier"]
             == enrollment_store_mod.TRUST_TIER_HARDWARE,
             "production_requires_hardware_rooted_enrollment",
             record["trust_tier"])
        # OPCLI01: the authenticated record must STILL satisfy the externally
        # admitted CURRENT operator policy and root-pin set — not merely the
        # historical designation frozen into the record at enrollment time.
        # The record stores its ceremony policy and root DER; we re-check both
        # against what the operator admits NOW, so a record enrolled under a
        # superseded app/team/environment/category/version/CDHash/ACL policy,
        # or whose root has since been removed from the hardware pin set, is
        # refused before any assertion is authenticated.
        need(admitted_policy is not None,
             "production_requires_admitted_policy")
        admitted_pol = admitted_policy["policy"]
        need(record["root_sha256"]
             in frozenset(admitted_policy["hardware_root_der_sha256"]),
             "enrollment_root_not_currently_pinned", record["root_sha256"])
        need(record["app_id"] == admitted_pol.app_id,
             "enrollment_app_not_current_policy")
        need(record["team_id"] == admitted_policy["team_id"],
             "enrollment_team_not_current_policy")
        need(record["environment"] == admitted_pol.environment,
             "enrollment_environment_not_current_policy")
        # Full policy-descriptor equality binds categories, versions, CDHashes,
        # the macOS ACL requirement and the AAGUID selection to the current
        # admitted policy (not the stored one), so the assertion below is
        # authenticated under CURRENT policy facts.
        need(record["policy"]
             == enrollment_store_mod._policy_descriptor(admitted_pol),
             "enrollment_policy_not_current_policy")
        # Caller metadata must agree with the authenticated record; trust
        # derives from `record`, never from the caller object.
        need(enrollment["app_id"] == record["app_id"],
             "enrollment_app_not_authenticated")
        need(enrollment["team_id"] == record["team_id"],
             "enrollment_team_not_authenticated")
        need(enrollment["environment"] == record["environment"],
             "enrollment_environment_not_authenticated")
        need(caller_point_b64 == record["public_key_b64"],
             "enrollment_key_not_authenticated")
        # REF02-retained-evidence: bind the TRANSFERRED enrollment package to
        # the exact ceremony the authenticated store ran.  The caller's
        # retained Apple attestation/receipt bytes, the challenge the nonce
        # extension bound and the pinned core that verified them must equal the
        # record's retained ceremony evidence.  Because these fields are also
        # covered by ``enrollment_sha256`` (statement.enrollment_digest), the
        # report's enrollment digest now binds the authenticated ceremony, not
        # free caller metadata.  Receipt status stays retained_not_validated.
        need(enrollment["apple_attestation_b64"]
             == record["apple_attestation_b64"],
             "enrollment_attestation_not_authenticated")
        need(enrollment["apple_receipt_b64"] == record["apple_receipt_b64"],
             "enrollment_receipt_not_authenticated")
        need(enrollment["apple_receipt_status"]
             == record["apple_receipt_status"],
             "enrollment_receipt_status_not_authenticated")
        prov = enrollment["provenance"]
        need(prov["attestation_challenge"]
             == record["attestation_challenge_b64"],
             "enrollment_challenge_not_authenticated")
        need(prov["verified_by_core_sha256"] == record["core_sha256"],
             "enrollment_core_not_authenticated")
        need(prov["verified_at_unix_s"] == record["enrolled_at_unix_s"],
             "enrollment_time_not_authenticated")
        public_key_b64 = record["public_key_b64"]
        policy = admitted_pol
        evidence_class = protocol.EVIDENCE_CLASS_PRODUCTION
        apple_environment = record["environment"]
        apple_receipt_status = record["apple_receipt_status"]
    else:
        need(enrollment["enrollment_class"]
             == protocol.ENROLLMENT_CLASS_FIXTURE,
             "fixture_mode_requires_fixture_class")
        public_key_b64 = caller_point_b64
        policy = core.Policy(app_id=enrollment["app_id"],
                             environment=enrollment["environment"])
        evidence_class = protocol.EVIDENCE_CLASS_FIXTURE
        apple_environment = enrollment["environment"]
        apple_receipt_status = (enrollment["apple_receipt_status"]
                                or "no-apple-receipt-fixture")

    # 4 ---- envelope ----
    envelope_bytes = base64.b64decode(request["envelope_b64"])
    envelope = load_json_bytes(envelope_bytes,
                               max_bytes=protocol.MAX_ENVELOPE_B64)
    need(canonical_bytes(envelope) == envelope_bytes,
         "envelope_not_canonical")
    schemas.validate_envelope_body(envelope)
    # 3 ---- statement (R01) ----
    statement_bytes = base64.b64decode(request["launch_statement_b64"])
    native_body, evidence_sha256 = statement_mod.authenticate_statement(
        statement_bytes, manifest_bytes, request["challenge"],
        request["key_id_b64"], result_envelope=envelope)

    envelope_sha256 = statement_mod.envelope_digest(envelope)
    launch = envelope["launch"]
    need(launch["evidence_sha256"] == evidence_sha256,
         "envelope_evidence_mismatch")
    need(launch["manifest_sha256"] == request["manifest_sha256"],
         "envelope_manifest_mismatch")
    need(launch["challenge"] == request["challenge"],
         "envelope_challenge_mismatch")
    need(launch["key_id_b64"] == request["key_id_b64"],
         "envelope_key_mismatch")
    need(launch["counter"] == request["launch_counter"],
         "envelope_counter_mismatch")

    # 5 ---- launch assertion (pinned core; authenticated counter) ----
    launch_client_data = statement_mod.launch_client_data(
        request["manifest_sha256"], evidence_sha256, request["challenge"])
    try:
        launch_result = core.verify_assertion(
            base64.b64decode(request["launch_assertion_b64"]),
            launch_client_data, public_key_b64,
            request["launch_counter"] - 1, policy)
    except core.Reject as exc:
        raise Refusal("launch_assertion_rejected", str(exc)) from exc
    need(launch_result["counter"] == request["launch_counter"],
         "launch_counter_not_authenticated",
         "claimed %d, authenticated %d" % (request["launch_counter"],
                                           launch_result["counter"]))

    # 6 ---- result assertion ----
    result_client_data = statement_mod.result_client_data(
        evidence_sha256, envelope_sha256, request["challenge"])
    try:
        result_result = core.verify_assertion(
            base64.b64decode(request["result_assertion_b64"]),
            result_client_data, public_key_b64,
            request["result_counter"] - 1, policy)
    except core.Reject as exc:
        raise Refusal("result_assertion_rejected", str(exc)) from exc
    need(result_result["counter"] == request["result_counter"],
         "result_counter_not_authenticated")
    need(request["result_counter"] > request["launch_counter"],
         "counter_order")

    # 7 ---- result image ----
    image_path = "%s/%s" % (attachments_dir, "result_image")
    disk = envelope["result_disk"]
    need(disk["sha256"] == request["result_image_sha256"],
         "envelope_image_mismatch")
    need(disk["bytes"] == request["result_image_bytes"],
         "envelope_image_bytes_mismatch")

    # 8 ---- confined extraction (R04); snapshot re-hashes the exact bytes --
    extractor = extractor_factory()
    try:
        extractor.snapshot(image_path, request["result_image_sha256"],
                           request["result_image_bytes"])
        receipt_rel, receipt_bytes = extractor.extract_bootstrap(
            request["receipt_selector"])

        # 9 ---- receipt ----
        receipt_sha256 = hashlib.sha256(receipt_bytes).hexdigest()
        receipt = load_json_bytes(receipt_bytes,
                                  max_bytes=protocol.EXTRACT_RECEIPT_CAP)
        from .frozen import execution_evidence_digest
        receipt_evidence_sha256 = execution_evidence_digest(receipt)
        try:
            validate_receipt_bytes(manifest_bytes, receipt_bytes,
                                   private_envelope_bytes)
        except (ReceiptError, Exception) as exc:
            if exc.__class__.__name__ not in ("ReceiptError", "ContractError"):
                raise
            raise Refusal("frozen_receipt_invalid", str(exc)) from exc
        need(receipt.get("manifest_sha256") == request["manifest_sha256"],
             "receipt_manifest_mismatch")

        # 10 ---- shared facts (R01) ----
        statement_mod.compare_shared_facts(receipt, native_body)

        # 11 ---- outputs from delivered bytes ----
        collected = extractor.extract_outputs(request["receipt_selector"],
                                              receipt)

        # 11b ---- REF11: require + reconcile the IMAGE-EXTRACTED binding index -
        # Production verification must REQUIRE and RECONCILE the producer's
        # retained binding index, not merely trust that producer and consumer
        # layouts agree in memory.  The relying party pulls
        # <selector>/outputs/index.json OUT OF THE IMAGE through the SAME
        # confined extractor and reconciles it against the validated receipt
        # (receipt digest + path, status/exit/cancel/environment) AND the exact
        # output bindings the extractor delivered.  An absent, tampered or
        # inconsistent index fails closed here — the earlier verifier never
        # read extract_index at all, so a divergent retained index was invisible
        # to production verification.
        index_rel, extracted_index = extractor.extract_index(
            request["receipt_selector"])
        export_index_sha256 = hashlib.sha256(extractor.last_index_bytes).hexdigest()
        _reconcile_export_index(extracted_index, receipt, receipt_bytes,
                                collected, request["receipt_selector"])

        # 12 ---- commitment claim (REF03/REF07: single source of truth) ----
        commitment_status = statement_mod.reconcile_commitment_status(
            envelope, receipt, private_envelope_bytes is not None)
    finally:
        extractor.cleanup()

    # 13 ---- pair evidence, report, atomic replay commit ----
    pair_evidence = {
        "schema": protocol.PAIR_DOMAIN,
        "challenge": request["challenge"],
        "key_id_b64": request["key_id_b64"],
        "enrollment_sha256": enrollment_sha256,
        "enrollment_class": enrollment["enrollment_class"],
        "launch_assertion_b64": request["launch_assertion_b64"],
        "result_assertion_b64": request["result_assertion_b64"],
        "launch_counter": request["launch_counter"],
        "result_counter": request["result_counter"],
        "launch_client_data_sha256":
            hashlib.sha256(launch_client_data).hexdigest(),
        "result_client_data_sha256":
            hashlib.sha256(result_client_data).hexdigest(),
    }
    pair_evidence_sha256 = statement_mod.pair_evidence_digest(pair_evidence)

    report = {
        "runresult_report_version": protocol.REPORT_VERSION,
        "verifier": {"id": protocol.VERIFIER_ID,
                     "version": protocol.VERIFIER_VERSION,
                     "key_id": report_key_id},
        "verifier_context": {
            "core_sha256": protocol.CORE_SHA256,
            "extractor_tool_sha256": extractor.tool_sha256,
            "extraction_contract": protocol.EXTRACTION_CONTRACT,
            "enrollment_sha256": enrollment_sha256,
        },
        "verified": True,
        "subject": {
            "manifest_sha256": request["manifest_sha256"],
            "receipt_selector": request["receipt_selector"],
            "challenge": request["challenge"],
            "key_id_b64": request["key_id_b64"],
            "launch_evidence_sha256": evidence_sha256,
            "envelope_sha256": envelope_sha256,
            "pair_evidence_sha256": pair_evidence_sha256,
            "launch_counter": launch_result["counter"],
            "result_counter": result_result["counter"],
            "result_image_sha256": request["result_image_sha256"],
            "result_image_bytes": request["result_image_bytes"],
            "console_sha256": envelope["console"]["sha256"],
            "console_bytes": envelope["console"]["bytes"],
            "receipt_path": receipt_rel,
            "receipt_sha256": receipt_sha256,
            "export_index_sha256": export_index_sha256,
            "receipt_evidence_sha256": receipt_evidence_sha256,
            "receipt_environment": receipt.get("environment"),
            "receipt_status": receipt["outputs"]["status"],
            "outputs_verified": True,
            "commitment_status": commitment_status,
            "evidence_class": evidence_class,
        },
        "apple": {
            "assertion_counters_authenticated": True,
            "receipt_status": apple_receipt_status,
            "environment": apple_environment,
            "verified_at_unix_s": now,
        },
    }
    body = report_body(report)
    signature = report_signing_key.sign(body)
    report["report_sig"] = {"alg": "ed25519", "key_id": report_key_id,
                            "sig_b64": core.b64(signature)}
    schemas.validate_report_shape(report)
    report_bytes = canonical_bytes(report)

    replay_store.commit(
        request["challenge"], request["key_id_b64"],
        request["manifest_sha256"], request["launch_counter"],
        request["result_counter"], report_bytes, now_unix_s=now,
        crash_before_commit=crash_before_commit,
        # REF02: a production commit requires an authenticated enrollment floor
        # for the key (a missing production floor is refused, never admitted at
        # zero); the fixture path keeps the floor optional.
        require_enrollment_floor=(mode == "production"))
    return report_bytes
