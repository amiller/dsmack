"""REF02-operator-path — the PRODUCTION operator entry point, INTEGRATED into
the reviewed IO package (``runresult_ref``).

This merges the corrected frozen operator package (loop40-operator-repair2:
bounded descriptor-safe reads of EVERY input, default trusted enrollment clock,
and an independent-context relying-party ``check`` command) WITH this lane's
checker improvements (REF03 image/console/commitment bindings and the merged
delivered-output membership + descriptor-safe image hash) and REF02 enrollment
hardening, preserving both lanes' changes:

  * Policy is operator-admitted, never caller-admitted.  The Apple root (by
    DER SHA256 pin), app id, team id, environment, validation categories and
    CDHashes come from an operator ``--policy`` file.  The demo policy is
    EXPLICITLY production / category 3 (COORDINATOR-APPLE-ENVIRONMENT-POLICY);
    development is only an explicit alternative (``--allow-development``).

  * REF02: ``verify`` CONFIRMS the current operator policy + root STILL equal
    the policy/root recorded in the resolved authenticated enrollment record,
    AND that the record's root is STILL a member of the CURRENT hardware-root
    pin set, before trusting it.  A rotated/mismatched policy, or a root that
    has been REMOVED from the current pin set (a revoked hardware root), is
    refused even though the stored record was hardware-tier when enrolled.

  * Every CLI input — operator secrets AND transferred wire documents, the
    policy, the root PEM, the ceremony files — is read through
    ``_read_regular_file``: opened O_NOFOLLOW|O_NONBLOCK (a symlink is refused,
    a FIFO/device cannot block us), fstat-admitted as a regular file BEFORE any
    blocking read, and bounded to a per-role cap.  Operator SECRET files must
    additionally be owned by the operator and mode EXACTLY 0600.

  * REF02: ``enroll`` initialises the AUTHENTICATED replay floor for the newly
    enrolled key (``ReplayStore.set_enrollment_floor``).  For a PRODUCTION
    policy this is MANDATORY (``--replay`` required); a production commit then
    refuses a key with no authenticated floor (``enrollment_floor_absent``).

  * There is NO clock-bypass parameter affecting cert validation.  ``enroll``
    always runs the pinned core with no ``at_time``; ``--now`` only stamps
    ``enrolled_at`` and DEFAULTS to trusted wall-clock time (never ``None``, so
    the default path cannot abort in ``int(now_unix_s)``).

  * ``check`` is the relying party's INDEPENDENT validation: it reads an
    independently admitted checker-context file (NOT values reconstructed from
    the submitted bundle) and the retained evidence, invokes ``checker.check``,
    and reports EVIDENCE validity (a cryptographic fact; a Refusal -> exit 2)
    SEPARATELY from WORKLOAD task success (exit 3 when evidence-valid but the
    attested outcome is not the pinned expected outcome).

``apple_receipt_status`` is preserved verbatim (``retained_not_validated``).
"""
import argparse
import base64
import errno
import json
import os
import secrets
import stat
import sys
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from . import protocol, schemas
from . import checker as checker_mod
from . import enrollment_store as enrollment_store_mod
from . import retained_evidence
from .enrollment_store import (AuthenticatedEnrollmentStore,
                               TRUST_TIER_HARDWARE, root_der_sha256)
from .errors import Refusal, need
from .extraction import SafeExtractor
from .frozen import canonical_bytes, core
from .replay import ReplayStore
from .verifier import verify as verify_bundle


# ---------------------------------------------------------------------------
# bounded, descriptor-safe reads for EVERY input (OPCLI04 / REF02 / R04)
# ---------------------------------------------------------------------------
MAX_OPERATOR_SECRET_BYTES = 1 << 20
MAX_ATTESTATION_FILE_BYTES = enrollment_store_mod.MAX_ATTESTATION_B64
MAX_CHALLENGE_FILE_BYTES = protocol.MAX_CHALLENGE_CHARS
MAX_KEY_ID_FILE_BYTES = protocol.MAX_KEY_ID_B64 + 16
MAX_INDEX_JSON_BYTES = 1 << 16
MAX_ENROLLMENT_JSON_BYTES = schemas.ATTACHMENT_BYTE_CAPS["enrollment"]
MAX_RECEIPT_JSON_BYTES = protocol.EXTRACT_RECEIPT_CAP
MAX_OUTPUT_STREAM_BYTES = protocol.EXTRACT_TOTAL_BYTES_MAX
MAX_POLICY_FILE_BYTES = 1 << 16
MAX_ROOT_PEM_BYTES = 1 << 16


def _read_regular_file(path, cap, what, require_private=False):
    """Descriptor-safe bounded read.  Opens O_NOFOLLOW|O_NONBLOCK, fstats the
    descriptor (regular-file required BEFORE any blocking read), optionally
    enforces mode 0600 (owner-only) + operator ownership, and reads at most
    ``cap`` bytes (a larger file is refused before it can exhaust memory)."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENXIO):
            # O_NOFOLLOW on a symlink -> ELOOP; O_NONBLOCK on a writer-less
            # FIFO -> ENXIO.  Both are refused inputs, never regular files.
            raise Refusal(("operator_secret_not_regular_file" if require_private
                           else "input_not_regular_file"), what) from None
        raise Refusal("input_open_failed", "%s: %s" % (what, exc.strerror)) \
            from None
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode),
             ("operator_secret_not_regular_file" if require_private
              else "input_not_regular_file"), what)
        if require_private:
            need(stat.S_IMODE(st.st_mode) == 0o600,
                 "operator_secret_permissions_too_open",
                 "%s mode %o must be exactly 0600"
                 % (what, stat.S_IMODE(st.st_mode)))
            need(st.st_uid == os.geteuid(),
                 "operator_secret_wrong_owner",
                 "%s uid %d must be operator uid %d"
                 % (what, st.st_uid, os.geteuid()))
        data = b""
        want = cap + 1
        while len(data) < want:
            try:
                chunk = os.read(fd, min(1 << 16, want - len(data)))
            except BlockingIOError:
                raise Refusal("input_would_block", what) from None
            if not chunk:
                break
            data += chunk
        need(len(data) <= cap,
             ("operator_secret_too_large" if require_private
              else "input_too_large"), what)
    finally:
        os.close(fd)
    return data


def _load_wire_json(path, cap, what):
    """Bounded read + duplicate-key-rejecting JSON parse for a transferred wire
    document (the same frozen ``unique_json`` used everywhere else)."""
    raw = _read_regular_file(path, cap, what)
    try:
        return core.unique_json(raw.decode("utf-8"))
    except core.Reject as exc:
        raise Refusal("wire_json_invalid", "%s: %s" % (what, exc)) from exc
    except UnicodeDecodeError:
        raise Refusal("wire_json_invalid", "%s: not utf-8" % what) from None


def _require_private_file(path, what):
    return _read_regular_file(path, MAX_OPERATOR_SECRET_BYTES, what,
                              require_private=True)


def load_operator_secret(path):
    secret = _require_private_file(path, "operator_secret")
    need(len(secret) >= 16, "weak_operator_secret")
    return secret


def load_signing_key(path):
    raw = _require_private_file(path, "report_signing_key")
    need(len(raw) == 32, "bad_signing_key_length")
    return ed25519.Ed25519PrivateKey.from_private_bytes(raw)


# ---------------------------------------------------------------------------
# operator policy (externally admitted — never from a caller request)
# ---------------------------------------------------------------------------
POLICY_KEYS = frozenset({
    "app_id", "team_id", "environment", "categories", "versions",
    "cdhashes", "require_macos_acl", "root_pem_path",
    "hardware_root_der_sha256",
})


def load_operator_policy(path, allow_development=False):
    # The operator policy + root PEM are operator-admitted local config, but
    # still read descriptor-safe (O_NOFOLLOW|O_NONBLOCK) and bounded, with the
    # duplicate-key-rejecting parser — a symlinked or oversized policy/root is
    # refused like any other input.
    obj = _load_wire_json(path, MAX_POLICY_FILE_BYTES, "operator_policy")
    need(isinstance(obj, dict) and set(obj.keys()) == POLICY_KEYS,
         "bad_operator_policy_keys")
    env = obj["environment"]
    need(env in ("production", "development"), "bad_policy_environment")
    need(env == "production" or allow_development,
         "development_policy_requires_explicit_opt_in")
    cdhashes = tuple(bytes.fromhex(h) for h in obj["cdhashes"])
    policy = core.Policy(
        app_id=obj["app_id"],
        environment=env,
        categories=tuple(obj["categories"]),
        versions=tuple(obj["versions"]),
        cdhashes=cdhashes,
        require_macos_acl=bool(obj["require_macos_acl"]),
    )
    need(policy.app_id.startswith(obj["team_id"] + "."), "policy_app_team_mismatch")
    root_pem = _read_regular_file(obj["root_pem_path"], MAX_ROOT_PEM_BYTES,
                                  "operator_root_pem")
    need(root_pem, "operator_root_required")
    hw_pins = tuple(obj["hardware_root_der_sha256"])
    need(all(isinstance(h, str) and len(h) == 64 for h in hw_pins),
         "bad_hardware_root_pin")
    return {"policy": policy, "team_id": obj["team_id"], "root_pem": root_pem,
            "hardware_root_der_sha256": hw_pins}


def assert_current_policy_matches_record(admitted, record):
    """REF02: the CURRENT operator policy + root must equal the policy/root the
    resolved record was enrolled under, AND the record's root must STILL be a
    member of the current hardware-root pin set.

    Without the membership check, removing a root from
    ``hardware_root_der_sha256`` would NOT revoke a previously hardware-tier
    record: ``resolve`` returns the stored trust tier and never re-evaluates
    membership, so a since-removed root would keep passing verification.  Here a
    record whose recorded root is no longer pinned is refused as revoked."""
    current = enrollment_store_mod._policy_descriptor(admitted["policy"])
    need(record["policy"] == current, "verify_policy_mismatch",
         "resolved record policy differs from the current operator policy")
    need(record["root_sha256"] == root_der_sha256(admitted["root_pem"]),
         "verify_root_mismatch",
         "resolved record root differs from the current operator root")
    need(record["root_sha256"] in set(admitted["hardware_root_der_sha256"]),
         "verify_root_not_in_current_pinset",
         "resolved record root is no longer a member of the current "
         "hardware-root pin set (revoked)")


# ---------------------------------------------------------------------------
# transferable enrollment package (bound to the stored ceremony)
# ---------------------------------------------------------------------------
def enrollment_package_from_record(record, attestation_b64):
    """Build the dsmack.runresult-enrollment/1 package a runner transfers with
    its request.  Every Apple field / provenance value is taken from the
    authenticated store record (which ran the ceremony), so the verifier binds
    the package to the exact ceremony — the operator never invents
    challenge/attestation/receipt values here."""
    need(record["trust_tier"] == TRUST_TIER_HARDWARE,
         "package_requires_hardware_record")
    need(record["apple_attestation_b64"] == attestation_b64,
         "package_attestation_mismatch")
    package = {
        "schema": protocol.ENROLLMENT_SCHEMA,
        "enrollment_class": protocol.ENROLLMENT_CLASS_PRODUCTION,
        "key_id_b64": record["key_id_b64"],
        "assertion_public_key": {
            "alg": "es256",
            "encoding": "x9.62-uncompressed",
            "key_b64": record["public_key_b64"],
        },
        "app_id": record["app_id"],
        "team_id": record["team_id"],
        "environment": record["environment"],
        "apple_attestation_b64": attestation_b64,
        "apple_receipt_b64": record["apple_receipt_b64"],
        "apple_receipt_status": record["apple_receipt_status"],
        "provenance": {
            "verified_by_core_sha256": record["core_sha256"],
            "verified_at_unix_s": record["enrolled_at_unix_s"],
            "attestation_challenge": record["attestation_challenge_b64"],
        },
    }
    schemas.validate_enrollment(package)
    return package


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------
def cmd_enroll(args):
    admitted = load_operator_policy(args.policy,
                                    allow_development=args.allow_development)
    secret = load_operator_secret(args.secret_file)
    attestation_raw = _read_regular_file(
        args.attestation, MAX_ATTESTATION_FILE_BYTES, "attestation")
    attestation_b64 = base64.b64encode(attestation_raw).decode()
    key_id_b64 = (args.key_id if args.key_id is not None
                  else _read_regular_file(
                      args.key_id_file, MAX_KEY_ID_FILE_BYTES,
                      "key_id_file").decode("utf-8").strip())
    challenge = _read_regular_file(
        args.challenge, MAX_CHALLENGE_FILE_BYTES, "challenge")
    policy = admitted["policy"]
    # OPCLI02: default enrollment uses trusted current wall-clock time for the
    # enrolled_at stamp when no --now is supplied.  The stamp NEVER affects
    # certificate-chain validation (the ceremony runs the pinned core with no
    # at_time in every case); defaulting it only prevents int(None) aborting.
    now_unix_s = args.now if args.now is not None else int(time.time())
    # REF02: a PRODUCTION enrollment MUST establish the authenticated replay
    # floor (so the key is not silently admitted at floor zero and a production
    # commit refuses a floorless key); --replay is mandatory for production.
    if policy.environment == "production":
        need(args.replay is not None,
             "production_enrollment_requires_replay_floor",
             "--replay is mandatory for a production enrollment")
    store = AuthenticatedEnrollmentStore(
        args.store, operator_secret=secret,
        hardware_root_sha256=admitted["hardware_root_der_sha256"])
    record = store.create_enrollment(
        attestation_b64, key_id_b64, challenge, policy.app_id,
        admitted["team_id"], policy.environment, policy, admitted["root_pem"],
        now_unix_s=now_unix_s)
    if policy.environment == "production":
        need(record["trust_tier"] == TRUST_TIER_HARDWARE,
             "production_enrollment_not_hardware_rooted",
             record["trust_tier"])
    package = enrollment_package_from_record(record, attestation_b64)
    if args.replay:
        ReplayStore(args.replay).set_enrollment_floor(
            record["key_id_b64"], int(args.min_counter))
    if args.out:
        with open(args.out, "wb") as fh:
            fh.write(canonical_bytes(package))
    summary = {
        "enrolled": True,
        "key_id_b64": record["key_id_b64"],
        "app_id": record["app_id"],
        "team_id": record["team_id"],
        "environment": record["environment"],
        "trust_tier": record["trust_tier"],
        "root_der_sha256": record["root_sha256"],
        "apple_receipt_status": record["apple_receipt_status"],
        "replay_floor_initialised": bool(args.replay),
        "ceremony_retained": sorted([
            "apple_attestation_b64", "attestation_challenge_b64",
            "apple_receipt_b64", "core_sha256"]),
        "enrollment_package": args.out,
    }
    print(json.dumps(summary, sort_keys=True))
    return 0


def cmd_issue_challenge(args):
    store = ReplayStore(args.replay)
    challenge = args.challenge or ("chal-" + secrets.token_urlsafe(24))
    store.issue_challenge(challenge, args.key_id, args.manifest_sha256,
                          args.ttl, now_unix_s=args.now)
    if args.out:
        with open(args.out, "w") as fh:
            fh.write(challenge)
    print(json.dumps({"issued": True, "challenge": challenge,
                      "key_id_b64": args.key_id,
                      "manifest_sha256": args.manifest_sha256,
                      "ttl_seconds": args.ttl}, sort_keys=True))
    return 0


def _load_bundle(bundle_dir):
    # Each transferred wire document is read through the bounded,
    # descriptor-safe reader with a per-role byte cap and the frozen
    # duplicate-key-rejecting JSON parser.
    return {
        "dir": bundle_dir,
        "request": _load_wire_json(
            os.path.join(bundle_dir, "request.json"),
            protocol.MAX_REQUEST_BYTES, "request.json"),
        "index": _load_wire_json(
            os.path.join(bundle_dir, "attachment-index.json"),
            MAX_INDEX_JSON_BYTES, "attachment-index.json"),
        "enrollment": _load_wire_json(
            os.path.join(bundle_dir, "enrollment.json"),
            MAX_ENROLLMENT_JSON_BYTES, "enrollment.json"),
        "attachments": os.path.join(bundle_dir, "attachments"),
    }


def _admitted_policy_binding(admitted):
    """The externally admitted CURRENT operator policy + root pin set that an
    authenticated enrollment record MUST satisfy at verification (OPCLI01)."""
    return {
        "policy": admitted["policy"],
        "team_id": admitted["team_id"],
        "hardware_root_der_sha256": admitted["hardware_root_der_sha256"],
    }


def cmd_verify(args):
    admitted = load_operator_policy(args.policy,
                                    allow_development=args.allow_development)
    secret = load_operator_secret(args.secret_file)
    signing_key = load_signing_key(args.signing_key_file)
    store = AuthenticatedEnrollmentStore(
        args.store, operator_secret=secret,
        hardware_root_sha256=admitted["hardware_root_der_sha256"])
    replay = ReplayStore(args.replay)
    bundle = _load_bundle(args.bundle)

    # REF02: confirm the CURRENT policy/root equals the resolved record's AND
    # the record's root is STILL a member of the current hardware-root pin set.
    key_id = bundle["request"]["key_id_b64"]
    record = store.resolve(key_id)
    need(record is not None, "verify_key_not_enrolled")
    assert_current_policy_matches_record(admitted, record)

    def extractor_factory():
        return SafeExtractor(args.extract_dir, tool_sha256=args.extractor_sha256)

    # mode is HARDCODED production — there is no fixture switch in this CLI.
    report_bytes = verify_bundle(
        bundle["request"], bundle["index"], bundle["attachments"],
        bundle["enrollment"], replay, signing_key, args.report_key_id,
        extractor_factory, mode="production", now_unix_s=args.now,
        enrollment_store=store,
        admitted_policy=_admitted_policy_binding(admitted))

    with open(args.out, "wb") as fh:
        fh.write(report_bytes)
    report = json.loads(report_bytes)
    print(json.dumps({"verified": True, "report": args.out,
                      "key_id_b64": report["subject"]["key_id_b64"],
                      "evidence_class": report["subject"]["evidence_class"],
                      "apple_receipt_status": report["apple"]["receipt_status"],
                      "apple_environment": report["apple"]["environment"]},
                     sort_keys=True))
    return 0


# ---------------------------------------------------------------------------
# relying-party check — independent expected context + retained evidence
# ---------------------------------------------------------------------------
def _load_check_evidence(evidence_dir):
    return retained_evidence.load_retained_check_evidence(evidence_dir)


def cmd_check(args):
    """Relying-party check: trust ONLY the INDEPENDENTLY admitted expected
    context (read from ``--context``, NOT reconstructed from the submitted
    bundle) plus the retained evidence; invoke ``checker.check`` and report
    EVIDENCE validity SEPARATELY from WORKLOAD task success.  Evidence validity
    is a cryptographic fact (a Refusal -> exit 2).  Task success is a distinct
    judgement: a valid report may faithfully attest a workload that did NOT meet
    the relying party's expected outcome — evidence-valid but task-failed
    (exit 3), never silently reported as success."""
    context = _load_wire_json(args.context, protocol.MAX_REQUEST_BYTES,
                              "checker_context")
    report_bytes = _read_regular_file(args.report, protocol.MAX_REQUEST_BYTES,
                                      "report")
    evidence = _load_check_evidence(args.evidence)
    evidence["launch_assertion_b64"] = args.launch_assertion_b64
    evidence["result_assertion_b64"] = args.result_assertion_b64

    result = checker_mod.check(report_bytes, context, evidence)
    summary = {
        "checked": result["checked"],
        "evidence_valid": True,
        "evidence_class": result["evidence_class"],
        "verification_level": result["verification_level"],
        "workload_outcome": result["workload_outcome"],
        "expected_workload_status": result["expected_workload_status"],
        "expected_exit_code": result["expected_exit_code"],
        "receipt_environment": result["receipt_environment"],
        "task_success": result["task_success"],
        "key_id_b64": result["subject"]["key_id_b64"],
    }
    print(json.dumps(summary, sort_keys=True))
    # Evidence is valid (no Refusal).  Exit 0 only when the attested workload
    # ALSO met the relying party's pinned expected outcome; otherwise exit 3 —
    # evidence-valid but task-failed, explicitly distinct from a refusal.
    return 0 if result["task_success"] else 3


def build_parser():
    parser = argparse.ArgumentParser(prog="operator-cli",
                                     description="dsmack production operator CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    e = sub.add_parser("enroll", help="run the authenticated attestation ceremony")
    e.add_argument("--policy", required=True)
    e.add_argument("--secret-file", required=True)
    e.add_argument("--store", required=True)
    e.add_argument("--attestation", required=True)
    g = e.add_mutually_exclusive_group(required=True)
    g.add_argument("--key-id")
    g.add_argument("--key-id-file")
    e.add_argument("--challenge", required=True, help="raw ceremony challenge file")
    e.add_argument("--out", help="write the transferable enrollment package here")
    e.add_argument("--replay", help="replay store; initialise the authenticated"
                                    " enrollment floor (MANDATORY for production)")
    e.add_argument("--min-counter", type=int, default=0,
                   help="authenticated minimum assertion counter floor")
    e.add_argument("--now", type=int, default=None,
                   help="stamp enrolled_at (does NOT affect cert validation;"
                        " defaults to trusted wall-clock time)")
    e.add_argument("--allow-development", action="store_true")
    e.set_defaults(func=cmd_enroll)

    i = sub.add_parser("issue-challenge", help="issue a fresh replay challenge")
    i.add_argument("--replay", required=True)
    i.add_argument("--key-id", required=True)
    i.add_argument("--manifest-sha256", required=True)
    i.add_argument("--ttl", type=int, required=True)
    i.add_argument("--challenge", default=None)
    i.add_argument("--out", default=None)
    i.add_argument("--now", type=int, default=None)
    i.set_defaults(func=cmd_issue_challenge)

    v = sub.add_parser("verify", help="verify a transferred production bundle")
    v.add_argument("--policy", required=True)
    v.add_argument("--secret-file", required=True)
    v.add_argument("--signing-key-file", required=True)
    v.add_argument("--report-key-id", required=True)
    v.add_argument("--store", required=True)
    v.add_argument("--replay", required=True)
    v.add_argument("--bundle", required=True)
    v.add_argument("--extract-dir", required=True)
    v.add_argument("--extractor-sha256", required=True)
    v.add_argument("--out", required=True)
    v.add_argument("--now", type=int, default=None)
    v.add_argument("--allow-development", action="store_true")
    v.set_defaults(func=cmd_verify)

    c = sub.add_parser("check", help="relying-party check of a report against "
                       "independently admitted expected context + retained "
                       "evidence (distinguishes evidence validity from task "
                       "success)")
    c.add_argument("--context", required=True,
                   help="independently admitted checker-context JSON")
    c.add_argument("--report", required=True, help="signed report bytes")
    c.add_argument("--evidence", required=True,
                   help="retained-evidence directory (manifest, statement.json,"
                        " result-envelope.json, enrollment.json, receipt.json,"
                        " console, result_image, outputs/streams/<s>,"
                        " outputs/artifacts/<name>, optional"
                        " runtime_envelope_private)")
    c.add_argument("--launch-assertion-b64", required=True)
    c.add_argument("--result-assertion-b64", required=True)
    c.set_defaults(func=cmd_check)
    return parser


def run(argv=None):
    """Parse and dispatch, letting a Refusal propagate (used by tests and by
    callers that want the structured refusal).  ``main`` wraps this with the
    fail-closed exit-code 2 for the command-line surface."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


def main(argv=None):
    try:
        return run(argv)
    except Refusal as exc:
        sys.stderr.write("REFUSED %s: %s\n" % (exc.code, exc))
        return 2


if __name__ == "__main__":
    sys.exit(main())
