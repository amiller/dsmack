"""R01 — authenticated source selection over the native run statement.

The launch assertion signs clientData =
  NUL-join(dsmack.appattest.assertion/4, M, L, challenge)
where L = sha256_obj([dsmack.receipt-evidence/4, receipt_evidence_body]).
Therefore the ONLY authenticated statement content is
statement.assertion.receipt_evidence_body (via L).  Every other statement
member is either a BOUND DUPLICATE — it must byte-equal a value recomputed
here from authenticated/retained bytes, or the whole statement is refused —
or an explicit DIAGNOSTIC that is never compared and never trusted
(protocol.STATEMENT_DIAGNOSTIC_KEYS).  All trusted comparisons downstream
use the authenticated body N exclusively.
"""
import hashlib

from . import protocol
from .errors import Refusal, need
from .frozen import (COMMITMENT_ALGS, execution_evidence_digest,
                     load_json_bytes, sha256_obj,
                     validate_commitment_scope_shape, _normalized_scope)
from .schemas import need_exact_keys, need_hex64, need_str


def launch_client_data(manifest_sha256: str, evidence_sha256: str,
                       challenge: str) -> bytes:
    """Native FOUR-part launch preimage (AssertionEvidence.swift shape; the
    counter binds via authenticatorData, not the client data).  The frozen
    five-part /4 assertion_payload is a DIFFERENT helper, untouched."""
    for value in (manifest_sha256, evidence_sha256):
        if not (isinstance(value, str) and len(value) == 64):
            raise Refusal("bad_preimage_hex", value)
    need(isinstance(challenge, str) and challenge and "\x00" not in challenge,
         "bad_preimage_challenge")
    return b"\x00".join([
        protocol.LAUNCH_ASSERTION_DOMAIN.encode(),
        manifest_sha256.encode("ascii"),
        evidence_sha256.encode("ascii"),
        challenge.encode("utf-8"),
    ])


def result_client_data(evidence_sha256: str, envelope_sha256: str,
                       challenge: str) -> bytes:
    """Result FOUR-part preimage: domain, L, E, challenge."""
    for value in (evidence_sha256, envelope_sha256):
        if not (isinstance(value, str) and len(value) == 64):
            raise Refusal("bad_preimage_hex", value)
    need(isinstance(challenge, str) and challenge and "\x00" not in challenge,
         "bad_preimage_challenge")
    return b"\x00".join([
        protocol.RESULT_ASSERTION_DOMAIN.encode(),
        evidence_sha256.encode("ascii"),
        envelope_sha256.encode("ascii"),
        challenge.encode("utf-8"),
    ])


def authenticate_statement(statement_bytes: bytes, manifest_bytes: bytes,
                           challenge: str, key_id_b64: str, result_envelope=None):
    """Parse statement.json; return (N, L) where N is the authenticated
    receipt-evidence body and L its /4 evidence digest.

    Enforces the R01 bound-duplicate policy: assertion.{manifest,evidence,
    client_data} digests, challenge, key_id, contract10_receipt_fragment
    base_vm/base_vm_launch and consumed must equal values recomputed from
    N / the exact manifest bytes / the request binding.  Diagnostic members
    are shape-checked as JSON but never compared.
    """
    need(len(statement_bytes) <= protocol.MAX_STATEMENT_B64, "statement_too_large")
    statement = load_json_bytes(statement_bytes, max_bytes=protocol.MAX_STATEMENT_B64)
    v3 = statement.get("schema") == "dsmack-general-launcher/v3-run-statement/1"
    keys = protocol.STATEMENT_KEYS | ({"result_assertion"} if v3 else set())
    need_exact_keys(statement, keys, "statement")
    need(statement["schema"] == protocol.STATEMENT_SCHEMA or v3, "bad_statement_schema")

    assertion = need_exact_keys(statement["assertion"],
                                protocol.STATEMENT_ASSERTION_KEYS,
                                "statement.assertion")
    body = need_exact_keys(assertion["receipt_evidence_body"],
                           protocol.EVIDENCE_BODY_KEYS,
                           "statement.assertion.receipt_evidence_body")

    # ---- the ONLY authenticated values: N and digests recomputed from it ----
    # R01/REF01: L = sha256_obj([EVIDENCE_DOMAIN, N]) is computed over the
    # EXACT admitted body.  The frozen execution_evidence_digest projects a
    # fixed 9-member body and UNCONDITIONALLY forces `attestation` to null.
    # Therefore a non-null `attestation` (or any member outside the frozen
    # projection) would change N while leaving L unchanged — a field
    # represented as authenticated that is not in fact bound.  We require the
    # native mapper's null members to BE null so that L is a pure injective
    # function of the exact admitted N and no authenticated field can be
    # mutated without changing L.
    need(body["attestation"] is None, "native_attestation_not_null")
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    evidence_sha256 = execution_evidence_digest(body)
    # Equality to the frozen projection: recomputing the digest from a body
    # rebuilt out of exactly the admitted members must reproduce L; any member
    # the frozen projection ignores is therefore proven absent/null here.
    _projection = {k: body[k] for k in protocol.EVIDENCE_BODY_KEYS}
    need(execution_evidence_digest(_projection) == evidence_sha256,
         "native_body_projection_mismatch")
    need(body["manifest_sha256"] == manifest_sha256,
         "authenticated_body_manifest_mismatch")

    # ---- bound duplicates (must equal recomputed values; else refusal) ----
    need(assertion["assertion_domain"] == protocol.LAUNCH_ASSERTION_DOMAIN,
         "duplicate_mismatch", "assertion.assertion_domain")
    need(assertion["evidence_domain"] == protocol.EVIDENCE_DOMAIN,
         "duplicate_mismatch", "assertion.evidence_domain")
    need(need_hex64(assertion["manifest_sha256"], "assertion.manifest_sha256")
         == manifest_sha256, "duplicate_mismatch", "assertion.manifest_sha256")
    need(need_hex64(assertion["evidence_sha256"], "assertion.evidence_sha256")
         == evidence_sha256, "duplicate_mismatch", "assertion.evidence_sha256")
    client_data = launch_client_data(manifest_sha256, evidence_sha256, challenge)
    need(assertion["client_data_sha256"]
         == hashlib.sha256(client_data).hexdigest(),
         "duplicate_mismatch", "assertion.client_data_sha256")
    need_str(statement["challenge"], "statement.challenge",
             protocol.MAX_CHALLENGE_CHARS)
    need(statement["challenge"] == challenge,
         "duplicate_mismatch", "statement.challenge")
    need(statement["key_id"] == key_id_b64,
         "duplicate_mismatch", "statement.key_id")

    fragment = statement["contract10_receipt_fragment"]
    need(isinstance(fragment, dict), "bad_fragment")
    need(fragment.get("base_vm") == body["base_vm"],
         "duplicate_mismatch", "contract10_receipt_fragment.base_vm")
    need(fragment.get("base_vm_launch") == body["base_vm_launch"],
         "duplicate_mismatch", "contract10_receipt_fragment.base_vm_launch")
    need(statement["consumed"] == body["observed"],
         "duplicate_mismatch", "consumed")
    identity = statement["identity"]
    need(isinstance(identity, dict), "bad_identity")
    need(identity.get("compose_manifest_sha256") == manifest_sha256,
         "duplicate_mismatch", "identity.compose_manifest_sha256")
    # Remaining members (protocol.STATEMENT_DIAGNOSTIC_KEYS) are diagnostics:
    # present, JSON-shaped, but never compared and never evidence.
    if "result_assertion" in statement:
        # The signed app emits these bound duplicates. Accept them only when
        # every field agrees with the original envelope and recomputed preimage.
        need(result_envelope is not None, "result_assertion_envelope_required")
        from .schemas import validate_envelope_body
        validate_envelope_body(result_envelope)
        actual = need_exact_keys(statement["result_assertion"], {
            "result_assertion_domain", "envelope_domain", "envelope_schema",
            "launch_evidence_sha256", "envelope_sha256", "result_client_data_sha256"},
            "statement.result_assertion")
        envelope_sha256 = envelope_digest(result_envelope)
        expected = {
            "result_assertion_domain": protocol.RESULT_ASSERTION_DOMAIN,
            "envelope_domain": protocol.ENVELOPE_DOMAIN,
            "envelope_schema": protocol.ENVELOPE_SCHEMA,
            "launch_evidence_sha256": evidence_sha256,
            "envelope_sha256": envelope_sha256,
            "result_client_data_sha256": hashlib.sha256(result_client_data(
                evidence_sha256, envelope_sha256, challenge)).hexdigest(),
        }
        for name, value in expected.items():
            need(type(actual[name]) is str and actual[name] == value,
                 "duplicate_mismatch", "result_assertion." + name)
    return body, evidence_sha256


def compare_shared_facts(guest_receipt: dict, native_body: dict):
    """R01 shared-fact join replacement: exact equality of the ten base_vm
    fields, four admission fields and complete VM boot tuple between the
    ORIGINAL guest receipt and AUTHENTICATED native body. Guest component
    identities are recorded claims; live cmdline/root validation belongs to the
    guest producer. No claims are overwritten. linux-test is non-VM engineering
    evidence and cannot establish authenticated boot provenance."""
    need(isinstance(guest_receipt.get("base_vm"), dict), "guest_base_vm_missing")
    native_base = native_body.get("base_vm")
    need(isinstance(native_base, dict), "native_base_vm_missing")
    need(set(native_base.keys()) == set(protocol.SHARED_BASE_VM_FIELDS),
         "native_base_vm_keys")
    for field in protocol.SHARED_BASE_VM_FIELDS:
        need(type(guest_receipt["base_vm"].get(field)) is type(native_base.get(field))
             and guest_receipt["base_vm"].get(field) == native_base.get(field),
             "shared_base_vm_mismatch", field)
    guest_adm = (guest_receipt.get("base_vm_launch") or {}).get("admission")
    native_adm = (native_body.get("base_vm_launch") or {}).get("admission")
    need(isinstance(guest_adm, dict), "guest_admission_missing")
    need(isinstance(native_adm, dict), "native_admission_missing")
    need(set(native_adm) == set(protocol.SHARED_ADMISSION_FIELDS), "native_admission_keys")
    for field in protocol.SHARED_ADMISSION_FIELDS:
        need(type(guest_adm.get(field)) is type(native_adm.get(field))
             and guest_adm.get(field) == native_adm.get(field),
             "shared_admission_mismatch", field)
    need(guest_receipt.get("manifest_sha256") == native_body.get("manifest_sha256"),
         "shared_manifest_mismatch")
    if (guest_receipt.get("environment") != "linux-test"
            or guest_receipt.get("base_vm_launch", {}).get("boot") is not None):
        compare_boot_facts(guest_receipt, native_body)


BOOT_KEYS = frozenset(("loader_mode", "kernel_sha256", "initrd_sha256",
                       "rootfs_sha256", "metadata_sha256", "cmdline",
                       "cmdline_sha256", "verity"))
VERITY_KEYS = frozenset(("block_bytes", "data_bytes", "hash_offset_bytes",
                         "root_hash", "salt_hex", "total_bytes"))


def compare_boot_facts(guest_receipt, native_body):
    """Portable external provenance join, shared by verifier and checker.

    Strict original tuples, exact UTF8 cmdline, no normalization. Frozen receipt
    validation still checks admitted geometry; this join also validates native
    types so Python bool/int equality cannot admit malformed authenticated facts.
    """
    boots = []
    for label, document in (("guest", guest_receipt), ("native", native_body)):
        launch = document.get("base_vm_launch")
        need(isinstance(launch, dict), "boot_launch_missing", label)
        boot = launch.get("boot")
        need(isinstance(boot, dict) and set(boot) == BOOT_KEYS,
             "boot_shape", label)
        need(type(boot["loader_mode"]) is str and
             boot["loader_mode"] in ("held-fd", "owned-copy"), "boot_loader_mode", label)
        for field in ("kernel_sha256", "initrd_sha256", "rootfs_sha256",
                      "metadata_sha256", "cmdline_sha256"):
            need_hex64(boot[field], label + ".boot." + field)
        cmdline = boot["cmdline"]
        need(type(cmdline) is str, "boot_cmdline_type", label)
        try:
            digest = hashlib.sha256(cmdline.encode("utf-8")).hexdigest()
        except UnicodeError as exc:
            raise Refusal("boot_cmdline_encoding", label) from exc
        need(digest == boot["cmdline_sha256"], "boot_cmdline_digest", label)
        verity = boot["verity"]
        need(isinstance(verity, dict) and set(verity) == VERITY_KEYS,
             "boot_verity_shape", label)
        for field in ("block_bytes", "data_bytes", "hash_offset_bytes", "total_bytes"):
            need(type(verity[field]) is int and verity[field] > 0,
                 "boot_verity_integer", label + "." + field)
        need_hex64(verity["root_hash"], label + ".verity.root_hash")
        salt = verity["salt_hex"]
        need(type(salt) is str and len(salt) % 2 == 0 and len(salt) <= 512
             and all(c in "0123456789abcdef" for c in salt), "boot_verity_salt", label)
        boots.append(boot)
    for field in sorted(BOOT_KEYS - {"verity"}):
        need(boots[0][field] == boots[1][field], "shared_boot_mismatch", field)
    for field in sorted(VERITY_KEYS):
        need(boots[0]["verity"][field] == boots[1]["verity"][field],
             "shared_verity_mismatch", field)



def reconcile_commitment_status(envelope: dict, receipt: dict,
                                private_envelope_present: bool) -> str:
    """REF03/REF07 single source of truth for the runtime-input commitment
    status.  Used by BOTH the verifier (to PRODUCE subject.commitment_status)
    and the independent checker (to RECONSTRUCT it from the retained envelope +
    receipt and compare against the report's claim).  Any malformed scope or a
    claim that does not match the receipt's recorded commitment REFUSES — so a
    report that claims ``bound-to-validated-envelope`` without a matching
    receipt commitment cannot be confirmed.

    Returns one of protocol.COMMITMENT_STATUSES.
    """
    claim = envelope["runtime_input"]["commitment_claim"]
    receipt_commitment = receipt.get("runtime_inputs_commitment")
    if claim is None:
        return ("recorded-unchecked"
                if receipt_commitment is not None else "absent")
    need(claim["alg"] in COMMITMENT_ALGS, "claim_alg_unknown")
    try:
        ok, _inc, _env, _slots = validate_commitment_scope_shape(claim["scope"])
    except Exception as exc:
        raise Refusal("claim_scope_invalid", str(exc)) from exc
    need(ok is True, "claim_scope_invalid", "scope shape rejected")
    need(receipt_commitment is not None, "claim_without_receipt_commitment")
    try:
        r_ok, _ri, _re, _rs = validate_commitment_scope_shape(
            receipt_commitment.get("scope"))
    except Exception as exc:
        raise Refusal("receipt_scope_invalid", str(exc)) from exc
    need(r_ok is True, "receipt_scope_invalid", "receipt scope rejected")
    need(receipt_commitment.get("alg") == claim["alg"]
         and receipt_commitment.get("inputs_sha256") == claim["inputs_sha256"]
         and _normalized_scope(receipt_commitment.get("scope"))
         == _normalized_scope(claim["scope"]),
         "claim_receipt_mismatch")
    return ("bound-to-validated-envelope"
            if private_envelope_present else "recorded-unchecked")


def envelope_digest(envelope_body: dict) -> str:
    return sha256_obj([protocol.ENVELOPE_DOMAIN, envelope_body])


def pair_evidence_digest(pair_evidence: dict) -> str:
    need_exact_keys(pair_evidence, protocol.PAIR_EVIDENCE_KEYS, "pair_evidence")
    return sha256_obj([protocol.PAIR_DOMAIN, pair_evidence])


def enrollment_digest(enrollment_record: dict) -> str:
    return sha256_obj([protocol.ENROLLMENT_SCHEMA, enrollment_record])
