#!/usr/bin/env python3
"""Consumer ADAPTER + VERIFIER for the v3 run-result producer (SWIFT04 repair2).

The rejected repair1 review (SWIFT04) said: "The new statement schema/key set
also lacks a supplied consumer adapter." This module is that adapter. It bridges
the launcher's producer artifacts (app-src/Sources/mar: the v3 run-statement, the
run-result envelope, the two assertion preimages) to the io-contract-reference
verification primitives, and proves the signed bytes the producer emits satisfy
the reference contract exactly:

  * ENVELOPE digest E = sha256_obj([ENVELOPE_DOMAIN, envelope])  (statement.py:146)
  * RESULT preimage  = NUL-join(RESULT_ASSERTION_DOMAIN, L, E, challenge)
                       (statement.result_client_data; L, NOT M)
  * envelope.status == "halted"                                   (schemas.py:167)
  * envelope shape   via schemas.validate_envelope_body
  * launch binding   via statement.authenticate_statement (after the v3→v2
                       statement adaptation), returning (N, L)
  * envelope.launch  == {L, M, challenge, key_id_b64, launch_counter}
                       (verifier.py step 4)

It imports the frozen reference read-only (through the hash-gated frozen.py). It
does NOT re-implement canonicalization or digests — the whole point is that the
SAME bytes the reference verifier would hash are hashed here.

Run: `python3 consumer.py`  (verifies every committed golden vector).
"""
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REF = "/data/amiller/dsmack/attested-runner-20261020/io-contract-reference/candidate"
if REF not in sys.path:
    sys.path.insert(0, REF)

from runresult_ref import protocol, schemas, statement as S      # noqa: E402
from runresult_ref.errors import Refusal, need                   # noqa: E402
from runresult_ref.frozen import (                                # noqa: E402
    canonical_bytes, load_json_bytes, sha256_obj, execution_evidence_digest)

VECTORS = os.path.join(HERE, "vectors")


# --------------------------------------------------------------------------
# The ADAPTER: v3 run-statement -> reference v2-run-statement shape.
# --------------------------------------------------------------------------
V3_STATEMENT_SCHEMA = "dsmack-general-launcher/v3-run-statement/1"
# Keys the v3 statement adds on top of the reference STATEMENT_KEYS.
V3_EXTRA_KEYS = frozenset({"result_assertion"})


def adapt_v3_statement_to_reference(v3_bytes):
    """Normalize the launcher's v3 statement bytes into a reference
    v2-run-statement document (STATEMENT_KEYS / STATEMENT_ASSERTION_KEYS) whose
    launch binding statement.authenticate_statement can authenticate.

    The ONLY structural differences are (1) the schema string and (2) the extra
    `result_assertion` member — the launch `assertion` sub-object and every
    bound-duplicate member are already the reference shape. The adapter removes
    the extra member and rewrites the schema; it carries NO authority of its own
    (it only re-serializes), and it returns BOTH the reference statement bytes and
    the extracted result_assertion so the caller can bind the result half too."""
    v3 = load_json_bytes(v3_bytes, "v3_statement", max_bytes=protocol.MAX_STATEMENT_B64)
    need(v3.get("schema") == V3_STATEMENT_SCHEMA, "adapter_bad_v3_schema")
    got = set(v3.keys())
    need(got == set(protocol.STATEMENT_KEYS) | V3_EXTRA_KEYS,
         "adapter_unexpected_v3_keyset",
         "missing=%s unknown=%s" % (sorted((set(protocol.STATEMENT_KEYS) | V3_EXTRA_KEYS) - got),
                                    sorted(got - (set(protocol.STATEMENT_KEYS) | V3_EXTRA_KEYS))))
    result_assertion = v3["result_assertion"]
    ref = {k: v3[k] for k in protocol.STATEMENT_KEYS}
    ref["schema"] = protocol.STATEMENT_SCHEMA          # v3 -> reference v2 schema
    return canonical_bytes(ref), result_assertion


# --------------------------------------------------------------------------
# The VERIFIER half: bind the launch statement, then the envelope + result.
# --------------------------------------------------------------------------
def consume(v3_statement_bytes, envelope_bytes, manifest_bytes,
            challenge, key_id_b64, launch_counter):
    """Returns a dict of the independently-recomputed digests on success;
    raises Refusal on any contract violation."""
    # 1. authenticate the LAUNCH statement through the reference (R01).
    ref_stmt_bytes, result_assertion = adapt_v3_statement_to_reference(v3_statement_bytes)
    N, L = S.authenticate_statement(ref_stmt_bytes, manifest_bytes, challenge, key_id_b64)
    M = hashlib.sha256(manifest_bytes).hexdigest()

    # 2. envelope: exact canonical bytes, §5.3 shape, status halted, E recomputed.
    envelope = load_json_bytes(envelope_bytes, "envelope", max_bytes=protocol.MAX_ENVELOPE_B64)
    need(canonical_bytes(envelope) == envelope_bytes, "envelope_not_canonical")
    schemas.validate_envelope_body(envelope)           # includes status=="halted"
    E = sha256_obj([protocol.ENVELOPE_DOMAIN, envelope])

    # 3. envelope.launch must equal {L, M, challenge, key_id, launch_counter}
    #    (verifier.py step 4).
    launch = envelope["launch"]
    need(launch["evidence_sha256"] == L, "envelope_launch_L_mismatch")
    need(launch["manifest_sha256"] == M, "envelope_launch_M_mismatch")
    need(launch["challenge"] == challenge, "envelope_launch_challenge_mismatch")
    need(launch["key_id_b64"] == key_id_b64, "envelope_launch_keyid_mismatch")
    need(launch["counter"] == launch_counter, "envelope_launch_counter_mismatch")

    # 4. result preimage: NUL-join(RESULT_ASSERTION_DOMAIN, L, E, challenge).
    result_cd = S.result_client_data(L, E, challenge)
    launch_cd = S.launch_client_data(M, L, challenge)

    # 5. bind the producer's own result_assertion diagnostic to the recomputed
    #    values (it must have signed L and E, not M / a bare envelope).
    need(result_assertion["result_assertion_domain"] == protocol.RESULT_ASSERTION_DOMAIN,
         "result_assertion_bad_domain")
    need(result_assertion["envelope_domain"] == protocol.ENVELOPE_DOMAIN,
         "result_assertion_bad_envelope_domain")
    need(result_assertion["launch_evidence_sha256"] == L,
         "result_assertion_L_mismatch")              # repair1 recorded M here
    need(result_assertion["envelope_sha256"] == E,
         "result_assertion_E_mismatch")              # repair1 E was over the BARE envelope
    need(result_assertion["result_client_data_sha256"] == hashlib.sha256(result_cd).hexdigest(),
         "result_assertion_preimage_mismatch")
    return {
        "M": M, "L": L, "E": E,
        "envelope_canonical_sha256": hashlib.sha256(envelope_bytes).hexdigest(),
        "launch_client_data_sha256": hashlib.sha256(launch_cd).hexdigest(),
        "result_client_data_sha256": hashlib.sha256(result_cd).hexdigest(),
        "status": envelope["status"],
    }


# --------------------------------------------------------------------------
# Golden-vector driver: verify every committed case against the reference.
# --------------------------------------------------------------------------
def verify_golden():
    index = json.load(open(os.path.join(VECTORS, "INDEX.json")))
    manifest_bytes = open(os.path.join(VECTORS, index["manifest_file"]), "rb").read()
    results = []
    for name in index["cases"]:
        case = json.load(open(os.path.join(VECTORS, "case.%s.json" % name)))
        envelope_bytes = open(os.path.join(VECTORS, "envelope.%s.json" % name), "rb").read()
        stmt_bytes = open(os.path.join(VECTORS, "statement.%s.json" % name), "rb").read()
        inp = case["inputs"]
        got = consume(stmt_bytes, envelope_bytes, manifest_bytes,
                      inp["challenge"], inp["key_id_b64"], inp["launch_counter"])
        exp = case["expected"]
        # Every recomputed digest must equal the committed golden expectation.
        checks = {
            "M": got["M"] == inp["manifest_sha256_M"],
            "L": got["L"] == inp["launch_evidence_sha256_L"],
            "E": got["E"] == exp["envelope_digest_E"],
            "envelope_canonical_sha256": got["envelope_canonical_sha256"] == exp["envelope_canonical_sha256"],
            "launch_client_data_sha256": got["launch_client_data_sha256"] == exp["launch_client_data_sha256"],
            "result_client_data_sha256": got["result_client_data_sha256"] == exp["result_client_data_sha256"],
            "status_halted": got["status"] == "halted",
        }
        ok = all(checks.values())
        results.append((name, ok, checks))
    return results


# --------------------------------------------------------------------------
# Negative tests: the repair1 defects MUST be refused by the reference.
# --------------------------------------------------------------------------
def verify_repair1_defects_rejected():
    """Prove the exact repair1 mistakes are refused, so this consumer actually
    discriminates the fix (not a vacuous pass)."""
    index = json.load(open(os.path.join(VECTORS, "INDEX.json")))
    manifest_bytes = open(os.path.join(VECTORS, index["manifest_file"]), "rb").read()
    name = index["cases"][0]
    case = json.load(open(os.path.join(VECTORS, "case.%s.json" % name)))
    envelope_bytes = open(os.path.join(VECTORS, "envelope.%s.json" % name), "rb").read()
    stmt_bytes = open(os.path.join(VECTORS, "statement.%s.json" % name), "rb").read()
    inp = case["inputs"]
    envelope = load_json_bytes(envelope_bytes, "e", max_bytes=protocol.MAX_ENVELOPE_B64)
    M = inp["manifest_sha256_M"]
    L = inp["launch_evidence_sha256_L"]
    E = sha256_obj([protocol.ENVELOPE_DOMAIN, envelope])
    outcomes = []

    # (a) status "finalized" (repair1) -> validate_envelope_body refuses.
    bad = dict(envelope); bad["status"] = "finalized"
    try:
        schemas.validate_envelope_body(bad); outcomes.append(("status_finalized_rejected", False))
    except Refusal as r:
        outcomes.append(("status_finalized_rejected", r.code == "bad_envelope_status"))

    # (b) E over the BARE envelope (repair1) != domain-separated E.
    bare = hashlib.sha256(envelope_bytes).hexdigest()
    outcomes.append(("bare_envelope_E_differs", bare != E))

    # (c) result preimage with M (repair1) != preimage with L.
    pre_M = b"\x00".join([protocol.RESULT_ASSERTION_DOMAIN.encode(), M.encode(), E.encode(),
                          inp["challenge"].encode()])
    pre_L = S.result_client_data(L, E, inp["challenge"])
    outcomes.append(("result_preimage_M_differs_from_L", pre_M != pre_L))

    # (d) adapter must refuse a statement whose result_assertion bound M not L.
    v3 = load_json_bytes(stmt_bytes, "s", max_bytes=protocol.MAX_STATEMENT_B64)
    v3bad = json.loads(json.dumps(v3))
    v3bad["result_assertion"]["launch_evidence_sha256"] = M      # the repair1 bug
    try:
        consume(canonical_bytes(v3bad), envelope_bytes, manifest_bytes,
                inp["challenge"], inp["key_id_b64"], inp["launch_counter"])
        outcomes.append(("consumer_rejects_M_in_result_assertion", False))
    except Refusal as r:
        outcomes.append(("consumer_rejects_M_in_result_assertion",
                         r.code == "result_assertion_L_mismatch"))
    return outcomes


def verify_swift04_producer_bounds_rejected():
    """SWIFT04 repair3: the exact producer-validation gaps the review named —
    'accepts an arbitrary result role, nonmatching final/template sizes and string
    commitment_claim values, while the reference requires vdd, equal sizes and a
    structured claim or null' — are REFUSED by the reference validate_envelope_body.
    This is the Linux-side counterpart to the Swift parseRunResultV3 negative suite:
    it proves the mutations are genuine contract violations (not just rejected by
    our own parser). The baseline repair2 parser ACCEPTED all three and would have
    composed these exact envelopes."""
    index = json.load(open(os.path.join(VECTORS, "INDEX.json")))
    name = index["cases"][0]
    envelope_bytes = open(os.path.join(VECTORS, "envelope.%s.json" % name), "rb").read()
    base = load_json_bytes(envelope_bytes, "e", max_bytes=protocol.MAX_ENVELOPE_B64)
    outcomes = []

    def rejects(label, mutate, expect_code):
        bad = json.loads(json.dumps(base))
        mutate(bad)
        try:
            schemas.validate_envelope_body(bad)
            outcomes.append((label, False))
        except Refusal as r:
            outcomes.append((label, r.code == expect_code))

    # (a) arbitrary result role (repair2 accepted any non-empty role).
    def _role(b): b["result_disk"]["role"] = "scratch"
    rejects("ref_rejects_role_not_vdd", _role, "bad_result_disk_role")
    # (b) result bytes != template bytes (repair2 never compared them).
    def _size(b): b["result_disk"]["bytes"] = b["result_disk"]["template_bytes"] + 512
    rejects("ref_rejects_size_mismatch", _size, "result_disk_size_mismatch")
    # (c) commitment_claim as a bare string (repair2 accepted any string).
    def _claim(b): b["runtime_input"]["commitment_claim"] = "opaque-string"
    rejects("ref_rejects_string_commitment_claim", _claim, "not_object")
    return outcomes


if __name__ == "__main__":
    print("== golden vectors (producer bytes satisfy the reference) ==")
    all_ok = True
    for name, ok, checks in verify_golden():
        print(" ", "PASS" if ok else "FAIL", name)
        if not ok:
            all_ok = False
            for k, v in checks.items():
                if not v:
                    print("      mismatch:", k)
    print("== repair1 defects are refused by the reference ==")
    for label, ok in verify_repair1_defects_rejected():
        print(" ", "PASS" if ok else "FAIL", label)
        all_ok = all_ok and ok
    print("== SWIFT04 producer-bounds gaps are refused by the reference ==")
    for label, ok in verify_swift04_producer_bounds_rejected():
        print(" ", "PASS" if ok else "FAIL", label)
        all_ok = all_ok and ok
    print("RESULT:", "ALL PASS" if all_ok else "FAILURES PRESENT")
    sys.exit(0 if all_ok else 1)
