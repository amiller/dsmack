#!/usr/bin/env python3
"""Independent-reference cross-check for the SWIFT04 envelope bounds (repair4 +
repair5). Feeds the EXACT reviewer counterexamples to the io-contract-reference
`runresult_ref.schemas.validate_envelope_body` (the normative Python verifier the
Swift producer must agree with) and asserts the reference's accept/refuse verdict.

The Swift producer (validateEnvelopeBodyV3 / parseRunResultV3) is driven by the
companion `swift/main.swift` golden suite on a Swift toolchain; this script is the
INDEPENDENT reference side of the same counterexamples, so a divergence between the
two is caught. In particular repair5's claim.alg length bound: the reference
`need_str(claim.alg, 128)` bounds Python `len()` (UNICODE CODE POINTS), so the
65-combining-cluster / 130-code-point alg is refused `str_too_long`, while the
128-code-point boundary is accepted.

Usage:  reference_crosscheck.py <path-to-io-contract-reference/candidate>
        (defaults to resolving ../../io-contract-reference/candidate relative here)
No network, no VM, no credentials. Read-only against the committed vectors.
"""
import copy
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def load_reference(cand_dir):
    sys.path.insert(0, cand_dir)
    from runresult_ref import schemas, errors  # noqa: E402
    return schemas, errors


def main():
    cand = sys.argv[1] if len(sys.argv) > 1 else os.path.realpath(
        os.path.join(HERE, "..", "..", "io-contract-reference", "candidate"))
    if not os.path.isdir(os.path.join(cand, "runresult_ref")):
        print("FAIL: reference package not found under %s" % cand, file=sys.stderr)
        sys.exit(2)
    schemas, errors = load_reference(cand)
    Refusal = errors.Refusal

    base = json.load(open(os.path.join(HERE, "vectors", "envelope.halted_console_complete.json")))

    failures = 0

    def expect_accept(label, obj):
        nonlocal failures
        try:
            schemas.validate_envelope_body(obj)
            print("PASS %s: reference accepted" % label)
        except Refusal as r:
            print("FAIL %s: reference refused (%s)" % (label, r)); failures += 1

    def expect_refuse(label, obj, code=None):
        nonlocal failures
        try:
            schemas.validate_envelope_body(obj)
            print("FAIL %s: reference ACCEPTED (should refuse)" % label); failures += 1
        except Refusal as r:
            if code is not None and getattr(r, "code", None) != code and code not in str(r):
                print("FAIL %s: refused but not %s (%s)" % (label, code, r)); failures += 1
            else:
                print("PASS %s: reference refused (%s)" % (label, r))

    def with_claim(alg):
        o = copy.deepcopy(base)
        o["runtime_input"]["commitment_claim"] = {
            "alg": alg,
            "inputs_sha256": "ab" * 32,
            "scope": {"k": "v"},
        }
        return o

    def with_lifecycle(**kw):
        o = copy.deepcopy(base)
        o["lifecycle"].update(kw)
        return o

    def with_launch(**kw):
        o = copy.deepcopy(base)
        o["launch"].update(kw)
        return o

    # --- baseline validity --------------------------------------------------
    expect_accept("valid_envelope", copy.deepcopy(base))
    expect_accept("valid_envelope_with_short_claim", with_claim("sha256"))

    # --- repair4 bounds (continuity) ---------------------------------------
    expect_refuse("negative_run_ms", with_lifecycle(run_ms=-1), "bad_int")
    expect_refuse("negative_counter", with_launch(counter=-1), "bad_int")
    expect_refuse("noncanonical_key_id", with_launch(key_id_b64="QR=="), "noncanonical_b64")
    import base64
    expect_refuse("key_id_over_32",
                  with_launch(key_id_b64=base64.b64encode(b"A" * 33).decode()), "b64_too_large")
    expect_refuse("claim_alg_nul", with_claim("sha\x00256"), "nul_in_str")

    # --- repair5 alg CODE-POINT length -------------------------------------
    # The reviewer's exact string: 65 × "é" (e + U+0301) = 65 clusters / 130 code
    # points. Python len() counts code points, so need_str refuses str_too_long.
    alg_overlong = "é" * 65
    alg_boundary = "é" * 64   # 128 code points
    assert len(alg_overlong) == 130 and len(alg_boundary) == 128
    print("  (combining alg) overlong len()=%d boundary len()=%d"
          % (len(alg_overlong), len(alg_boundary)))
    expect_refuse("alg_130_codepoints", with_claim(alg_overlong), "str_too_long")
    expect_refuse("alg_129_ascii", with_claim("a" * 129), "str_too_long")
    expect_accept("alg_128_codepoints_boundary", with_claim(alg_boundary))
    expect_accept("alg_128_ascii_boundary", with_claim("a" * 128))

    if failures:
        print("REFERENCE CROSS-CHECK: %d FAILURE(S)" % failures); sys.exit(1)
    print("REFERENCE CROSS-CHECK: ALL EXPECTED")


if __name__ == "__main__":
    main()
