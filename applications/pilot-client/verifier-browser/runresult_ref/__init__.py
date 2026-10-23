"""runresult_ref — executable reference contract for the dsmack run-result
composition protocol (io-contract-reference lane, 2026-10-21).

Development prototype under the output-continuity-design-review-repair1
gate (R01–R08).  NOT integration approval; native execution, real Apple
hardware/credentials and image rebuilds remain later gates.
"""
__all__ = [
    "protocol", "frozen", "errors", "schemas", "statement", "replay",
    "private_transport", "extraction", "finalize", "lifecycle",
    "verifier", "checker", "testkeys", "cborenc",
]
