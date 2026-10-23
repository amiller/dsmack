"""The contract-defined request->report ADAPTER for dsmack.appattest-verifier/2 (U03).

TWO DISTINCT ARTIFACTS (the separation the freeze must state coherently):

- The EXISTING Apple App Attest verification core (the production
  implementation, trusted-verifier-inputs/verifier/core.py, pinned by SHA256
  13214b3711f2c69e145a11eee22c3f1c522d7d63f535bcf1ba5f5f9804ea8cb5) performs
  the actual Apple cryptography: attestation certificate chain against Apple
  roots, the nonce extension binding, the AAGUID environment check, and the
  P-256 (ES256) assertion signature. It exposes PLAIN FUNCTIONS
  (verify_attestation / verify_assertion) over already-decoded evidence -- it
  is NOT a subprocess, it does not speak this contract's request document,
  and it does not produce or sign verifier reports.

- The report ADAPTER specified here is the contract-side boundary between
  that core and relying parties. It consumes the EXACT frozen request
  document (below), RECONSTRUCTS the complete attestation object from the
  request alone, RECOMPUTES subject.attestation_sha256 over that preimage
  (canonical SHA256 of the full object INCLUDING generated_at_unix_s), and
  derives every other report binding from the request. A caller-supplied
  digest is NEVER accepted: the request vocabulary has no attestation_sha256
  member, and an unknown request key is a refusal. The Apple cryptography is
  delegated through the REQUIRED ``apple_core`` callable -- the deployment's
  binding of the existing core (it resolves the enrolled P-256 key from its
  authenticated enrollment store and runs core.verify_assertion over the
  request's assertion for these bindings); a core refusal produces NO report.
  Only after the core affirms does the adapter sign the report with the
  deployment's long-term ed25519 key through the REQUIRED ``report_signer``
  callable.

FROZEN REQUEST ABI (verifier_request_version 2, one line, canonical JSON;
this is the U03 completion of the former version-1 document, which omitted
``generated_at_unix_s`` and therefore could not support recomputation of the
required attestation digest -- two attestations differing only in that
timestamp produced identical v1 requests while requiring different digests):

  {"assertion_b64": "<standard base64 of the App Attest assertion CBOR>",
   "attestation_receipt_b64": "<standard base64 of the opaque Apple receipt>",
   "challenge": "<the exact challenge bound in the assertion payload>",
   "counter": <non-negative integer assertion counter>,
   "evidence_sha256": "<64 hex>",
   "generated_at_unix_s": <non-negative integer>,
   "key_id_b64": "<standard base64 of the 32-byte App Attest key identifier>",
   "manifest_sha256": "<64 hex>",
   "verifier_request_version": 2}

The EXACT key set is fixed: extra keys (including any caller-provided
digest) and missing keys are refusals. These fields are exactly the receipt
attestation object's members (``provider`` is the fixed constant
"apple-appattest" and is not carried) plus the two bindings the verifier
must re-derive (manifest_sha256, evidence_sha256). With version 2 the
request therefore carries the COMPLETE attestation preimage:
``attestation_from_request`` reproduces the receipt's attestation object
byte-for-byte under canonical serialization, so the adapter's recomputed
``subject.attestation_sha256`` equals the relying party's
``sha256_obj(receipt["attestation"])`` for ITS OWN request and for no other
preimage (cross-substitution of any carried member -- including
generated_at_unix_s -- binds a different digest and fails the relying
party's binding check).

``evidence_sha256`` is carried, not recomputed, BY DESIGN: the evidence
preimage substitutes ``attestation: null`` and binds the receipt's execution
body (base_vm, observed, outputs, ...), which the request deliberately does
not carry. The relying party computes it over its full receipt; the App
Attest assertion signs it; the adapter binds it verbatim.

SUBPROCESS CONTRACT (the deployment adapter shape): one-shot invocation --
the request document is ONE line of canonical JSON on stdin; the report is
ONE line of canonical JSON on stdout; exit 0 means a report was produced,
any nonzero exit means the adapter refused and NO report exists (nothing a
file says may be trusted after a refusal).
"""

from .attestation import (
    ACCEPTED_APP_ATTEST_ENVIRONMENTS,
    ASSERTION_DOMAIN,
    EVIDENCE_DOMAIN,
    VERIFIER_REPORT_VERSION,
    AttestationError,
    report_body,
    validate_verifier_report,
)
from .canonical import canonical_bytes, load_json_bytes, sha256_obj
from .manifest import HEX64_RE

VERIFIER_REQUEST_VERSION = 2

#: The EXACT request vocabulary (U03): the complete attestation preimage
#: (assertion, Apple receipt bytes, challenge, counter, generated_at_unix_s,
#: key identifier -- provider is the fixed constant) plus the bindings the
#: verifier must carry (manifest_sha256, evidence_sha256). There is NO
#: caller-supplied attestation_sha256 member and there never will be: the
#: adapter recomputes it.
VERIFIER_REQUEST_KEYS = {
    "assertion_b64",
    "attestation_receipt_b64",
    "challenge",
    "counter",
    "evidence_sha256",
    "generated_at_unix_s",
    "key_id_b64",
    "manifest_sha256",
    "verifier_request_version",
}

#: The attestation provider is a contract constant, not a request field:
#: receipt validation admits exactly this provider.
ATTESTATION_PROVIDER = "apple-appattest"

#: Bounded request member sizes (fail closed before any decode work).
MAX_REQUEST_BYTES = 1 << 20
MAX_B64_MEMBER_CHARS = 1 << 16
MAX_CHALLENGE_CHARS = 4096


def _non_negative_int(value, what):
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise AttestationError("verifier request.%s must be a non-negative integer" % what)


def _bounded_b64(value, what):
    if not isinstance(value, str) or not value or len(value) > MAX_B64_MEMBER_CHARS:
        raise AttestationError("verifier request.%s must be a non-empty bounded base64 string" % what)


def parse_verifier_request(raw_bytes):
    """Parse and fully validate the frozen request document.

    Accepts ONLY the exact version-2 vocabulary under the contract's strict
    canonical-JSON profile (bounded read, duplicate keys rejected, no
    floats). Any deviation -- missing key, UNKNOWN key (including any
    caller-supplied digest), wrong version, wrong type -- raises
    AttestationError: the adapter refuses, it never guesses.
    """
    request = load_json_bytes(raw_bytes, "verifier request", max_bytes=MAX_REQUEST_BYTES)
    if not isinstance(request, dict):
        raise AttestationError("verifier request must be a JSON object")
    unknown = set(request) - VERIFIER_REQUEST_KEYS
    if unknown:
        # E08 hygiene: caller-controlled key text is withheld.
        raise AttestationError(
            "verifier request has unsupported keys (key text withheld); the exact request "
            "vocabulary is %s (a caller-supplied digest is never part of it -- the adapter "
            "recomputes attestation_sha256 from the carried preimage)" % sorted(VERIFIER_REQUEST_KEYS)
        )
    missing = VERIFIER_REQUEST_KEYS - set(request)
    if missing:
        raise AttestationError("verifier request is missing keys: %s" % sorted(missing))
    if request["verifier_request_version"] != VERIFIER_REQUEST_VERSION:
        raise AttestationError(
            "verifier request.verifier_request_version must be %d (the version that carries the "
            "complete attestation preimage)" % VERIFIER_REQUEST_VERSION
        )
    for field in ("assertion_b64", "attestation_receipt_b64", "key_id_b64"):
        _bounded_b64(request[field], field)
    if not isinstance(request["challenge"], str) or not request["challenge"] or "\x00" in request["challenge"]:
        raise AttestationError("verifier request.challenge must be a non-empty string without NUL")
    if len(request["challenge"]) > MAX_CHALLENGE_CHARS:
        raise AttestationError("verifier request.challenge exceeds the bounded length")
    for field in ("evidence_sha256", "manifest_sha256"):
        if not (isinstance(request[field], str) and HEX64_RE.match(request[field])):
            raise AttestationError("verifier request.%s must be 64 lowercase hex" % field)
    for field in ("counter", "generated_at_unix_s"):
        _non_negative_int(request[field], field)
    return request


def attestation_from_request(request):
    """Reconstruct the COMPLETE receipt attestation object from the request.

    The request carries every attestation member except ``provider`` (the
    fixed constant), so canonical serialization of the reconstructed object
    is byte-identical to the receipt's ``attestation`` object the request was
    derived from -- and different for ANY other preimage (that injectivity is
    exactly what makes the recomputed digest per-request and the
    cross-substitution negative sound).
    """
    return {
        "provider": ATTESTATION_PROVIDER,
        "key_id_b64": request["key_id_b64"],
        "assertion_b64": request["assertion_b64"],
        "receipt_b64": request["attestation_receipt_b64"],
        "challenge": request["challenge"],
        "counter": request["counter"],
        "generated_at_unix_s": request["generated_at_unix_s"],
    }


def attestation_sha256_from_request(request):
    """RECOMPUTE (never accept) subject.attestation_sha256 from the request's
    own complete preimage."""
    return sha256_obj(attestation_from_request(request))


def report_subject_from_request(request):
    """Derive the full report.subject from the request alone.

    attestation_sha256 is RECOMPUTED over the reconstructed preimage;
    manifest_sha256 / evidence_sha256 / challenge / counter are the request's
    carried bindings (evidence_sha256 is the relying party's committed digest
    over the receipt body, which the request intentionally does not carry).
    """
    return {
        "manifest_sha256": request["manifest_sha256"],
        "evidence_sha256": request["evidence_sha256"],
        "attestation_sha256": attestation_sha256_from_request(request),
        "challenge": request["challenge"],
        "counter": request["counter"],
        "environment": "mac-attested",
    }


def produce_verifier_report(request, *, apple_core, report_signer, verifier_key_id, verifier_id, verifier_version, verified_at_unix_s):
    """Produce ONE signed verifier report from ONE validated request.

    apple_core: REQUIRED. The deployment's binding of the EXISTING Apple
      verification core: ``apple_core(attestation, subject)`` resolves the
      enrolled P-256 assertion key from ITS authenticated enrollment store,
      runs the core's assertion verification over ``attestation``'s
      assertion CBOR for these exact bindings, and affirms by returning the
      ``apple`` report block (all three check flags literally true,
      ``environment`` in ACCEPTED_APP_ATTEST_ENVIRONMENTS). ANY refusal --
      a falsy return or a raised exception -- aborts the adapter with
      NO report.
    report_signer: REQUIRED. Signs the canonical report body with the
      deployment's long-term ed25519 verifier key; returns sig_b64.
    verifier_key_id: REQUIRED. The id of the signing key -- fixed BEFORE
      the body is built, so the signature covers the final body including
      verifier.key_id (verifier.key_id == report_sig.key_id is a relying-
      party check; a key id patched in after signing would never verify).

    The adapter never performs Apple cryptography itself and never trusts a
    caller-supplied verdict or digest.
    """
    subject = report_subject_from_request(request)
    apple = apple_core(attestation_from_request(request), subject)
    if not isinstance(apple, dict):
        raise AttestationError("the bound Apple verification core refused the request; NO report is produced")
    for flag in ("cert_chain_verified", "receipt_checked", "genuine"):
        if apple.get(flag) is not True:
            raise AttestationError(
                "the bound Apple verification core did not affirm %s; NO report is produced" % flag
            )
    if apple.get("environment") not in ACCEPTED_APP_ATTEST_ENVIRONMENTS:
        raise AttestationError("the bound Apple verification core affirmed an environment outside the accepted set; NO report is produced")
    if not (isinstance(verifier_id, str) and verifier_id and isinstance(verifier_version, str) and verifier_version):
        raise AttestationError("the adapter requires a non-empty verifier id and version")
    if not (isinstance(verifier_key_id, str) and verifier_key_id):
        raise AttestationError("the adapter requires a non-empty verifier key id (fixed before signing)")
    if not isinstance(verified_at_unix_s, (int, float)) or isinstance(verified_at_unix_s, bool):
        raise AttestationError("verified_at_unix_s must be a number")
    report = {
        "verifier_report_version": VERIFIER_REPORT_VERSION,
        "verifier": {"id": verifier_id, "version": verifier_version, "key_id": verifier_key_id},
        "verified": True,
        "subject": subject,
        "apple": {
            "cert_chain_verified": True,
            "receipt_checked": True,  # retained-not-validated retention (see interface)
            "genuine": True,
            "app_key_id_b64": request["key_id_b64"],
            "verified_at_unix_s": verified_at_unix_s,
            "environment": apple["environment"],
        },
    }
    sig_b64 = report_signer(report_body(report))
    if not (isinstance(sig_b64, str) and sig_b64):
        raise AttestationError("the report signer returned an unusable signature")
    report["report_sig"] = {"alg": "ed25519", "key_id": verifier_key_id, "sig_b64": sig_b64}
    # The produced report must satisfy the same structural validation every
    # consumer applies (self-conformance).
    validate_verifier_report(report)
    return report


def request_bytes(request):
    """The EXACT serialized request form: one line, canonical JSON."""
    return canonical_bytes(request)


def domains():
    """The frozen domain strings this boundary sits between (documentation
    helper; keeps the adapter importable without the receipt module)."""
    return {"assertion": ASSERTION_DOMAIN, "evidence": EVIDENCE_DOMAIN}
