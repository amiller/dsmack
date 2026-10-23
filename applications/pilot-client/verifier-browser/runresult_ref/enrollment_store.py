"""R02/REF02 — authenticated enrollment store and attestation ceremony.

Production trust in an assertion key derives EXCLUSIVELY from an authenticated
enrollment record created by an attestation CEREMONY that calls the pinned
Apple App Attest core (``core.verify_attestation``) under an operator-pinned
Apple root certificate and operator ``core.Policy``.  NOTHING a caller asserts
establishes trust: not a public key carried in a request/enrollment object, not
a ``provenance.verified_by_core_sha256`` string naming the pinned core, not
fabricated ``apple_attestation_b64`` / ``apple_receipt_b64`` bytes.  Those are
retained metadata only (``retained_not_validated``).  The verifier resolves the
enrolled key from THIS store BY key id; an unknown key id is refused and the
caller's self-asserted key is never used for production trust.

Trust tier is derived from the operator-pinned root, never from a self-report:

  * ``apple-hardware`` ONLY when the ceremony root sha256 is in the operator's
    out-of-band ``hardware_root_sha256`` pin set (the genuine Apple App Attest
    root).  Genuine Apple hardware is then required to mint an admissible
    attestation; no software key can.
  * ``software-test-nonhardware`` for every other (operator TEST) root.  The
    ceremony still runs the FULL pinned-core verification (chain, nonce,
    AAGUID, credential id, COSE key), but the resulting record can NEVER be
    read as hardware evidence; ``verifier.verify(mode="production")`` refuses a
    non-hardware record.

Integrity: every row is bound by an HMAC-SHA256 over its canonical record bytes
under a store secret the OPERATOR holds (constructor argument, NOT persisted in
the backing file).  ``resolve`` recomputes and checks the HMAC in constant
time, so a row injected directly into the sqlite file without going through
``create_enrollment`` (the only path that runs the ceremony) is refused — an
untrusted record cannot enter the trusted set.
"""
import base64
import binascii
import hashlib
import hmac
import sqlite3

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import protocol
from .errors import Refusal, need
from .frozen import canonical_bytes, core

MAX_ATTESTATION_B64 = 262144
RECORD_KEYS = frozenset({
    "key_id_b64", "public_key_b64", "app_id", "team_id", "environment",
    "trust_tier", "root_sha256", "policy", "apple_receipt_status",
    "apple_receipt_b64", "enrolled_at_unix_s",
    # REF02: complete-ceremony retention so the operator package builder and
    # the verifier can RE-BIND the transferred package to the exact ceremony
    # that ran (pinned core identity, the ceremony challenge, and the attested
    # Apple attestation bytes) — never invented at package-build time.
    "core_sha256", "attestation_challenge_b64", "apple_attestation_b64",
})


def root_der_sha256(root_pem):
    """REF02: the operator root is pinned by its CERTIFICATE DER sha256, NOT
    its PEM encoding.  PEM bytes carry header/whitespace/base64-wrapping that
    are not part of the certificate's identity; hashing them produced a digest
    that disagreed with the authoritative DER root pin.  Parse the certificate
    and hash its canonical DER encoding."""
    der = x509.load_pem_x509_certificate(bytes(root_pem)).public_bytes(
        serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()
TRUST_TIER_HARDWARE = "apple-hardware"
TRUST_TIER_SOFTWARE = "software-test-nonhardware"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS enrollment (
  key_id_b64 TEXT PRIMARY KEY,
  record_json BLOB NOT NULL,
  hmac_hex TEXT NOT NULL
);
"""


def _policy_descriptor(policy):
    """Stable, serializable description of the operator Policy the ceremony
    ran under (so the resolved record reconstructs the SAME policy)."""
    return {
        "app_id": policy.app_id,
        "environment": policy.environment,
        "development_aaguid": policy.development_aaguid,
        "categories": list(policy.categories),
        "versions": list(policy.versions),
        "cdhashes": [h.hex() for h in policy.cdhashes],
        "require_macos_acl": bool(policy.require_macos_acl),
    }


def policy_from_descriptor(desc):
    return core.Policy(
        app_id=desc["app_id"],
        environment=desc["environment"],
        development_aaguid=desc["development_aaguid"],
        categories=tuple(desc["categories"]),
        versions=tuple(desc["versions"]),
        cdhashes=tuple(bytes.fromhex(h) for h in desc["cdhashes"]),
        require_macos_acl=desc["require_macos_acl"],
    )


class AuthenticatedEnrollmentStore:
    def __init__(self, path, operator_secret, hardware_root_sha256=()):
        need(isinstance(operator_secret, (bytes, bytearray))
             and len(operator_secret) >= 16, "weak_operator_secret")
        self.path = str(path)
        self._secret = bytes(operator_secret)
        self._hardware_roots = frozenset(hardware_root_sha256)
        connection = self._connect()
        with connection:
            connection.executescript(_SCHEMA)
        connection.close()

    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=30.0,
                                     isolation_level=None)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _mac(self, record_bytes):
        return hmac.new(self._secret, record_bytes, hashlib.sha256).hexdigest()

    # ---- the authenticated creation path (ceremony) ----
    def create_enrollment(self, attestation_b64, key_id_b64,
                          attestation_challenge, app_id, team_id, environment,
                          operator_policy, root_pem, now_unix_s=0):
        """Run the pinned-core attestation ceremony and, ONLY on success,
        insert an authenticated record.  Every failure of the ceremony is a
        refusal; no record is written.  The operator supplies app/team/
        environment and the Policy/root — never the caller.
        """
        need(isinstance(attestation_b64, str)
             and len(attestation_b64) <= MAX_ATTESTATION_B64,
             "attestation_too_large")
        try:
            raw = base64.b64decode(attestation_b64, validate=True)
        except (ValueError, binascii.Error):
            raise Refusal("attestation_bad_b64") from None
        need(isinstance(root_pem, (bytes, bytearray)) and root_pem,
             "operator_root_required")
        need(isinstance(operator_policy, core.Policy), "operator_policy_required")
        need(operator_policy.app_id == app_id, "policy_app_id_mismatch")
        need(operator_policy.environment == environment,
             "policy_environment_mismatch")
        need(app_id.startswith(team_id + "."), "app_team_mismatch")
        # The pinned core performs ALL Apple cryptography: chain to the
        # operator root, AAGUID environment, credential id, COSE key, and the
        # nonce extension binding over this exact challenge.  A Reject here is
        # a ceremony refusal — no record exists.
        try:
            result = core.verify_attestation(
                raw, key_id_b64, attestation_challenge, operator_policy,
                bytes(root_pem))
        except core.Reject as exc:
            raise Refusal("attestation_ceremony_rejected", str(exc)) from exc
        # The attestation-DERIVED public key is the only trusted key; its id
        # must equal the claimed key id (core already bound them, re-checked).
        point = base64.b64decode(result["public_key"])
        need(core.b64(hashlib.sha256(point).digest()) == key_id_b64,
             "ceremony_key_id_mismatch")
        # REF02: the trust-tier pin and the recorded root identity both use the
        # certificate DER sha256 (authoritative root pin domain), not PEM bytes.
        root_sha256 = root_der_sha256(root_pem)
        trust_tier = (TRUST_TIER_HARDWARE if root_sha256 in self._hardware_roots
                      else TRUST_TIER_SOFTWARE)
        # Retain the ceremony challenge in the SAME encoding Apple assertions
        # use (base64), and the pinned-core identity, so the operator's
        # transferable package re-binds to this exact ceremony.
        attestation_challenge_b64 = core.b64(
            attestation_challenge if isinstance(attestation_challenge, bytes)
            else bytes(attestation_challenge))
        record = {
            "key_id_b64": key_id_b64,
            "public_key_b64": result["public_key"],
            "app_id": app_id,
            "team_id": team_id,
            "environment": environment,
            "trust_tier": trust_tier,
            "root_sha256": root_sha256,
            "policy": _policy_descriptor(operator_policy),
            "apple_receipt_status": result["receipt_status"],
            "apple_receipt_b64": result["receipt"],
            "enrolled_at_unix_s": int(now_unix_s),
            "core_sha256": protocol.CORE_SHA256,
            "attestation_challenge_b64": attestation_challenge_b64,
            "apple_attestation_b64": attestation_b64,
        }
        record_bytes = canonical_bytes(record)
        mac = self._mac(record_bytes)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT record_json FROM enrollment WHERE key_id_b64=?",
                (key_id_b64,)).fetchone()
            if row is not None:
                # Idempotent re-enrollment of the SAME authenticated key is
                # allowed; a conflicting key for the same id is refused.
                need(row[0] == record_bytes, "enrollment_key_conflict")
            connection.execute(
                "INSERT INTO enrollment VALUES (?,?,?)"
                " ON CONFLICT(key_id_b64) DO UPDATE SET record_json=excluded"
                ".record_json, hmac_hex=excluded.hmac_hex",
                (key_id_b64, record_bytes, mac))
            connection.execute("COMMIT")
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise Refusal("enrollment_store_error", str(exc)) from exc
        finally:
            connection.close()
        return record

    # ---- trusted resolution (HMAC-gated) ----
    def resolve(self, key_id_b64):
        """Return the authenticated record for ``key_id_b64`` or None.  A row
        whose HMAC does not verify under the operator secret is treated as
        absent (injected/untrusted) — it can never be resolved as trusted."""
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT record_json, hmac_hex FROM enrollment WHERE key_id_b64=?",
                (key_id_b64,)).fetchone()
        finally:
            connection.close()
        if row is None:
            return None
        record_bytes, mac_hex = row
        expected = self._mac(record_bytes)
        if not hmac.compare_digest(expected, str(mac_hex)):
            return None
        import json
        record = json.loads(record_bytes)
        if set(record.keys()) != set(RECORD_KEYS):
            return None
        if record["key_id_b64"] != key_id_b64:
            return None
        return record
