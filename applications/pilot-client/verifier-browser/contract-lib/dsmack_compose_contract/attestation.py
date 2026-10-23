"""Attestation boundary for dsmack.receipt/4 (contract4; astra C01 + D02).

HARD RULE: receipt SHAPE validation never reports successful attestation.
A shape-valid attestation object (even with provider apple-appattest and
placeholder Apple fields) proves NOTHING. "Attested" is reported ONLY by
attestation.verify_attestation(), which requires an AUTHENTICATED report
from the separate appattest-verifier/2 domain:

  1. AUTHENTICATION (new in v3): the report body must carry a valid ed25519
     signature (report_sig) made by a verifier key the CALLER pins.
     validate_verifier_report() is purely STRUCTURAL -- it cannot assert
     attestation and does not check any signature. Only verify_attestation()
     checks the signature under a caller-supplied trusted key map
     ({key_id: ed25519_public_key}). A self-declared verifier id alone
     (the v2 allowlist) is INSUFFICIENT and no longer accepted.

  2. FRESHNESS (mandatory): the caller MUST pass expected_challenge -- the
     nonce it issued for THIS run -- plus replay duties through ONE of the
     two supported modes. STATEFUL relying parties pass replay_state: an
     object implementing the atomic consume(challenge, app_key_id, counter)
     ABI that records the challenge consumed and advances the per-key
     counter under one lock (this library ships InMemoryReplayState and
     FileReplayState, and the CLI requires a FileReplayState via
     --replay-state). STATELESS one-shot callers (no replay_state;
     in-process only) MUST pass BOTH min_counter -- the lowest assertion
     counter they will accept for this app key -- AND consumed_challenges,
     and record consumption and advance the counter themselves on success.
     These are relying-party duties specified in
     interfaces/mac-attestation-interface.md; verify_attestation() enforces
     whichever mode's parameters were supplied and never invents
     persistence.

  3. BINDINGS: report subject must match the receipt and manifest bytes
     (manifest digest, attestation digest, recomputed evidence digest,
     challenge, counter).

assertion payload (exact bytes the Mac app signs and the verifier checks;
frozen at /4 across code, schemas, documents and vectors -- E03):

  "dsmack.appattest.assertion/4" \\0
  manifest_sha256 (64 hex) \\0
  evidence_sha256 (64 hex) \\0
  challenge (UTF-8) \\0
  counter (decimal ASCII, no padding)

evidence_sha256 = execution_evidence_digest(receipt) over the EXACT body
documented in interfaces/mac-attestation-interface.md AND reproduced by
examples/hash-vectors.json (frozen cross-implementation vector): a
domain-separated canonical digest over
  ["dsmack.receipt-evidence/4", {
     "attestation": null,            <-- explicit member, documented (C01)
     "base_vm": <full base_vm object>,
     "base_vm_launch": <admission + boot observation (E02)>,
     "harness_sha256": ...,
     "manifest_sha256": ...,
     "observed": ...,
     "outputs": ...,
     "run_id": ...,
     "runtime_inputs_commitment": ...}]

The actual Apple cryptography (attestation certificate chain, nonce
extension binding, AAGUID environment check, and the P-256 assertion
signature over the payload above) is performed by the EXISTING App Attest
verifier core. That core RETAINS the App Attest receipt as opaque evidence
(receipt_status 'retained_not_validated') and does NOT validate the receipt
against Apple -- receipt validation is not part of this boundary. This
contract library defines the exact bindings, the verifier-report adapter
ABI, and the ed25519 report-signature check. It never performs or simulates
Apple cryptography.

HONESTY (scoped precisely, C01): a structural pass proves nothing; an
UNTRUSTED or unsigned report proves nothing; a signature under a caller-
pinned key with a fresh challenge and acceptable counter attests that THE
PINNED VERIFIER checked the Apple evidence -- it is still NOT a hardware
measurement of the Linux guest. The guest is covered by the manifest's
base-VM pins. Genuine hardware execution remains a later gate; nothing here
claims otherwise.
"""

import base64
import binascii

from . import ed25519
from .canonical import canonical_bytes, load_json_bytes, sha256_hex, sha256_obj
from .errors import AttestationError, ReceiptError
from .manifest import HEX64_RE
from .receipt import ENVIRONMENT_MAC_ATTESTED, validate_receipt
from .schema_check import SchemaViolation, validate as schema_validate

ASSERTION_DOMAIN = "dsmack.appattest.assertion/4"
EVIDENCE_DOMAIN = "dsmack.receipt-evidence/4"
VERIFIER_REPORT_VERSION = 2

#: Keys of the SIGNED report (report_sig carries the signature).
REPORT_REQUIRED_KEYS = {
    "verifier_report_version",
    "verifier",
    "verified",
    "subject",
    "apple",
    "report_sig",
}
SUBJECT_REQUIRED_KEYS = {
    "manifest_sha256",
    "evidence_sha256",
    "attestation_sha256",
    "challenge",
    "counter",
    "environment",
}
APPLE_REQUIRED_KEYS = {"cert_chain_verified", "receipt_checked", "genuine", "verified_at_unix_s", "app_key_id_b64", "environment"}
VERIFIER_REQUIRED_KEYS = {"id", "version", "key_id"}
REPORT_SIG_REQUIRED_KEYS = {"alg", "key_id", "sig_b64"}

#: E03: the only accepted Apple App Attest enrollment environment, and the
#: authenticated assertion-key lookup configuration a verifier must operate
#: under (the verifier resolves App Attest keys via Apple's authenticated
#: provisioning -- never from the request).
ACCEPTED_APP_ATTEST_ENVIRONMENTS = ("production",)
ASSERTION_KEY_SOURCES = ("apple-appattest-provisioned",)

#: R03 + S02: an enrollment record carries the AUTHENTICATED PUBLIC KEY
#: MATERIAL for the assertion-key lookup, the admitted app identity, the
#: environment binding and the counter state -- the concrete configuration
#: the actual verifier subprocess resolves App Attest keys from (never from
#: the request). `assertion_public_key` is the ALGORITHM-TAGGED Apple App
#: Attest assertion key: {"alg": "es256", "encoding": "x9.62-uncompressed",
#: "key_b64": <standard base64 of the 65-byte SEC1/X9.62 uncompressed P-256
#: public key point, 0x04 || X || Y>}. This is a DIFFERENT key class from
#: the ed25519 verifier-report keys (trusted_verifier_keys /
#: report_sig): Apple App Attest assertion keys are P-256 ES256 keys
#: extracted from the verified attestation certificate; the 32-byte
#: ed25519 keys sign verifier REPORTS. The key identifier binding follows
#: Apple's specification: app_key_id_b64 == base64(SHA256(X9.62 point)).
ENROLLMENT_RECORD_KEYS = {
    "app_key_id_b64",
    "app_id",
    "team_id",
    "assertion_public_key",
    "environment",
    "enrolled_at_unix_s",
    "last_counter",
}
ASSERTION_PUBLIC_KEY_KEYS = {"alg", "encoding", "key_b64"}
ASSERTION_KEY_ALG = "es256"
ASSERTION_KEY_ENCODING = "x9.62-uncompressed"

#: T02: the enrollment ENVIRONMENT is persisted authenticated provenance.
#: The EXISTING production verifier (trusted-verifier-inputs/verifier/core.py,
#: Policy.environment) checks the environment during ATTESTATION only -- the
#: AAGUID inside the attestation authData (production = b'appattest' + 7 NULs;
#: development = 'appattestdevelop' or 'appattestsandbox' per the operator's
#: policy) -- and NOT during assertion verification (legacy assertion authData
#: carries no attested-key section). The assertion path therefore resolves the
#: environment from THIS persisted record, never from the request and never by
#: re-derivation; a context whose accepted environments exclude the record's
#: environment rejects BEFORE any assertion is accepted, so development- and
#: production-enrolled records are never interchangeable.
ENROLLMENT_ENVIRONMENTS = ("production", "development")
PRODUCTION_AAGUID = b"appattest" + b"\x00" * 7
DEVELOPMENT_AAGUIDS = ("appattestdevelop", "appattestsandbox")


def environment_from_aaguid(aaguid):
    """The enrollment environment a VERIFIED attestation AAGUID proves (the
    production verifier's exact derivation; None for any other bytes)."""
    if not isinstance(aaguid, (bytes, bytearray)):
        return None
    if bytes(aaguid) == PRODUCTION_AAGUID:
        return "production"
    if bytes(aaguid) in tuple(a.encode("ascii") for a in DEVELOPMENT_AAGUIDS):
        return "development"
    return None

#: NIST SP 800-186 P-256 (secp256r1) domain parameters -- only the primes and
#: the curve coefficient b are needed for the offline on-curve validation.
_P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B


def _decode_x962_uncompressed_p256(key_b64):
    """Decode + VALIDATE a standard-base64 SEC1/X9.62 uncompressed P-256 point.

    Returns the 65 bytes (0x04 || X || Y) or None. Validation is offline and
    mathematical: exact encoded length, the 0x04 uncompressed marker, both
    coordinates in [1, p) and the point ON the curve y^2 = x^3 - 3x + b
    (mod p) -- a decoded-but-invalid point (e.g. 32 zero bytes or a point
    off the curve) is rejected here, never downstream.
    """
    if not isinstance(key_b64, str):
        return None
    try:
        data = base64.b64decode(key_b64, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(data) != 65 or data[0] != 0x04:
        return None
    x = int.from_bytes(data[1:33], "big")
    y = int.from_bytes(data[33:65], "big")
    if not (0 < x < _P256_P and 0 < y < _P256_P):
        return None
    if (y * y - (x * x * x - 3 * x + _P256_B)) % _P256_P != 0:
        return None
    return data


def validate_enrollment_record(record):
    """S02: validate a COMPLETE authenticated enrollment record.

    Enforces the exact key set, the Apple key-identifier binding
    (app_key_id_b64 == base64(SHA256(X9.62 uncompressed assertion key))),
    the algorithm-tagged P-256 assertion-key encoding (on-curve validated),
    the admitted application identity fields and the counter state. Raises
    AttestationError on any violation; returns the decoded material.
    """
    import hashlib

    if not isinstance(record, dict) or set(record) != ENROLLMENT_RECORD_KEYS:
        raise AttestationError(
            "the enrollment record must carry exactly the authenticated ABI fields %s (including "
            "assertion_public_key: the algorithm-tagged Apple assertion verification key the "
            "verifier subprocess resolves for this app key)" % sorted(ENROLLMENT_RECORD_KEYS)
        )
    kid = record["app_key_id_b64"]
    if not isinstance(kid, str) or not kid:
        raise AttestationError("enrollment app_key_id_b64 must be a non-empty string")
    try:
        kid_bytes = base64.b64decode(kid, validate=True)
    except (binascii.Error, ValueError):
        raise AttestationError(
            "enrollment app_key_id_b64 must be standard base64 of the 32-byte key-identifier digest"
        ) from None
    if len(kid_bytes) != 32:
        raise AttestationError(
            "enrollment app_key_id_b64 must decode to exactly 32 bytes (the SHA-256 key-identifier digest)"
        )
    # CANONICALITY: the production verifier decodes and RE-ENCODES to
    # compare, so non-canonical spellings (over-padding, "-O" variants) of
    # the identifier never interoperate. Require the exact canonical form.
    if base64.b64encode(kid_bytes).decode("ascii") != kid:
        raise AttestationError("enrollment app_key_id_b64 must be the CANONICAL standard base64 of its 32 bytes")
    key = record["assertion_public_key"]
    if not isinstance(key, dict) or set(key) != ASSERTION_PUBLIC_KEY_KEYS:
        raise AttestationError(
            "enrollment assertion_public_key must be an object with exactly %s (the algorithm-tagged "
            "Apple assertion-key encoding)" % sorted(ASSERTION_PUBLIC_KEY_KEYS)
        )
    if key["alg"] != ASSERTION_KEY_ALG:
        raise AttestationError(
            "enrollment assertion_public_key.alg must be %r (Apple App Attest assertion keys are "
            "P-256 ES256 keys -- never the ed25519 verifier-report key class)" % ASSERTION_KEY_ALG
        )
    if key["encoding"] != ASSERTION_KEY_ENCODING:
        raise AttestationError(
            "enrollment assertion_public_key.encoding must be %r (SEC1/X9.62 uncompressed)"
            % ASSERTION_KEY_ENCODING
        )
    point = _decode_x962_uncompressed_p256(key["key_b64"])
    if point is None:
        raise AttestationError(
            "enrollment assertion_public_key.key_b64 must be standard base64 of the 65-byte X9.62 "
            "uncompressed P-256 public key (0x04 || X || Y) with the point ON the curve"
        )
    if base64.b64encode(point).decode("ascii") != key["key_b64"]:
        raise AttestationError("enrollment assertion_public_key.key_b64 must be the CANONICAL standard base64 of its 65 bytes")
    if base64.b64encode(hashlib.sha256(point).digest()).decode("ascii") != kid:
        raise AttestationError(
            "the enrollment key identifier does not equal base64(SHA256(X9.62 uncompressed "
            "assertion key)) (the Apple key-identifier binding)"
        )
    for field in ("app_id", "team_id"):
        if not isinstance(record[field], str) or not record[field]:
            raise AttestationError("enrollment %s must be a non-empty string" % field)
    # T02: the persisted AUTHENTICATED enrollment environment. This is the
    # production-scoped provenance the attestation established (the verifier
    # checked the AAGUID against its policy environment when it verified the
    # enrollment attestation); the assertion path binds every lookup to it.
    if record["environment"] not in ENROLLMENT_ENVIRONMENTS:
        raise AttestationError(
            "enrollment environment must be one of %s (authenticated provenance derived from the "
            "verified attestation AAGUID; development- and production-enrolled records are never "
            "interchangeable)" % (list(ENROLLMENT_ENVIRONMENTS),)
        )
    stamp = record["enrolled_at_unix_s"]
    if not isinstance(stamp, int) or isinstance(stamp, bool) or stamp < 0:
        raise AttestationError("enrollment enrolled_at_unix_s must be a non-negative integer")
    counter = record["last_counter"]
    if not isinstance(counter, int) or isinstance(counter, bool) or counter < 0:
        raise AttestationError("the enrollment record's last_counter must be a non-negative integer (counter state)")
    return {"key_id_bytes": kid_bytes, "assertion_point": point}


# ---------------------------------------------------------------------------
# D02: trusted verifier context, authenticated enrollment and replay state.
#
# An independently implemented verifier can only be verifying THE ADMITTED
# LAUNCHER when the verification request itself carries a trusted context:
# which application identity is admitted, which verifier keys are pinned, and
# where the AUTHENTICATED enrollment record for the App Attest key comes from.
# Enrollments happen out-of-band (the relying party verifies a genuine App
# Attest ATTESTATION for the expected app and stores the key record); the
# assertion path NEVER auto-enrolls a first-seen key.


class InMemoryEnrollmentStore:
    """Thread-safe in-memory enrollment store (tests + small deployments).

    ABI every store must implement: lookup(app_key_id_b64) -> an immutable
    record copy or None. A production store is the relying party's OWN
    authenticated enrollment database (populated only through verified
    attestations for the expected app identity); this library never writes
    enrollments.
    """

    def __init__(self):
        import threading

        self._records = {}
        self._lock = threading.Lock()

    def enroll(self, app_key_id_b64, app_id, team_id, assertion_public_key, environment, enrolled_at_unix_s=0):
        """Record a FRESH AUTHENTICATED enrollment (R03 + S02 + T02 ABI).

        assertion_public_key: the ALGORITHM-TAGGED Apple App Attest assertion
        key {"alg": "es256", "encoding": "x9.62-uncompressed", "key_b64":
        <b64 of the 65-byte X9.62 uncompressed P-256 point>}, verified
        out-of-band through a genuine App Attest ATTESTATION for the expected
        app identity. environment: the enrollment environment that ATTESTATION
        proved -- the caller derives it from the verified authData AAGUID with
        environment_from_aaguid (production = b'appattest' + 7 NULs) exactly
        as the production verifier's policy does -- and it is PERSISTED with
        the record as authenticated provenance. Required -- the assertion path
        resolves key material AND environment ONLY from this record. A fresh
        enrollment starts at last_counter 0; to import an EXISTING record with
        its counter state use import_record (S03).
        """
        record = {
            "app_key_id_b64": app_key_id_b64,
            "app_id": app_id,
            "team_id": team_id,
            "assertion_public_key": assertion_public_key,
            "environment": environment,
            "enrolled_at_unix_s": enrolled_at_unix_s,
            "last_counter": 0,
        }
        validate_enrollment_record(record)
        with self._lock:
            self._records[app_key_id_b64] = dict(record)
        return record

    def import_record(self, record):
        """S03: import a COMPLETE authenticated enrollment record WITHOUT
        resetting its counter state.

        The record is validated in full (exact key set, Apple
        key-identifier binding, on-curve tagged assertion key, app identity,
        PERSISTED environment, counter state) and stored VERBATIM -- a record
        carrying last_counter=100 imports with last_counter=100, and a record
        enrolled under the development environment imports as a development
        record (T02: the environment provenance survives export/import), so
        the effective counter floor and the environment binding at
        verification include the imported state. This is the CLI `enrollment
        import` path; enroll() is the fresh-enrollment path and always starts
        at zero.
        """
        validate_enrollment_record(record)
        stored = dict(record)
        with self._lock:
            self._records[stored["app_key_id_b64"]] = stored
        return dict(stored)

    def lookup(self, app_key_id_b64):
        with self._lock:
            record = self._records.get(app_key_id_b64)
            return dict(record) if record is not None else None


class FileReplayState:
    """File-backed replay state for CLI / one-process relying parties (R03).

    Implements the replay_state ABI: consume(challenge, app_key_id, counter)
    performs the read/check/record/rewrite cycle under ONE exclusive flock
    on the state file. The locked file is rewritten IN PLACE while the lock
    is held (lseek(0) + write + ftruncate + fsync) -- atomic replacement
    (temp file + os.replace) is deliberately NOT used, because the
    serialization lock is bound to the file's INODE and replacing the file
    would let a concurrent consumer lock a different inode. The lock is held
    across the whole check-and-update, so two concurrent CLI invocations
    serialize: exactly one succeeds for a given challenge. A rejected
    verification never modifies the file. CRASH SEMANTICS: the in-place
    rewrite is serialized against cooperative flock users but is not
    crash-atomic -- a crash mid-write can leave a torn state file, which the
    loader then rejects fail-closed ("not valid JSON") at the cost of the
    recorded state; non-flock readers may observe torn bytes.
    last_counter(app_key_id) is the read-only persisted-counter query
    (S03's effective counter floor).
    """

    def __init__(self, path):
        import os

        if not isinstance(path, str) or not path:
            raise AttestationError("replay state path must be a non-empty string")
        self._path = path
        self._os = os

    def last_counter(self, app_key_id):
        """S03: the persisted per-key counter floor (0 for fresh/absent state).

        Read-only: takes a SHARED flock so a concurrent consume() cannot be
        mid-rewrite, parses the state and returns that key's counter (0 when
        the state file or the key is absent).
        """
        import fcntl
        import io

        if not self._os.path.exists(self._path):
            return 0
        fd = self._os.open(self._path, self._os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_SH)
            chunks = []
            while True:
                chunk = self._os.read(fd, 65536)
                if not chunk:
                    break
                chunks.append(chunk)
            raw = b"".join(chunks).decode("utf-8") if chunks else "{}"
            _consumed, counters = self._load(io.StringIO(raw))
            return counters.get(app_key_id, 0)
        finally:
            self._os.close(fd)

    def _load(self, handle):
        import json

        try:
            data = json.load(handle)
        except ValueError:
            raise ReplayRejectedError("replay state file is not valid JSON") from None
        if not isinstance(data, dict) or set(data) - {"consumed", "counters"}:
            raise ReplayRejectedError("replay state file must be a JSON object {consumed, counters}")
        consumed = data.get("consumed", [])
        counters = data.get("counters", {})
        if not isinstance(consumed, list) or any(not isinstance(c, str) for c in consumed):
            raise ReplayRejectedError("replay state consumed must be a list of strings")
        if not isinstance(counters, dict) or any(not isinstance(k, str) or not isinstance(v, int) or isinstance(v, bool) for k, v in counters.items()):
            raise ReplayRejectedError("replay state counters must be {key_id: int}")
        return set(consumed), dict(counters)

    def consume(self, challenge, app_key_id, counter):
        import fcntl
        import io
        import json

        fd = self._os.open(self._path, self._os.O_RDWR | self._os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            chunks = []
            while True:
                chunk = self._os.read(fd, 65536)
                if not chunk:
                    break
                chunks.append(chunk)
            raw = b"".join(chunks).decode("utf-8") if chunks else "{}"
            consumed, counters = self._load(io.StringIO(raw))
            if challenge in consumed:
                raise ReplayRejectedError("challenge was already consumed (replay rejected)")
            last = counters.get(app_key_id)
            if last is not None and counter <= last:
                raise ReplayRejectedError(
                    "assertion counter does not advance the per-key state (replayed/rolled-back key rejected)"
                )
            consumed.add(challenge)
            counters[app_key_id] = counter
            payload = json.dumps({"consumed": sorted(consumed), "counters": counters}, sort_keys=True).encode("utf-8")
            self._os.lseek(fd, 0, self._os.SEEK_SET)
            self._os.write(fd, payload)
            self._os.ftruncate(fd, len(payload))
            self._os.fsync(fd)
            fcntl.flock(fd, fcntl.LOCK_UN)
            return {"consumed": True, "app_key_counter": counter}
        finally:
            self._os.close(fd)


class InMemoryReplayState:
    """Thread-safe atomic challenge consumption + per-key counter state (D02).

    ABI every replay store must implement: consume(challenge, app_key_id,
    counter) -> raises ReplayRejectedError on a reused challenge or a
    non-advancing counter; on success atomically records both. The check and
    the update happen under ONE lock acquisition, so concurrent verification
    of the same evidence admits exactly one success.
    """

    def __init__(self):
        import threading

        self._consumed = set()
        self._counters = {}
        self._lock = threading.Lock()

    def consume(self, challenge, app_key_id, counter):
        with self._lock:
            if challenge in self._consumed:
                raise ReplayRejectedError("challenge was already consumed (replay rejected)")
            last = self._counters.get(app_key_id)
            if last is not None and counter <= last:
                raise ReplayRejectedError(
                    "assertion counter does not advance the per-key state (replayed/rolled-back key rejected)"
                )
            self._consumed.add(challenge)
            self._counters[app_key_id] = counter
            return {"consumed": True, "app_key_counter": counter}

    def last_counter(self, app_key_id):
        """S03: the in-memory per-key counter floor (0 when unseen)."""
        with self._lock:
            return self._counters.get(app_key_id, 0)


class ReplayRejectedError(AttestationError):
    """Atomic replay-state rejection (reused challenge or stale counter)."""


def expected_context_keys():
    return (
        "trusted_verifier_keys",
        "expected_app",
        "enrollment_store",
        "app_attest_environments",
        "assertion_key_source",
    )


def assertion_payload(manifest_sha256, evidence_sha256, challenge, counter):
    """Exact domain-separated bytes an App Attest assertion must sign."""
    if not (isinstance(manifest_sha256, str) and HEX64_RE.match(manifest_sha256)):
        raise AttestationError("manifest_sha256 must be 64-hex")
    if not (isinstance(evidence_sha256, str) and HEX64_RE.match(evidence_sha256)):
        raise AttestationError("evidence_sha256 must be 64-hex")
    if not isinstance(challenge, str) or not challenge or "\x00" in challenge:
        raise AttestationError("challenge must be a non-empty string without NUL")
    if not isinstance(counter, int) or isinstance(counter, bool) or counter < 0:
        raise AttestationError("counter must be a non-negative integer")
    return b"\x00".join(
        [
            ASSERTION_DOMAIN.encode("utf-8"),
            manifest_sha256.encode("ascii"),
            evidence_sha256.encode("ascii"),
            challenge.encode("utf-8"),
            str(counter).encode("ascii"),
        ]
    )


def execution_evidence_digest(receipt):
    """Domain-separated digest over the receipt's execution evidence.

    The body is the EXACT document in interfaces/mac-attestation-interface.md
    (the explicit "attestation": null member included) and is frozen by the
    evidence-digest vector in examples/hash-vectors.json (C01: documentation,
    code and a cross-language vector now agree).
    """
    body = {
        "attestation": None,  # bound via attestation_sha256; explicit member
        "base_vm": receipt.get("base_vm"),
        "base_vm_launch": receipt.get("base_vm_launch"),
        "harness_sha256": receipt.get("harness_sha256"),
        "manifest_sha256": receipt.get("manifest_sha256"),
        "observed": receipt.get("observed"),
        "outputs": receipt.get("outputs"),
        "run_id": receipt.get("run_id"),
        "runtime_inputs_commitment": receipt.get("runtime_inputs_commitment"),
    }
    return sha256_obj([EVIDENCE_DOMAIN, body])


def report_body(report):
    """The exact canonically-serialized bytes a report signature covers:
    the full report object minus its report_sig member. (Signers call this
    BEFORE attaching report_sig; verifiers call it after structural
    validation, which requires report_sig to be present.)"""
    if not isinstance(report, dict):
        raise AttestationError("verifier report must be a JSON object")
    body = {k: v for k, v in report.items() if k != "report_sig"}
    return canonical_bytes(body)


def validate_verifier_report(report):
    """STRUCTURAL validation of a verifier report -- and nothing more.

    This checks the shape (keys, literal verified flags, 64-hex fields).
    It CANNOT assert attestation: a structurally valid report may be
    fabricated by anyone. Signature verification, trust, freshness and
    binding checks happen only in verify_attestation().
    """
    if not isinstance(report, dict):
        raise AttestationError("verifier report must be a JSON object")
    unknown = set(report) - REPORT_REQUIRED_KEYS
    if unknown:
        # E08: caller-controlled key text is withheld in diagnostics.
        raise AttestationError(
            "verifier report has unsupported keys (key text withheld); allowed keys are %s" % sorted(REPORT_REQUIRED_KEYS)
        )
    missing = REPORT_REQUIRED_KEYS - set(report)
    if missing:
        raise AttestationError("verifier report is missing keys: %s" % sorted(missing))
    if report["verifier_report_version"] != VERIFIER_REPORT_VERSION:
        raise AttestationError("verifier_report_version must be %d" % VERIFIER_REPORT_VERSION)
    for path, node, required in (
        ("verifier", report["verifier"], VERIFIER_REQUIRED_KEYS),
        ("subject", report["subject"], SUBJECT_REQUIRED_KEYS),
        ("apple", report["apple"], APPLE_REQUIRED_KEYS),
        ("report_sig", report["report_sig"], REPORT_SIG_REQUIRED_KEYS),
    ):
        if not isinstance(node, dict):
            raise AttestationError("verifier report.%s must be an object" % path)
        unknown = set(node) - set(required)
        if unknown:
            # E08: withheld key text here too.
            raise AttestationError(
                "verifier report.%s has unsupported keys (key text withheld); allowed keys are %s"
                % (path, sorted(required))
            )
        missing = set(required) - set(node)
        if missing:
            raise AttestationError("verifier report.%s is missing keys: %s" % (path, sorted(missing)))
    if report["verified"] is not True:
        # The report must affirmatively claim verified=true; anything else
        # (false, "true", 1) is not a report of verification at all.
        raise AttestationError(
            "verifier report.verified must be literal true; a document that does not claim "
            "verification is not a verifier report (and no claim here is TRUST yet)"
        )
    for field in ("id", "key_id"):
        value = report["verifier"][field]
        if not isinstance(value, str) or not value:
            raise AttestationError("verifier report.verifier.%s must be a non-empty string" % field)
    if not isinstance(report["verifier"]["version"], str) or not report["verifier"]["version"]:
        raise AttestationError("verifier report.verifier.version must be a non-empty string")
    for field in ("cert_chain_verified", "receipt_checked", "genuine"):
        if report["apple"][field] is not True:
            raise AttestationError(
                "verifier report.apple.%s must be literal true (a report that did not fully check the "
                "Apple evidence is not a verification report)" % field
            )
    key_id_b64 = report["apple"]["app_key_id_b64"]
    if not isinstance(key_id_b64, str) or not key_id_b64:
        raise AttestationError("verifier report.apple.app_key_id_b64 must be a non-empty string (the App Attest key the report is scoped to)")
    if report["report_sig"]["alg"] != "ed25519":
        raise AttestationError("verifier report.report_sig.alg must be 'ed25519'")
    if not isinstance(report["report_sig"]["key_id"], str) or not report["report_sig"]["key_id"]:
        raise AttestationError("verifier report.report_sig.key_id must be a non-empty string")
    if not isinstance(report["report_sig"]["sig_b64"], str) or not report["report_sig"]["sig_b64"]:
        raise AttestationError("verifier report.report_sig.sig_b64 must be a non-empty base64 string")
    subject = report["subject"]
    for field in ("manifest_sha256", "evidence_sha256", "attestation_sha256"):
        if not (isinstance(subject[field], str) and HEX64_RE.match(subject[field])):
            raise AttestationError("verifier report.subject.%s must be 64-hex" % field)
    # D02: field types are validated BEFORE any use (a list-valued challenge
    # or float counter must be a structural rejection, not a downstream
    # TypeError).
    if not isinstance(subject["challenge"], str) or not subject["challenge"] or "\x00" in subject["challenge"]:
        raise AttestationError("verifier report.subject.challenge must be a non-empty string without NUL")
    if not isinstance(subject["counter"], int) or isinstance(subject["counter"], bool) or subject["counter"] < 0:
        raise AttestationError("verifier report.subject.counter must be a non-negative integer")
    if not isinstance(report["apple"]["verified_at_unix_s"], (int, float)) or isinstance(
        report["apple"]["verified_at_unix_s"], bool
    ):
        raise AttestationError("verifier report.apple.verified_at_unix_s must be a number")
    # E03: the report records WHICH App Attest environment the verifier
    # checked; only the accepted production environment is representable.
    if report["apple"]["environment"] not in ACCEPTED_APP_ATTEST_ENVIRONMENTS:
        raise AttestationError(
            "verifier report.apple.environment must be one of %s (the accepted enrollment environment)"
            % (list(ACCEPTED_APP_ATTEST_ENVIRONMENTS),)
        )
    if subject["environment"] != ENVIRONMENT_MAC_ATTESTED:
        raise AttestationError("verifier report.subject.environment must be 'mac-attested'")
    return True


def validate_verifier_report_bytes(report_bytes):
    report = load_json_bytes(report_bytes, "attestation verifier report")
    validate_verifier_report(report)
    return report


def check_report_against_schema(report):
    """Schema/library parity for verifier reports (test + tooling helper)."""
    schema = schema_of_verifier_report()
    try:
        schema_validate(report, schema)
    except SchemaViolation as exc:
        raise ReceiptError("verifier report violates its schema: %s" % exc) from exc
    return True


def _b64_32(value, what):
    if not isinstance(value, str):
        return None
    try:
        data = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(data) != 32:
        return None
    return data


def verify_attestation(
    manifest_bytes,
    receipt,
    report,
    *,
    context,
    expected_challenge,
    replay_state=None,
    min_counter=None,
    consumed_challenges=None,
):
    """Independently verify a mac-attested receipt using a SIGNED verifier report.

    This is the ONLY path in the contract that may report attested=true.
    Every failure raises AttestationError; success returns a summary dict.

    context: REQUIRED trusted verifier context (D02). An independently
      implemented verifier can only verify THE ADMITTED LAUNCHER when the
      request itself fixes:
        - trusted_verifier_keys: {verifier_key_id: 32-byte ed25519 public
          key} pinned out-of-band by the caller;
        - expected_app: {"app_id": ..., "team_id": ...} -- the admitted
          application identity; the App Attest key must be ENROLLED under
          exactly this identity;
        - enrollment_store: an authenticated enrollment store (lookup
          ABI) populated only through genuine App Attest attestations.
          The assertion path NEVER auto-enrolls a first-seen key.

    expected_challenge: REQUIRED. The fresh nonce the caller issued for THIS
      run; replays are rejected (C01).

    replay_state: REQUIRED for stateful relying parties. An object whose
      atomic consume(challenge, app_key_id, counter) rejects a reused
      challenge or a non-advancing per-key counter and records both under
      one lock (concurrent verification of the same evidence admits exactly
      one success). consume() is invoked ONLY after every other check
      passes, so a rejected verification never burns the challenge.

    min_counter + consumed_challenges: the stateless fallback for one-shot
      callers. At least one of replay_state / min_counter must be supplied;
      both paths enforce mandatory freshness and counter duties (C01/D02).
    """
    # 0. Mandatory trusted context and freshness parameters (C01/D02):
    #    relying-party duties are not optional and are not inferred.
    if not isinstance(context, dict):
        raise AttestationError(
            "context is REQUIRED: a trusted verifier context fixing the pinned verifier keys, the "
            "admitted application identity and the authenticated enrollment store (D02)"
        )
    trusted_verifier_keys = context.get("trusted_verifier_keys")
    expected_app = context.get("expected_app")
    enrollment_store = context.get("enrollment_store")
    accepted_environments = context.get("app_attest_environments")
    assertion_key_source = context.get("assertion_key_source")
    if not isinstance(trusted_verifier_keys, dict) or not trusted_verifier_keys:
        raise AttestationError(
            "context.trusted_verifier_keys is REQUIRED: a {key_id: ed25519 public key} map of verifier "
            "keys the caller pins; a self-declared verifier id is never sufficient"
        )
    # E03: the trusted verifier configuration must fix the accepted App Attest
    # enrollment environment and the authenticated assertion-key lookup.
    if accepted_environments != list(ACCEPTED_APP_ATTEST_ENVIRONMENTS):
        raise AttestationError(
            "context.app_attest_environments is REQUIRED and must be exactly %s: the enrollment "
            "environment(s) the verifier is configured to accept" % (list(ACCEPTED_APP_ATTEST_ENVIRONMENTS),)
        )
    if assertion_key_source not in ASSERTION_KEY_SOURCES:
        raise AttestationError(
            "context.assertion_key_source is REQUIRED and must be %r: the verifier resolves App Attest "
            "assertion keys through Apple's authenticated key provisioning, never from the request"
            % (ASSERTION_KEY_SOURCES[0],)
        )
    if (
        not isinstance(expected_app, dict)
        or set(expected_app) != {"app_id", "team_id"}
        or not isinstance(expected_app["app_id"], str)
        or not expected_app["app_id"]
        or not isinstance(expected_app["team_id"], str)
        or not expected_app["team_id"]
    ):
        raise AttestationError(
            "context.expected_app is REQUIRED and must be {app_id, team_id}: the admitted application "
            "identity the App Attest key must have been enrolled under"
        )
    if enrollment_store is None or not hasattr(enrollment_store, "lookup"):
        raise AttestationError(
            "context.enrollment_store is REQUIRED: the authenticated enrollment store whose records "
            "bind app keys to the admitted app identity (the assertion path never auto-enrolls)"
        )
    if not isinstance(expected_challenge, str) or not expected_challenge:
        raise AttestationError(
            "expected_challenge is REQUIRED: the relying party must compare against the fresh nonce "
            "it issued for THIS run (replay rejection)"
        )
    stateful = replay_state is not None
    if not stateful:
        # E03: the stateless fallback enforces BOTH duties consistently --
        # a per-key counter minimum AND an explicit consumed-challenge set.
        if not isinstance(min_counter, int) or isinstance(min_counter, bool) or min_counter < 0:
            raise AttestationError(
                "replay_state, or BOTH min_counter and consumed_challenges, is REQUIRED: the relying "
                "party must enforce a per-key counter minimum and single-use challenges; pass 0 "
                "explicitly for a first-seen key and adopt per-key state"
            )
        if consumed_challenges is None or not isinstance(consumed_challenges, (set, frozenset, list)):
            raise AttestationError(
                "stateless verification REQUIRES consumed_challenges: the caller's recorded set of "
                "already-consumed challenges (the library does not store state; production relying "
                "parties adopt replay_state)"
            )
    # 1. Receipt must be shape-valid for mac-attested and bound to these
    #    exact manifest bytes.
    validate_receipt(manifest_bytes, receipt)
    if receipt["environment"] != ENVIRONMENT_MAC_ATTESTED:
        raise AttestationError("attestation verification applies only to environment 'mac-attested' receipts")
    # 2. Structural report check with full type validation before use (D02).
    try:
        validate_verifier_report(report)
    except AttestationError as exc:
        raise AttestationError("verifier report rejected: %s" % exc) from exc
    # 3. AUTHENTICATION: ed25519 signature under a caller-pinned key (C01).
    sig = report["report_sig"]
    key_id = sig["key_id"]
    if not isinstance(key_id, str) or not key_id:
        raise AttestationError("report_sig.key_id must be a non-empty string")
    pinned = trusted_verifier_keys.get(key_id)
    if pinned is None:
        raise AttestationError(
            "report_sig.key_id is not in the caller's pinned verifier key map; an unsigned or "
            "unknown-key report is never trusted"
        )
    public_key = pinned if isinstance(pinned, (bytes, bytearray)) else _b64_32(pinned, "pinned key")
    if public_key is None:
        raise AttestationError("the pinned verifier key must be 32 ed25519 bytes (raw or base64)")
    if not isinstance(sig["sig_b64"], str):
        raise AttestationError("report_sig.sig_b64 must be a base64 string")
    try:
        signature = base64.b64decode(sig["sig_b64"], validate=True)
    except (binascii.Error, ValueError):
        raise AttestationError("report_sig.sig_b64 is not valid standard base64") from None
    if len(signature) != 64:
        raise AttestationError("report_sig.sig_b64 must decode to a 64-byte ed25519 signature")
    if report["verifier"]["key_id"] != key_id:
        raise AttestationError("verifier.key_id and report_sig.key_id must identify the same verifier key")
    if not ed25519.verify(bytes(public_key), signature, report_body(report)):
        raise AttestationError(
            "verifier report signature verification FAILED under the pinned key; the report is not "
            "authentic and the receipt is NOT attested"
        )
    # 4. Bindings: report subject must match the receipt and manifest bytes.
    errors = []
    subject = report["subject"]
    attestation = receipt["attestation"]
    app_key_id_b64 = report["apple"]["app_key_id_b64"]
    # D02: the report's app key must equal the receipt attestation's key.
    if app_key_id_b64 != attestation["key_id_b64"]:
        errors.append(
            "report.apple.app_key_id_b64 does not equal receipt.attestation.key_id_b64 (the replay "
            "state and the enrolled identity are scoped to THIS assertion's key)"
        )
    if subject["manifest_sha256"] != receipt["manifest_sha256"]:
        errors.append("report.manifest_sha256 does not match the receipt")
    if subject["manifest_sha256"] != sha256_hex(manifest_bytes):
        errors.append("report.manifest_sha256 does not match the manifest bytes")
    expected_attestation_digest = sha256_obj(attestation)
    if subject["attestation_sha256"] != expected_attestation_digest:
        errors.append("report.attestation_sha256 does not match the receipt attestation (altered Apple evidence)")
    expected_evidence = execution_evidence_digest(receipt)
    if subject["evidence_sha256"] != expected_evidence:
        errors.append(
            "report.evidence_sha256 does not match the recomputed execution evidence digest (altered "
            "execution evidence)"
        )
    if subject["challenge"] != attestation["challenge"]:
        errors.append("report.challenge does not match the receipt attestation challenge")
    if subject["challenge"] != expected_challenge:
        errors.append(
            "challenge is not the fresh challenge expected for this run (replayed evidence rejected)"
        )
    if consumed_challenges is not None and subject["challenge"] in consumed_challenges:
        errors.append("challenge was already consumed (replay rejected; relying-party state required)")
    if subject["counter"] != attestation["counter"]:
        errors.append("report.counter does not match the receipt attestation counter")
    if not stateful and attestation["counter"] < min_counter:
        errors.append(
            "attestation counter %d is below the accepted minimum %d (replayed/rolled-back key rejected)"
            % (attestation["counter"], min_counter)
        )
    if errors:
        raise AttestationError("; ".join(errors))
    # 5. AUTHENTICATED ENROLLMENT (D02 + R03 + S02): the app key must already
    #    be enrolled under the admitted application identity WITH its
    #    authenticated public-key material; the verifier's assertion-key
    #    lookup resolves from THIS record (algorithm-tagged P-256 assertion
    #    key, Apple key-identifier binding, app identity, counter state),
    #    never from the request. First use on the assertion path is never an
    #    enrollment.
    record = enrollment_store.lookup(app_key_id_b64)
    if record is None:
        raise AttestationError(
            "the assertion's App Attest key is not enrolled in the trusted enrollment store; a key "
            "seen for the first time on the assertion path is never auto-enrolled"
        )
    try:
        validate_enrollment_record(record)
    except AttestationError as exc:
        raise AttestationError("the enrolled record failed validation: %s" % exc) from None
    if record.get("app_id") != expected_app["app_id"] or record.get("team_id") != expected_app["team_id"]:
        raise AttestationError(
            "the assertion's App Attest key is not enrolled under the admitted application identity "
            "(launcher admission failed)"
        )
    # T02: the lookup is bound to the PERSISTED enrollment environment. The
    # production verifier proves the environment only at attestation time
    # (AAGUID in the attestation authData); assertions carry no environment,
    # so the enrolled provenance is authoritative here. A record enrolled
    # under an environment outside this context's accepted set rejects BEFORE
    # any assertion is accepted -- a development-enrolled key never verifies
    # in a production context.
    if record.get("environment") not in accepted_environments:
        raise AttestationError(
            "the enrolled record's environment (%s) is outside the accepted enrollment environments "
            "%s; the enrollment environment is authenticated provenance derived from the verified "
            "attestation AAGUID, persisted with the record and bound at every lookup"
            % (record.get("environment"), list(accepted_environments))
        )
    # S03: the effective counter floor spans BOTH stores -- the enrollment
    # record's persisted counter AND the replay store's persisted per-key
    # counter (when the store exposes the last_counter query, as
    # FileReplayState and InMemoryReplayState do). Advancement must be
    # STRICT beyond the floor: a counter EQUAL to the last accepted one is a
    # replay, not a first use. This closes the imported-record reset hole
    # (an enrollment imported with last_counter=100 can never admit
    # counter=1, and counter=100 is rejected as a replay too).
    counter_floor = record["last_counter"]
    replay_last_counter = getattr(replay_state, "last_counter", None)
    if callable(replay_last_counter):
        persisted_counter = replay_last_counter(app_key_id_b64)
        if not isinstance(persisted_counter, int) or isinstance(persisted_counter, bool) or persisted_counter < 0:
            raise AttestationError("the replay store's last_counter must return a non-negative integer")
        counter_floor = max(counter_floor, persisted_counter)
    if subject["counter"] <= counter_floor:
        raise AttestationError(
            "the assertion counter does not advance beyond the effective counter floor across the "
            "enrollment record and the replay store (replayed/rolled-back key rejected)"
        )
    # 6. ATOMIC replay state (D02): challenge consumption + per-key counter
    #    advancement happen under one lock, only after every binding check
    #    above passed. With replay_state, concurrency admits exactly one
    #    success; without it, the legacy min_counter/consumed_challenges
    #    checks (already applied above) stand and the caller adopts state.
    if stateful:
        try:
            replay_state.consume(subject["challenge"], app_key_id_b64, subject["counter"])
        except ReplayRejectedError as exc:
            raise AttestationError(str(exc)) from None
    return {
        "attested": True,
        "verifier": report["verifier"]["id"],
        "verifier_key_id": key_id,
        "app_key_id_b64": app_key_id_b64,
        "app_id": record["app_id"],
        "team_id": record["team_id"],
        "enrollment_environment": record["environment"],
        "manifest_sha256": receipt["manifest_sha256"],
        "evidence_sha256": expected_evidence,
        "challenge": subject["challenge"],
        "counter": subject["counter"],
        "note": (
            "attested=true means: the report was SIGNED by a caller-pinned verifier key, all bindings "
            "match, the key is enrolled under the admitted app identity, the challenge is fresh and the "
            "counter acceptable. This attests the App Attest evidence checked by that verifier -- it is "
            "NOT a hardware measurement of the Linux guest."
        ),
    }


def schema_of_verifier_report():
    """Parse and return the bundled verifier-report schema (parity helper)."""
    import os

    path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "schema")
    with open(os.path.join(path, "attestation-verifier.schema.json"), "rb") as handle:
        return load_json_bytes(handle.read(), "attestation-verifier schema")


__all__ = [
    "ASSERTION_DOMAIN",
    "ASSERTION_KEY_ALG",
    "ASSERTION_KEY_ENCODING",
    "ASSERTION_PUBLIC_KEY_KEYS",
    "DEVELOPMENT_AAGUIDS",
    "EVIDENCE_DOMAIN",
    "ENROLLMENT_ENVIRONMENTS",
    "ENROLLMENT_RECORD_KEYS",
    "FileReplayState",
    "InMemoryEnrollmentStore",
    "InMemoryReplayState",
    "PRODUCTION_AAGUID",
    "ReplayRejectedError",
    "assertion_payload",
    "check_report_against_schema",
    "environment_from_aaguid",
    "execution_evidence_digest",
    "expected_context_keys",
    "report_body",
    "validate_enrollment_record",
    "validate_verifier_report",
    "validate_verifier_report_bytes",
    "verify_attestation",
]
