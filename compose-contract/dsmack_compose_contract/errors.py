"""Errors for the dsmack app-compose contract validators (v3, contract3).

The contract is dstack-INSPIRED but not wire-compatible; see CONTRACT.json.
v3 adds the signed verifier-report boundary (AttestationError covers the
ed25519 signature check) and keeps LoweringError for the deterministic
fail-closed lowering paths.

Diagnostic hygiene (astra C08): every error message names field paths, types,
sizes and counts. Messages NEVER contain decoded input values, recomputed
digests of rejected input, or raw caller-controlled text.
"""


class ContractError(Exception):
    """Base class for all contract validation errors."""


class ManifestError(ContractError):
    """Workload manifest violates dsmack.app-compose/3."""


class ComposeSubsetError(ManifestError):
    """Embedded compose document uses something outside the supported subset.

    v3 policy: unsupported or forbidden fields FAIL explicitly with the key
    named -- they are never silently dropped. Any '$' in a compose string is
    rejected: compose tooling would expand it from ambient environment and
    this contract has no ambient host environment.
    """


class RuntimeInputError(ContractError):
    """Runtime-input envelope violates dsmack.runtime-input/3."""


class ReceiptError(ContractError):
    """Execution receipt violates dsmack.receipt/3."""


class AttestationError(ContractError):
    """Attestation verification failed or a verifier report is untrusted.

    Shape validation NEVER reports attestation success; only
    attestation.verify_attestation() can, and it requires a verifier report
    SIGNED by a caller-pinned ed25519 verifier key plus a fresh caller-issued
    challenge and an acceptable per-key counter. Unsigned or fabricated
    reports, replayed challenges, stale counters and altered evidence all
    raise AttestationError.
    """


class LoweringError(ContractError):
    """Deterministic lowering to Docker Compose cannot proceed (fail closed).

    Raised for a missing explicit daemon endpoint or run id, an unavailable
    requested runtime (e.g. runsc absent -- never a silent fallback), or a
    required credential broker that is not available.
    """


class SchemaViolation(ContractError):
    """A document does not conform to a contract schema (schema_check)."""


class ImageAdmissionError(ContractError):
    """Base-image admission or verified-byte boot verification failed (D01).

    Raised when a checksum manifest does not match its pins, an image
    identity is not externally admitted, or staged/boot bytes fail
    verification. Admission always fails closed: an unknown or mutated
    image is never booted and never silently substituted.
    """


class OCIIndexError(ContractError):
    """OCI index membership could not be verified against exact bytes (D03).

    Raised when index bytes do not hash to the requested pin, an index or
    child media type is unsupported, or the requested platform is absent or
    ambiguous. Membership is VERIFIED (content-addressed) or reported
    unchecked -- never asserted.
    """


class MultiError(ContractError):
    """Aggregates several validation errors found in one pass.

    The list is bounded (MAX_REPORTED_ERRORS) so adversarial inputs cannot
    make validation allocate without bound; when the bound is hit a final
    truncation marker is appended. Never raised empty.
    """

    MAX_REPORTED_ERRORS = 100

    def __init__(self, errors):
        errors = list(errors)
        if not errors:  # pragma: no cover - defensive; callers always add one
            errors = [ContractError("validation failed")]
        if len(errors) > self.MAX_REPORTED_ERRORS:
            errors = errors[: self.MAX_REPORTED_ERRORS]
            errors.append(ContractError("...further errors withheld (report bound reached)"))
        self.errors = errors
        super().__init__("; ".join(str(e) for e in self.errors))
