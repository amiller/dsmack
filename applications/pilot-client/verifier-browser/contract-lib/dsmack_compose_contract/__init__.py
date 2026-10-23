"""dsmack app-compose contract validators v4 (contract4; Python 3.10+ stdlib only).

Contract: dsmack.app-compose/4, dsmack.runtime-input/4, dsmack.receipt/4,
plus the separate dsmack.appattest-verifier/2 SIGNED report domain.
dstack-INSPIRED, explicitly NOT wire-compatible. See CONTRACT.json.
This package validates contracts and lowers manifests deterministically;
it implements no runtime and performs no attestation cryptography (the
ed25519 module verifies verifier-report signatures only).

contract4 = repair of contract3 under contract3-review D01-D11:
image admission + verified-byte boot identity (image_admission), OCI index
verification (oci_index), trusted verifier context/enrollment/replay
(attestation), bounded multi-service lowering, runtime closure, value-free
diagnostics, and an evidence-backed acceptance freeze.
"""

from .attestation import (
    ASSERTION_DOMAIN,
    EVIDENCE_DOMAIN,
    InMemoryEnrollmentStore,
    InMemoryReplayState,
    ReplayRejectedError,
    assertion_payload,
    execution_evidence_digest,
    report_body,
    validate_verifier_report,
    validate_verifier_report_bytes,
    verify_attestation,
)
from .canonical import (
    canonical_bytes,
    canonicalize,
    exact_and_canonical_sha256,
    sha256_hex,
    sha256_obj,
)
from .errors import (
    AttestationError,
    ComposeSubsetError,
    ContractError,
    ImageAdmissionError,
    LoweringError,
    ManifestError,
    MultiError,
    OCIIndexError,
    ReceiptError,
    RuntimeInputError,
    SchemaViolation,
)
from .image_admission import (
    COMPONENT_PATHS,
    admit_image,
    os_image_hash,
    parse_admission,
    parse_checksum_manifest,
    reverify_fd,
    verify_and_hold,
    verify_base_vm_identity,
)
from .lowering import WORKLOAD_GID, WORKLOAD_UID, lower, render_compose_file
from .manifest import (
    ADAPTER_PROFILES,
    ARCH_COMPAT,
    ARTIFACTS_ROOT,
    CONTRACT_WORKSPACE_ROOT,
    DEFAULT_USER_CONFIG_TARGET,
    INPUTS_ROOT,
    MAX_SERVICES,
    REGISTERED_RUNTIMES,
    RESERVED_ENV_NAMES,
    RESERVED_ENV_PREFIXES,
    RESERVED_SLOT_NAMES,
    RUNTIME_RUNSC,
    RUNTIME_RUNSC_HOSTNET,
    RUNTIME_RUNC,
    SHARED_ROOT,
    STATE_ROOT,
    SUPPORTED_ARCHITECTURES,
    validate_compose_document,
    validate_manifest,
    validate_manifest_bytes,
)
from .oci_index import verify_index_membership
from .receipt import validate_receipt, validate_receipt_bytes
from .report_adapter import (
    VERIFIER_REQUEST_KEYS,
    VERIFIER_REQUEST_VERSION,
    attestation_from_request,
    attestation_sha256_from_request,
    parse_verifier_request,
    produce_verifier_report,
    report_subject_from_request,
)
from .runtime_inputs import (
    COMMITMENT_ALGS,
    MAX_ENVELOPE_BYTES,
    SECRET_COMMITMENT_ALG,
    TASK_COMMITMENT_ALG,
    canonical_b64,
    compute_commitment,
    delivery_plan,
    redact,
    validate_commitment_scope_shape,
    validate_runtime_inputs,
    validate_runtime_inputs_bytes,
)
from .schema_check import SchemaViolation, validate as schema_validate

__version__ = "4.0.0"

__all__ = [
    "ADAPTER_PROFILES",
    "ARCH_COMPAT",
    "ARTIFACTS_ROOT",
    "ASSERTION_DOMAIN",
    "AttestationError",
    "COMPONENT_PATHS",
    "COMMITMENT_ALGS",
    "CONTRACT_WORKSPACE_ROOT",
    "ComposeSubsetError",
    "ContractError",
    "DEFAULT_USER_CONFIG_TARGET",
    "EVIDENCE_DOMAIN",
    "ImageAdmissionError",
    "InMemoryEnrollmentStore",
    "InMemoryReplayState",
    "INPUTS_ROOT",
    "LoweringError",
    "MAX_SERVICES",
    "ManifestError",
    "MAX_ENVELOPE_BYTES",
    "MultiError",
    "OCIIndexError",
    "REGISTERED_RUNTIMES",
    "RESERVED_ENV_NAMES",
    "RESERVED_ENV_PREFIXES",
    "RESERVED_SLOT_NAMES",
    "RUNTIME_RUNSC",
    "RUNTIME_RUNSC_HOSTNET",
    "RUNTIME_RUNC",
    "ReplayRejectedError",
    "ReceiptError",
    "SECRET_COMMITMENT_ALG",
    "SHARED_ROOT",
    "STATE_ROOT",
    "SUPPORTED_ARCHITECTURES",
    "SchemaViolation",
    "RuntimeInputError",
    "TASK_COMMITMENT_ALG",
    "VERIFIER_REQUEST_KEYS",
    "VERIFIER_REQUEST_VERSION",
    "WORKLOAD_GID",
    "WORKLOAD_UID",
    "admit_image",
    "assertion_payload",
    "attestation_from_request",
    "attestation_sha256_from_request",
    "canonical_b64",
    "canonical_bytes",
    "canonicalize",
    "compute_commitment",
    "delivery_plan",
    "exact_and_canonical_sha256",
    "execution_evidence_digest",
    "lower",
    "os_image_hash",
    "parse_admission",
    "parse_checksum_manifest",
    "parse_verifier_request",
    "produce_verifier_report",
    "redact",
    "report_subject_from_request",
    "render_compose_file",
    "report_body",
    "reverify_fd",
    "schema_validate",
    "sha256_hex",
    "sha256_obj",
    "validate_commitment_scope_shape",
    "validate_compose_document",
    "validate_manifest",
    "validate_manifest_bytes",
    "validate_receipt",
    "validate_receipt_bytes",
    "validate_runtime_inputs",
    "validate_runtime_inputs_bytes",
    "validate_verifier_report",
    "validate_verifier_report_bytes",
    "verify_and_hold",
    "verify_attestation",
    "verify_base_vm_identity",
    "verify_index_membership",
    "__version__",
]
