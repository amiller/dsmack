"""Contract library and Apple core imports shared with the guest and verifier/."""
import importlib.util
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]
CONTRACT_LIB = REPO / "base-vm/browser-sandbox-v1/source/runner-content/lib"
CORE_PY = REPO / "verifier/core.py"
sys.path.insert(0, str(CONTRACT_LIB))

from dsmack_compose_contract.canonical import (  # noqa: E402
    canonical_bytes, load_json_bytes, sha256_hex, sha256_obj)
from dsmack_compose_contract.attestation import (  # noqa: E402
    execution_evidence_digest, report_body, assertion_payload)
from dsmack_compose_contract.receipt import (  # noqa: E402
    validate_receipt_bytes)
from dsmack_compose_contract.runtime_inputs import (  # noqa: E402
    COMMITMENT_ALGS, validate_commitment_scope_shape, _normalized_scope,
    validate_runtime_inputs_bytes)
from dsmack_compose_contract import ed25519 as frozen_ed25519  # noqa: E402
from dsmack_compose_contract.errors import (  # noqa: E402
    ContractError, ReceiptError, AttestationError)


def _load_core():
    spec = importlib.util.spec_from_file_location("appattest_core", CORE_PY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


core = _load_core()

__all__ = [
    "canonical_bytes", "load_json_bytes", "sha256_hex", "sha256_obj",
    "execution_evidence_digest", "report_body", "assertion_payload",
    "validate_receipt_bytes", "COMMITMENT_ALGS",
    "validate_commitment_scope_shape", "_normalized_scope",
    "validate_runtime_inputs_bytes", "frozen_ed25519",
    "ContractError", "ReceiptError", "AttestationError",
    "core",
]
