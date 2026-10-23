"""Pinned read-only imports of the frozen contract10 library and Apple core.

Every import is hash-gated: if the frozen bytes on disk change, this module
refuses to import them (the reference is only valid against the exact
reviewed dependencies).  Nothing here edits other owners' trees.
"""
import hashlib
import importlib.util
import sys
from pathlib import Path

# Package-relative placement only; all original reviewed dependency digests
# remain unchanged except the explicitly derived closed browser manifest extension. B/JOINED are compatibility aliases, not original host paths.
PACKAGE_ROOT = Path(__file__).resolve().parents[1]
B = PACKAGE_ROOT
JOINED = PACKAGE_ROOT
CONTRACT10_LIB = PACKAGE_ROOT / "contract-lib"
CORE_PY = PACKAGE_ROOT / "apple-core/core.py"
CORE_SHA256 = "13214b3711f2c69e145a11eee22c3f1c522d7d63f535bcf1ba5f5f9804ea8cb5"

FROZEN_PINS = {str(PACKAGE_ROOT / relative): digest for relative, digest in {'contract-lib/dsmack_compose_contract/__init__.py': '0b2379fdd3681b5c1eea1250ba63256e83a3d8e1c8a9ea2ad216d3067aa91f2f', 'contract-lib/dsmack_compose_contract/__main__.py': 'd3659ee70c3363fe42909825371a72665fb3043432c556524a32456bdccc29eb', 'contract-lib/dsmack_compose_contract/attestation.py': '8dbb839e921b8cff1f146d50c2ed07e3b1f4241433c8bbfc4de6e0a1f8fae6c3', 'contract-lib/dsmack_compose_contract/canonical.py': '9d8be2083dff2d3d261bb53aa3d6605fe35a4d43d3958bc40f5c2b9012f13037', 'contract-lib/dsmack_compose_contract/ed25519.py': '0a5d0b36f759cee5b232dc819e7c04de7d71c4607c6e77a9d8c80f1fc80e2ee7', 'contract-lib/dsmack_compose_contract/errors.py': '5eb10e5969e905f4932deb709c3961e1eedc6986ab360058bfd51b30e4d82052', 'contract-lib/dsmack_compose_contract/image_admission.py': '47c6375204a6c04f19cfe909c716f9497aa076e8f917edaeb596b4b24dd56379', 'contract-lib/dsmack_compose_contract/lowering.py': '1648def74bfcde268ad0f855f2543ca8e5eb8304f566a1ffe4315a600b328b07', 'contract-lib/dsmack_compose_contract/manifest.py': 'd041ecae81051bdc2bd3d196ea55eefee491caddf0fecf51060358201df3b5f9', 'contract-lib/dsmack_compose_contract/oci_index.py': '94a625cee7491055bb9f8a2d0017d0d79c38b790563e1b3aa5e10a8af57f6cb3', 'contract-lib/dsmack_compose_contract/receipt.py': '3f25dbead69d07b7caa78414132e10f3278e176f10d1abe2f09d8cfd7955ca72', 'contract-lib/dsmack_compose_contract/report_adapter.py': 'aeca885bb9f2029ba4052607d16b25a2b54431ec953f68248518d8c24f72d2d6', 'contract-lib/dsmack_compose_contract/runtime_inputs.py': '151cede062fa6b58a4645a39257289e52c64f2d08b2605235498a979fa5caa8e', 'contract-lib/dsmack_compose_contract/schema_check.py': 'a5ad2e1273e764575918fb680787b592daa95304f839c8468984c7748cbbcb0d', 'apple-core/core.py': '13214b3711f2c69e145a11eee22c3f1c522d7d63f535bcf1ba5f5f9804ea8cb5'}.items()}


def _pin_check():
    actual = {str(p) for p in CONTRACT10_LIB.rglob("*.py")}
    expected = set(FROZEN_PINS) - {str(CORE_PY)}
    if actual != expected:
        raise RuntimeError("frozen contract module membership changed")
    for path, want in FROZEN_PINS.items():
        got = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        if got != want:
            raise RuntimeError(
                "frozen dependency changed: %s sha256 %s != pinned %s"
                % (path, got, want))


_pin_check()

if str(CONTRACT10_LIB) not in sys.path:
    sys.path.insert(0, str(CONTRACT10_LIB))

# Frozen /4 contract with explicitly reviewed closed browser manifest extension.
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


#: Pinned Apple App Attest core (verify_assertion / verify_attestation,
#: Policy, Reject).  No oracle port: this IS the reviewed implementation.
core = _load_core()

__all__ = [
    "canonical_bytes", "load_json_bytes", "sha256_hex", "sha256_obj",
    "execution_evidence_digest", "report_body", "assertion_payload",
    "validate_receipt_bytes", "COMMITMENT_ALGS",
    "validate_commitment_scope_shape", "_normalized_scope",
    "validate_runtime_inputs_bytes", "frozen_ed25519",
    "ContractError", "ReceiptError", "AttestationError",
    "core", "CORE_SHA256", "B", "JOINED",
]
