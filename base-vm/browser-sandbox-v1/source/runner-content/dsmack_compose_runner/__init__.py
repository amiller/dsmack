"""dsmack compose-runner: the Linux/Docker-Compose execution runner.

Consumes the shared contract library (``dsmack_compose_contract``) READ-ONLY
for every contract decision -- validation, lowering, delivery planning,
admission and receipt validation -- and implements ONLY the operational
duties the contract assigns to the runner: control-process isolation, live
image/runtime identity resolution, input materialization, the frozen compose
lifecycle, limits, cancellation, output collection, cleanup and receipt
assembly.

Environment honesty is structural: this runner emits ONLY ``linux-test``
receipts (``boot: null``, ``attestation: null``). It never runs or claims a
VM boot, a Mac, App Attest, or any attested execution domain.
"""

from .errors import RunnerError

__version__ = "1.0.0"

__all__ = ["RunnerError", "__version__"]
