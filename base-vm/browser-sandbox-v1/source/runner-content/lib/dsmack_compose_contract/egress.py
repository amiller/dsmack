"""Install the measured guest egress policy: python3 -m dsmack_compose_contract.egress [MANIFEST].

Without a manifest it installs the loopback-only table the supervisor needs before the NIC comes up.
"""
import subprocess
import sys
from pathlib import Path

from .lowering import render_egress_rules
from .manifest import validate_manifest_bytes


def apply(manifest_bytes=None):
    manifest = validate_manifest_bytes(manifest_bytes)[0] if manifest_bytes is not None else {"network": {}}
    subprocess.run(["/usr/sbin/nft", "-f", "-"], input=render_egress_rules(manifest).encode(),
                   check=True, timeout=30)


if __name__ == "__main__":
    apply(Path(sys.argv[1]).read_bytes() if len(sys.argv) > 1 else None)
