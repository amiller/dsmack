"""Install the measured guest egress policy: python3 -m dsmack_compose_contract.egress MANIFEST."""
import subprocess
import sys
from pathlib import Path

from .lowering import render_egress_rules
from .manifest import validate_manifest_bytes


def apply(manifest_bytes):
    manifest, _ = validate_manifest_bytes(manifest_bytes)
    subprocess.run(["/usr/sbin/nft", "-f", "-"], input=render_egress_rules(manifest).encode(),
                   check=True, timeout=30)


if __name__ == "__main__":
    apply(Path(sys.argv[1]).read_bytes())
