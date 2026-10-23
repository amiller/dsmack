#!/usr/bin/env python3
"""Extract the guest-written export disk (ext4, vdd image) WITHOUT mounting it
(debugfs in the builder container; the host never mounts guest state), then
verify the receipts with the frozen contract library (validate_receipt against
the exact manifest bytes + envelope bytes).

Usage:
  python3 extract_export.py <export.img> <outdir>
Expects the disk layout written by the guest supervisor:
  /<name>/receipt.json, /<name>/summary.json, /<name>/artifacts/*,
  /<name>.validate.out, /<name>.run.out, /<name>.run.err, RESULT-dockerd.console
"""
import json
import os
import subprocess
import sys

LANE = "/data/amiller/dsmack/attested-runner-20261020/dstack-runner-join"
LIB = "/data/amiller/dsmack/attested-runner-20261020/contract10/candidate/lib"
INPUTS = os.path.join(LANE, "build", "runner-inputs")


def extract(img, outdir):
    os.makedirs(outdir, exist_ok=True)
    # debugfs runs unprivileged in the builder container; rdump copies the tree.
    cmd = ["docker", "run", "--rm", "-v", f"{os.path.dirname(img)}:/d:ro",
           "-v", f"{outdir}:/out", "dsmack-dstack-arm64/builder:trixie-20260721",
           "bash", "-c",
           "debugfs -R 'rdump / /out' /d/" + os.path.basename(img) + " 2>&1 | tail -5; "
           "debugfs -R 'ls -l /' /d/" + os.path.basename(img) + " 2>/dev/null | head -20"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    print(r.stdout)
    if r.returncode != 0:
        print(r.stderr, file=sys.stderr)
        raise SystemExit("debugfs extraction failed")
    # rdump copies "." and ".." entries into /out as well; flatten one level
    dot = os.path.join(outdir, ".")
    for entry in os.listdir(outdir):
        src = os.path.join(outdir, entry)
        if entry == "lost+found":
            continue
    return outdir


def verify_receipts(outdir):
    sys.path.insert(0, LIB)
    from dsmack_compose_contract import validate_receipt_bytes
    results = {}
    for name in ("greet-sh", "pycompute"):
        d = os.path.join(outdir, name)
        receipt_path = os.path.join(d, "receipt.json")
        if not os.path.isfile(receipt_path):
            results[name] = {"present": False}
            continue
        manifest_raw = open(os.path.join(INPUTS, "manifests", f"{name}.app-compose.json"), "rb").read()
        envelope_raw = None
        env_path = os.path.join(INPUTS, "envelopes", f"{name}.envelope.json")
        if os.path.isfile(env_path):
            envelope_raw = open(env_path, "rb").read()
        receipt_bytes = open(receipt_path, "rb").read()
        try:
            verdict = validate_receipt_bytes(manifest_raw, receipt_bytes, envelope_bytes=envelope_raw)
            receipt = json.loads(receipt_bytes)
            results[name] = {
                "present": True,
                "validate_receipt": "PASS",
                "status": receipt["outputs"]["status"],
                "exit_code": receipt["outputs"]["exit_code"],
                "verdict_keys": sorted(verdict.keys()),
            }
        except Exception as exc:  # noqa: BLE001
            results[name] = {"present": True, "validate_receipt": "FAIL", "error": str(exc)[:300]}
    return results


if __name__ == "__main__":
    img, outdir = sys.argv[1], sys.argv[2]
    extract(img, outdir)
    results = verify_receipts(outdir)
    print(json.dumps(results, indent=1))
    json.dump(results, open(os.path.join(outdir, "receipt-verification.json"), "w"), indent=1)
