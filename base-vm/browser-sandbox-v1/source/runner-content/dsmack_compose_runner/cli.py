"""The compose-runner CLI.

Exact commands (also exercised by the regression tests):

  dsmack-compose-runner validate <manifest.json>
  dsmack-compose-runner validate-inputs <manifest.json> <envelope.json>
  dsmack-compose-runner hash <manifest.json>
  dsmack-compose-runner run <manifest.json> [--envelope envelope.json]
      --run-id ID --workspace-root DIR --control-dir DIR
      --base-bundle DIR --admission DOC
      [--receipt-out PATH] [--summary-out PATH]
      --daemon-endpoint unix://...   (REQUIRED; the only endpoint source)

Every failure exits nonzero with `runner-error <code>` on stderr and NO
fabricated receipt. Successful runs print the receipt summary as JSON.
"""

from __future__ import annotations

import argparse
import json
import sys

from dsmack_compose_contract import (
    canonical_bytes,
    sha256_hex,
    validate_manifest_bytes,
    validate_runtime_inputs_bytes,
)
from dsmack_compose_contract.errors import MultiError

from .errors import RunnerError
from .runner import run_manifest


def _cmd_validate(args) -> int:
    with open(args.manifest, "rb") as handle:
        raw = handle.read()
    manifest, summary = validate_manifest_bytes(raw)
    print(
        json.dumps(
            {
                "manifest_sha256": summary["manifest_sha256"],
                "manifest_bytes": len(raw),
                "name": manifest["name"],
                "services": summary.get("services", summary.get("service_names")),
                "runner": {
                    "runtime_name": manifest["runner"]["runtime_name"],
                    "runtime_version": manifest["runner"]["runtime_version"],
                    "compose_tool": manifest["runner"]["compose_tool"]["version"],
                },
                "image_platform": manifest["image_platform"],
                "base_vm_os_image_hash": manifest["base_vm"]["os_image_hash"],
                "status": "valid",
            },
            indent=1,
            sort_keys=True,
        )
    )
    return 0


def _cmd_validate_inputs(args) -> int:
    with open(args.manifest, "rb") as handle:
        manifest_raw = handle.read()
    with open(args.envelope, "rb") as handle:
        envelope_raw = handle.read()
    summary = validate_runtime_inputs_bytes(manifest_raw, envelope_raw)
    print(json.dumps(summary, indent=1, sort_keys=True))
    return 0


def _cmd_hash(args) -> int:
    with open(args.manifest, "rb") as handle:
        raw = handle.read()
    manifest, summary = validate_manifest_bytes(raw)
    print(json.dumps({"manifest_sha256": sha256_hex(raw), "bytes": len(raw)}, indent=1))
    return 0


def _cmd_run(args) -> int:
    with open(args.manifest, "rb") as handle:
        manifest_raw = handle.read()
    # Validate BEFORE anything operational (the exact bytes are the identity).
    validate_manifest_bytes(manifest_raw)
    envelope_raw = None
    if args.envelope:
        with open(args.envelope, "rb") as handle:
            envelope_raw = handle.read()
    broker = None
    if getattr(args, "broker_endpoint", None):
        # F02: the broker is supplied by the harness/pinned adapter (it launches
        # the per-run sentinel holding the credential); the runner renders this
        # workload-reachable endpoint and never sees the credential itself.
        broker = {"endpoint": args.broker_endpoint}
    receipt, summary = run_manifest(
        manifest_raw,
        envelope_bytes=envelope_raw,
        daemon_endpoint=args.daemon_endpoint,
        run_id=args.run_id,
        workspace_root=args.workspace_root,
        control_dir=args.control_dir,
        base_bundle_dir=args.base_bundle,
        admission_path=args.admission,
        receipt_out_path=args.receipt_out,
        summary_out_path=args.summary_out,
        export_artifacts_dir=args.export_artifacts,
        export_outputs_dir=args.export_outputs,
        broker=broker,
        environment=args.environment,
        boot_observations_path=args.boot_observations,
    )
    print(json.dumps({"status": summary["status"], "exit_code": summary["exit_code"], "receipt_written": bool(args.receipt_out)}, indent=1))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dsmack-compose-runner",
        description="dsmack app-compose Linux/Docker-Compose runner (linux-test receipts; unattested)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("validate", help="validate exact manifest bytes")
    p.add_argument("manifest")
    p.set_defaults(func=_cmd_validate)

    p = sub.add_parser("validate-inputs", help="validate a runtime-input envelope against exact manifest bytes")
    p.add_argument("manifest")
    p.add_argument("envelope")
    p.set_defaults(func=_cmd_validate_inputs)

    p = sub.add_parser("hash", help="exact-bytes manifest digest")
    p.add_argument("manifest")
    p.set_defaults(func=_cmd_hash)

    p = sub.add_parser("run", help="admit, lower, execute, collect, receipt")
    p.add_argument("manifest")
    p.add_argument("--envelope", default=None, help="runtime-input envelope JSON (exact bytes validated)")
    p.add_argument("--run-id", required=True, help="fresh per-run identifier (never reused)")
    p.add_argument("--daemon-endpoint", required=True, help="EXPLICIT unix:// or tcp:// docker endpoint")
    p.add_argument("--workspace-root", required=True)
    p.add_argument("--control-dir", required=True)
    p.add_argument("--base-bundle", required=True, help="admitted dstack bundle dir (sha256sum.txt + 4 components)")
    p.add_argument("--admission", required=True, help="external admission document JSON")
    p.add_argument("--receipt-out", default=None)
    p.add_argument("--summary-out", default=None)
    p.add_argument("--export-artifacts", default=None, help="EXPLICIT public export dir for recorded artifacts (legacy, artifact-only)")
    p.add_argument("--export-outputs", default=None,
                   help="EXPLICIT SHARED result-image ROOT dir for the COMPLETE output package in the "
                        "CANONICAL guest layout: <root>/<selector>/receipt.json + "
                        "<root>/<selector>/outputs/{index.json,streams/<s>,artifacts/<name>,EXPORT-COMPLETE} "
                        "where <selector> is the MANIFEST NAME (multi-selector: one subtree per manifest); "
                        "the per-selector outputs/EXPORT-COMPLETE marker is published LAST through a "
                        "fail-distinguishable protocol, written through the lifecycle before cleanup")
    p.add_argument("--broker-endpoint", default=None,
                   help="F02: workload-reachable per-run sentinel endpoint supplied by the harness/"
                        "pinned adapter for credential profiles (http://<gw-ip>:<port>/<token>); the "
                        "runner never sees the credential. Omit for credential-free runs.")
    p.add_argument("--environment", choices=("linux-test", "vm"), default="linux-test",
                   help="VM-OBSERVATIONS: receipt execution environment. 'linux-test' (default; "
                        "host-Docker reproduction) records boot=null. 'vm' records the frozen VM boot "
                        "shape and REQUIRES --boot-observations gathered from the running VM; a missing "
                        "observation fails closed (null boot is never relabelled as a VM boot).")
    p.add_argument("--boot-observations", default=None,
                   help="VM-OBSERVATIONS: path to the JSON boot observation "
                        "(dsmack.vm-boot-observation/1: loader_mode + consumed component sha256s + "
                        "booted cmdline + verity geometry) gathered from the running VM. Required with "
                        "--environment vm; the receipt self-check binds it to the admitted manifest.")
    p.set_defaults(func=_cmd_run)
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except RunnerError as exc:
        print("runner-error %s" % exc.code, file=sys.stderr)
        print(exc.message, file=sys.stderr)
        return 2
    except MultiError as exc:
        # Contract-library validation refusal (manifest/envelope/receipt).
        # Value-free: the messages name fields, not caller values.
        print("runner-error contract-invalid", file=sys.stderr)
        print("%d contract violation(s); first: %s" % (len(exc.errors), exc.errors[0]), file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - the CLI boundary reports, never crashes raw
        print("runner-error internal", file=sys.stderr)
        print("%s" % exc, file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
