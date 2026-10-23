"""Installed ``dsmack-guest-io`` CLI — invoked by the trusted guest supervisor.

Subcommands:

  extract-private DEVICE DEST
      Read the raw UNMEASURED private-input device (vde) and safely extract it
      into the FRESH 0700 directory DEST (0600 files, 0700 dirs).  DEST must not
      already exist.  On any transport refusal it prints
      ``DSMACK_PRIVATE_TRANSPORT_REFUSED <rule>`` to stderr and exits nonzero
      WITHOUT leaving a partial tree — there is NO measured-private fallback.
      On success it prints ONLY a count summary (never file names or content):
      ``DSMACK_PRIVATE_TRANSPORT_OK entries=N dirs=D files=F``.

  verify-private DEVICE
      Dry-run: fully parse/admit the transport and print the same count summary
      without writing anything.  Used by the host-unit tests and as a cheap
      pre-flight.

  oci-serve ...  / oci-verify ...
      Portable offline digest-preserving OCI publisher (see oci_publish.py).

Exit codes: 0 success; 2 transport refusal (fail closed); 3 usage/IO error.
"""
from __future__ import annotations

import argparse
import json
import sys

from . import private_transport as pt


def _summary_counts(entries):
    dirs = sum(1 for _n, is_dir, _o, _s in entries if is_dir)
    files = len(entries) - dirs
    return len(entries), dirs, files


def _cmd_extract_private(args) -> int:
    try:
        entries, _created = pt.extract_device(args.device, args.dest)
    except pt.TransportRefusal as exc:
        print("DSMACK_PRIVATE_TRANSPORT_REFUSED %s" % exc.rule, file=sys.stderr)
        return 2
    n, d, f = _summary_counts(entries)
    print("DSMACK_PRIVATE_TRANSPORT_OK entries=%d dirs=%d files=%d" % (n, d, f))
    return 0


def _cmd_verify_private(args) -> int:
    try:
        blob = pt.read_image(args.device)
        entries = pt.parse_entries(blob)
    except pt.TransportRefusal as exc:
        print("DSMACK_PRIVATE_TRANSPORT_REFUSED %s" % exc.rule, file=sys.stderr)
        return 2
    n, d, f = _summary_counts(entries)
    print("DSMACK_PRIVATE_TRANSPORT_OK entries=%d dirs=%d files=%d" % (n, d, f))
    return 0


def _cmd_admit_public_toc(args) -> int:
    """GIO03: structurally admit the measured public vdc archive BEFORE
    extraction (regular/dir only, no absolute/.. path, allowlisted top-level),
    reading exact names from the tar headers (whitespace + hidden entries
    exact).  Writes nothing."""
    from . import public_toc
    try:
        n = public_toc.admit_archive(args.archive)
    except public_toc.PublicTocRefusal as exc:
        print("DSMACK_WORKLOAD_TOC_REFUSED %s" % exc, file=sys.stderr)
        return 2
    print("DSMACK_WORKLOAD_TOC_ADMITTED %d" % n)
    return 0


def _cmd_boot_observe(args) -> int:
    """VM-OBSERVATIONS: emit a boot observation gathered from LIVE kernel state
    (exact /proc/cmdline tokens + active dm-verity root), bound to the admitted
    bundle recorded claims (not preboot consumed-byte proof). Writes the observation JSON to --out and a marker line to
    stdout. Fails closed (exit 2) if the live state does not match the admitted
    bundle -- null/wrong boot data is never relabelled as a VM boot."""
    from . import boot_observe
    try:
        with open(args.live_cmdline, encoding="utf-8", newline="") as stream:
            live_cmdline = stream.read()
        verity_text = open(args.verity_table).read() if args.verity_table else ""
        obs = boot_observe.build_observation(args.bundle_dir, live_cmdline, verity_text,
                                             loader_mode=args.loader_mode,
                                             loader_observation=json.load(open(args.loader_observation)) if args.loader_observation else None,
                                             mountinfo_text=open(args.mountinfo).read(),
                                             dm_info_text=open(args.dm_info).read())
    except boot_observe.BootObservationError as exc:
        print("DSMACK_VM_OBS_FAIL %s" % exc, file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        print("DSMACK_VM_OBS_FAIL io-error %s" % exc, file=sys.stderr)
        return 2
    with open(args.out, "w") as fh:
        json.dump(obs, fh, sort_keys=True)
    print("DSMACK_VM_BOOT_OBSERVED root=%s data_bytes=%d loader_claim=%s component_origin=admitted-docs provenance=external-join-required"
          % (obs["verity_root_hash"], obs["verity_data_bytes"], obs["loader_mode"]))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dsmack-guest-io",
        description="measured guest-image I/O helpers (private transport + offline OCI publisher)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("extract-private", help="safely extract the vde private-input device")
    p.add_argument("device")
    p.add_argument("dest")
    p.set_defaults(func=_cmd_extract_private)

    p = sub.add_parser("verify-private", help="dry-run admit the vde transport (no write)")
    p.add_argument("device")
    p.set_defaults(func=_cmd_verify_private)

    p = sub.add_parser("admit-public-toc",
                       help="GIO03: structurally admit the measured public vdc archive (no write)")
    p.add_argument("archive")
    p.set_defaults(func=_cmd_admit_public_toc)

    p = sub.add_parser("boot-observe",
                       help="VM-OBSERVATIONS: gather a live boot observation (exact cmdline + active verity)")
    p.add_argument("bundle_dir")
    p.add_argument("--live-cmdline", default="/proc/cmdline")
    p.add_argument("--verity-table", default=None,
                   help="file holding the live dmsetup table / veritysetup status output")
    p.add_argument("--loader-mode", choices=("held-fd", "owned-copy"), required=True, help="Recorded admitted mode claim; requires external authenticated full boot join")
    p.add_argument("--loader-observation", default=None, help="Optional engineering consistency claims only; not authentication")
    p.add_argument("--mountinfo", default="/proc/self/mountinfo")
    p.add_argument("--dm-info", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(func=_cmd_boot_observe)

    # OCI publisher subcommands are registered lazily (optional import) so the
    # private-transport path never depends on the publisher module loading.
    try:
        from . import oci_publish
        oci_publish.register_subcommands(sub)
    except Exception:  # noqa: BLE001 - the publisher is optional at parse time
        pass
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print("dsmack-guest-io: not found: %s" % exc.filename, file=sys.stderr)
        return 3
    except pt.TransportRefusal as exc:  # defensive; subcommands catch their own
        print("DSMACK_PRIVATE_TRANSPORT_REFUSED %s" % exc.rule, file=sys.stderr)
        return 2
    except OSError as exc:
        print("dsmack-guest-io: io-error %s" % exc, file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
