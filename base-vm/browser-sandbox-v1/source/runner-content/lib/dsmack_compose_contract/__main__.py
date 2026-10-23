"""CLI for the dsmack app-compose contract validators (v4, contract4).

Usage:
  PYTHONPATH=lib python3 -m dsmack_compose_contract <command> [args]

Commands:
  validate-manifest FILE                 validate a workload manifest; prints
                                         the EXACT-BYTES manifest_sha256 (the
                                         manifest identity)
  validate-inputs MANIFEST FILE          validate a runtime-input envelope
  validate-receipt MANIFEST FILE [--envelope FILE]
                                         validate an execution receipt; with
                                         --envelope, cross-checks the recorded
                                         commitment against it; NEVER reports
                                         attestation success
  redact-inputs MANIFEST FILE            validate first, then print the
                                         redacted names/sizes form
  verify-attestation MANIFEST RECEIPT REPORT --verifier-key KEY
                                         --verifier-key-id ID --challenge C
                                         --app-id A --team-id T
                                         --enrollment-store FILE
                                         --replay-state FILE
                                         the ONLY command that can report
                                         attested=true; requires a trusted
                                         verifier context (pinned key, admitted
                                         app identity, authenticated enrollment
                                         store carrying the algorithm-tagged
                                         Apple assertion key, its persisted
                                         AAGUID-derived environment and its
                                         counter state) plus a fresh challenge
                                         and explicit flock-serialized replay
                                         state (C01/D02/R03/S02/S03/T02)
  lower MANIFEST --daemon-endpoint ENDPOINT --run-id ID [--workspace-host-dir DIR]
                                         [--broker-endpoint URL]
                                         [--sentinel-endpoint URL]
                                         deterministic lowering to execution
                                         config + generated compose file
  hash FILE                              exact-bytes and canonical sha256 under
                                         the SAME strict parser

Diagnostics on stderr are value-free (field paths, types, sizes, counts; D06).
Reads are BOUNDED before parsing (D05). Output: a JSON object on stdout.
Exit 0 on success, 1 on contract violation, 2 on usage/IO errors.
"""

import argparse
import json
import sys

from .canonical import exact_and_canonical_sha256
from .errors import ContractError
from .lowering import lower, render_compose_file
from .manifest import validate_manifest_bytes
from .receipt import validate_receipt_bytes
from .runtime_inputs import MAX_ENVELOPE_BYTES, redact, validate_runtime_inputs_bytes

#: CLI read bound (D05): raw reads never exceed the parse bound before the
#: parser can reject oversize documents.
CLI_READ_BOUND = MAX_ENVELOPE_BYTES


def _read(path):
    with open(path, "rb") as handle:
        data = handle.read(CLI_READ_BOUND + 1)
    if len(data) > CLI_READ_BOUND:
        raise ContractError("%s exceeds the %d-byte read bound" % (path, CLI_READ_BOUND))
    return data


def _emit(payload):
    json.dump(payload, sys.stdout, indent=2, sort_keys=True, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


def _run(args):
    if args.command == "validate-manifest":
        raw = _read(args.file)
        _manifest, summary = validate_manifest_bytes(raw)
        return _emit({"ok": True, "kind": "manifest", **summary})

    if args.command == "validate-inputs":
        manifest_raw = _read(args.manifest)
        envelope_raw = _read(args.file)
        summary = validate_runtime_inputs_bytes(manifest_raw, envelope_raw)
        return _emit({"ok": True, "kind": "runtime-inputs", **summary})

    if args.command == "validate-receipt":
        from .receipt import verify_receipt_index_membership

        manifest_raw = _read(args.manifest)
        receipt_raw = _read(args.file)
        envelope_raw = _read(args.envelope) if args.envelope else None
        summary = validate_receipt_bytes(manifest_raw, receipt_raw, envelope_bytes=envelope_raw)
        receipt = _parsed(receipt_raw, "receipt")
        index_membership = {}
        if args.index:
            # E09: cross-check recorded membership against the EXACT index
            # bytes the caller supplies; everything else stays
            # recorded-unchecked.
            blobs = {}
            for path in args.index:
                blob = _read(path)
                from .canonical import sha256_hex

                blobs["sha256:%s" % sha256_hex(blob)] = blob
            index_membership = verify_receipt_index_membership(manifest_raw, receipt, blobs)
            summary["index_membership"].update(index_membership)
        return _emit({"ok": True, "kind": "receipt", **summary})

    if args.command == "redact-inputs":
        manifest_raw = _read(args.manifest)
        envelope_raw = _read(args.file)
        return _emit(
            {
                "ok": True,
                "kind": "redacted-runtime-inputs",
                "redacted": redact(manifest_raw, _parsed(envelope_raw, "runtime-input envelope")),
            }
        )

    if args.command == "verify-attestation":
        from .attestation import FileReplayState, InMemoryEnrollmentStore, verify_attestation

        manifest_raw = _read(args.manifest)
        receipt = _parsed(_read(args.receipt), "receipt")
        report = _parsed(_read(args.report), "verifier report")
        store = InMemoryEnrollmentStore()
        with open(args.enrollment_store, "rb") as handle:
            records = json.load(handle)
        if not isinstance(records, list):
            raise ContractError("enrollment store file must be a JSON array of enrollment records")
        # S03: records are imported COMPLETE -- including their persisted
        # last_counter state. Importing through the fresh-enrollment path
        # would reset every counter to zero and let a rolled-back report
        # carry an already-exceeded counter; import_record validates the
        # full record (tagged assertion key, Apple key-identifier binding,
        # app identity, counter state) and preserves it verbatim.
        for record in records:
            store.import_record(record)
        # R03: replay state is EXPLICIT at the CLI boundary and its
        # check-and-update is serialized -- FileReplayState consumes the
        # challenge under one exclusive flock and rewrites the locked file
        # IN PLACE while the lock is held, so repeated CLI invocations can
        # never both accept the same report. The former fresh-empty-set
        # bypass (which let repeated invocations succeed without any
        # recorded state) is gone; callers without single-use state have NO
        # authorizing CLI mode.
        replay_state = FileReplayState(args.replay_state)
        summary = verify_attestation(
            manifest_raw,
            receipt,
            report,
            context={
                "trusted_verifier_keys": {args.verifier_key_id: args.verifier_key},
                "expected_app": {"app_id": args.app_id, "team_id": args.team_id},
                "enrollment_store": store,
                "app_attest_environments": ["production"],
                "assertion_key_source": "apple-appattest-provisioned",
            },
            expected_challenge=args.challenge,
            replay_state=replay_state,
        )
        return _emit({"ok": True, "kind": "attestation-verification", **summary})

    if args.command == "lower":
        manifest_raw = _read(args.manifest)
        manifest, summary = validate_manifest_bytes(manifest_raw)
        lowered = lower(
            manifest,
            summary["manifest_sha256"],
            daemon_endpoint=args.daemon_endpoint,
            run_id=args.run_id,
            workspace_host_dir=args.workspace_host_dir,
            broker={"endpoint": args.broker_endpoint} if args.broker_endpoint else None,
        )
        lowered["generated_compose_file"] = render_compose_file(
            manifest, lowered, workload_env={}, sentinel_endpoint=args.sentinel_endpoint
        )
        return _emit({"ok": True, "kind": "lowered-execution-config", "lowering": lowered})

    if args.command == "hash":
        exact, canonical = exact_and_canonical_sha256(_read(args.file), max_bytes=MAX_ENVELOPE_BYTES)
        return _emit(
            {
                "ok": True,
                "kind": "hashes",
                "identity": "exact submitted bytes",
                "sha256_exact_bytes": exact,
                "sha256_canonical": canonical,
            }
        )

    raise AssertionError("unreachable command %r" % args.command)


def _parsed(raw_bytes, what):
    from .canonical import load_json_bytes

    return load_json_bytes(raw_bytes, what, max_bytes=MAX_ENVELOPE_BYTES)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="dsmack_compose_contract",
        description="Validators for the dsmack app-compose contract (dsmack.app-compose/4 et al).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("validate-manifest", help="validate a workload manifest")
    p.add_argument("file")

    p = sub.add_parser("validate-inputs", help="validate a runtime-input envelope against a manifest")
    p.add_argument("manifest")
    p.add_argument("file")

    p = sub.add_parser("validate-receipt", help="validate an execution receipt against a manifest")
    p.add_argument("manifest")
    p.add_argument("file")
    p.add_argument("--envelope", help="runtime-input envelope to cross-check commitments", default=None)
    p.add_argument(
        "--index",
        action="append",
        default=None,
        help="exact content-addressed index bytes to cross-check recorded index membership against "
        "(E09: repeatable; membership without supplied bytes stays recorded-unchecked)",
    )

    p = sub.add_parser("redact-inputs", help="validate then print the redacted form of a runtime-input envelope")
    p.add_argument("manifest")
    p.add_argument("file")

    p = sub.add_parser(
        "verify-attestation",
        help="independently verify a mac-attested receipt via a SIGNED trusted verifier report",
    )
    p.add_argument("manifest")
    p.add_argument("receipt")
    p.add_argument("report")
    p.add_argument(
        "--verifier-key",
        required=True,
        help="base64 ed25519 public key of the trusted verifier (pinned by the caller; required)",
    )
    p.add_argument(
        "--verifier-key-id",
        required=True,
        help="the id of the pinned verifier key (must match the report's report_sig.key_id)",
    )
    p.add_argument(
        "--app-id",
        required=True,
        help="the admitted application identity the App Attest key must be enrolled under (D02)",
    )
    p.add_argument(
        "--team-id",
        required=True,
        help="the admitted signing team identity (D02)",
    )
    p.add_argument(
        "--enrollment-store",
        required=True,
        help="JSON file holding the COMPLETE authenticated enrollment records (tagged assertion "
        "key, Apple key-identifier binding, admitted app identity, PERSISTED enrollment "
        "environment -- AAGUID-derived authenticated provenance, T02 -- and persisted "
        "last_counter; imported verbatim -- the assertion path never auto-enrolls and never "
        "resets counter state; records whose environment is outside the accepted set reject)",
    )
    p.add_argument(
        "--challenge",
        required=True,
        help="the fresh challenge the relying party issued for THIS run (mandatory; replay rejection)",
    )
    p.add_argument(
        "--replay-state",
        required=True,
        help="JSON replay-state file {consumed: [...], counters: {...}}; the challenge is consumed "
        "under an EXCLUSIVE flock and the locked file is rewritten IN PLACE while the lock is held "
        "(R03: serialized check-and-update, so repeated CLI invocations can never both accept the "
        "same report; created on first use)",
    )

    p = sub.add_parser("lower", help="deterministic lowering of a manifest to execution config")
    p.add_argument("manifest")
    p.add_argument("--daemon-endpoint", required=True, help="explicit Docker daemon endpoint (the only selection mechanism)")
    p.add_argument("--run-id", required=True, help="fresh per-run identifier (project/workspace isolation)")
    p.add_argument("--workspace-host-dir", default=None, help="private per-run workspace directory")
    p.add_argument("--broker-endpoint", default=None, help="guest-root credential broker endpoint")
    p.add_argument("--sentinel-endpoint", default=None, help="runner-resolved workload-reachable per-run sentinel URL")

    p = sub.add_parser("hash", help="print exact-bytes and canonical sha256 of a JSON file")
    p.add_argument("file")

    args = parser.parse_args(argv)
    try:
        return _run(args)
    except ContractError as exc:
        sys.stderr.write("CONTRACT VIOLATION: %s\n" % exc)
        return 1
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        sys.stderr.write("ERROR: %s\n" % exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())
