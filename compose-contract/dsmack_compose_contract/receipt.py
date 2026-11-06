"""Execution receipt validation for dsmack.receipt/4 (contract4).

Receipts distinguish execution environments honestly: linux-test vs vm vs
mac-attested. A linux-test or vm receipt NEVER carries attestation; only a
mac-attested receipt carries the attestation SHAPE.

v4 repairs (contract3-review):

  D03 - index membership status is EXPLICIT: `index_verification` is
        "verified" only when the runner ran oci_index.verify_index_membership
        against the EXACT content-addressed index bytes (digest-checked);
        "unchecked" can never back a receipt (it fails validation). The
        recorded index_entry must be the exact byte-derived entry (child
        descriptor digest + platform), so an invented child or an entry from
        an unrelated index is rejectable.
  D09 - `observed.services` records PER-SERVICE identities (image,
        resolution, platform, observed container runtime) for the bounded
        multi-service subset.
  D10 - each service records the OBSERVED container runtime {name, version,
        executable_sha256, registration_verified}; on vm receipts the
        executable digest must equal the manifest's runtime_closure pin and
        registration must be verified -- same-name wrong-binary or
        wrong-arguments registrations are rejectable. The host-test
        toolchain has a DEFINED bundle encoding (bundle digest + component
        list) with optional requested/admitted comparison against
        runner.host_toolchain_policy.
  D06 - unknown-key diagnostics are value-free (offender text withheld).

Core invariants unchanged (v3): requested-vs-observed equality, full
base_vm checksum-manifest binding, commitment status distinction
(absent / recorded-unchecked / bound-to-validated-envelope), outputs
status semantics with disjoint recorded/missing sets, and shape validation
that NEVER reports attestation success.
"""

from .canonical import load_json_bytes, sha256_hex, sha256_obj
from .errors import MultiError, ReceiptError
from .manifest import (
    DIGEST_RE,
    HEX64_RE,
    IMAGE_RE,
    RUNTIME_COMPONENT,
    _primary_service_image,
    _service_images,
    validate_manifest_bytes,
)
from .runtime_inputs import COMMITMENT_ALGS, _normalized_scope, validate_commitment_scope_shape

ENVIRONMENT_LINUX_TEST = "linux-test"
ENVIRONMENT_VM = "vm"
ENVIRONMENT_MAC_ATTESTED = "mac-attested"
ENVIRONMENTS = (ENVIRONMENT_LINUX_TEST, ENVIRONMENT_VM, ENVIRONMENT_MAC_ATTESTED)

RECEIPT_REQUIRED_KEYS = {
    "receipt_version",
    "environment",
    "run_id",
    "manifest_sha256",
    "base_vm",
    "base_vm_launch",
    "runner",
    "harness_sha256",
    "runtime_inputs_commitment",
    "observed",
    "outputs",
    "attestation",
}
RECEIPT_OPTIONAL_KEYS = set()

#: E02: the receipt's admission/launch observation (spike DESIGN R5). The
#: admission object is REQUIRED in every environment (admission gates the
#: run); the boot object is REQUIRED non-null for vm/mac-attested and null
#: for linux-test (no VM boots on a test host).
LAUNCH_ALLOWED_KEYS = {"admission", "boot"}
LAUNCH_ADMISSION_KEYS = {"decision", "os_image_hash", "admission_sha256", "admission_version"}
LAUNCH_BOOT_KEYS = {
    "loader_mode",
    "kernel_sha256",
    "initrd_sha256",
    "rootfs_sha256",
    "metadata_sha256",
    "cmdline",
    "cmdline_sha256",
    "verity",
}
LAUNCH_VERITY_KEYS = {
    "block_bytes",
    "data_bytes",
    "hash_offset_bytes",
    "root_hash",
    "salt_hex",
    "total_bytes",
}
#: E02: loader modes with UNEQUAL claims. "owned-copy" is the admitted-boot
#: invariant (hash the OWNED COPY, consume THAT copy -- boot-binding-spike
#: DESIGN R1/R2); "held-fd" is ENGINEERING TRANSPORT (a held ordinary-file
#: descriptor does not prevent same-inode modification after its final hash).
LOADER_MODES = ("owned-copy", "held-fd")
LOADER_OWNED_COPY = "owned-copy"
LOADER_HELD_FD = "held-fd"

STATUSES = ("completed", "failed", "cancelled")
CANCEL_REASONS = ("timeout", "external", "limit-output", "limit-workspace")

#: Keys that must never appear anywhere in a receipt (defense-in-depth only).
LEAK_KEYS = {
    "env",
    "env_values",
    "content_base64",
    "content_b64",
    "stdin_b64",
    "user_config",
    "user_config_b64",
    "secret",
    "password",
    "api_key",
    "credential",
}

#: Attestation SHAPE keys (presence is NOT verification; see attestation.py).
ATTESTATION_REQUIRED_KEYS = {
    "provider",
    "key_id_b64",
    "assertion_b64",
    "receipt_b64",
    "challenge",
    "counter",
    "generated_at_unix_s",
}

COMMITMENT_SCOPE_STATUSES = ("absent", "recorded-unchecked", "bound-to-validated-envelope")

#: D03/E09: membership statuses. "verified" is a RUNNER CLAIM that
#: oci_index.verify_index_membership succeeded over the exact pinned index
#: bytes; "recorded-unchecked" records a resolution the contract library has
#: NOT independently checked. A receipt alone can never self-certify
#: "verified": independent verification requires the exact index bytes via
#: verify_receipt_index_membership (which compares the hook result against
#: every recorded field). Consumers read the summary's per-service
#: index_membership, not the recorded label.
INDEX_VERIFICATION_ACCEPTED = ("recorded-unchecked", "verified")
INDEX_MEMBERSHIP_LOCALLY_VERIFIED = "verified"
INDEX_MEMBERSHIP_RECORDED_UNCHECKED = "recorded-unchecked"

OBSERVED_ALLOWED_KEYS = {"services", "host_toolchain", "host_toolchain_components"}
SERVICE_ALLOWED_KEYS = {
    "service",
    "image",
    "resolved_manifest_digest",
    "index_digest",
    "index_entry",
    "index_verification",
    "platform",
    "container",
    "exit_code",
}
CONTAINER_ALLOWED_KEYS = {"name", "version", "executable_sha256", "registration_verified"}
TOOLCHAIN_COMPONENT_KEYS = {"name", "sha256"}

#: E06: bundle preimage domain for the linux-test host toolchain encoding.
HOST_TOOLCHAIN_BUNDLE_DOMAIN = "dsmack.host-toolchain-bundle/1"


def host_toolchain_bundle_sha256(components):
    """The DEFINED bundle_sha256 preimage (E06): canonical digest over
    [domain, [[name, sha256], ...]] with components sorted by name."""
    for c in components:
        if not (isinstance(c, dict) and isinstance(c.get("name"), str) and isinstance(c.get("sha256"), str)):
            raise ReceiptError(
                "host_toolchain_components entries must be {name: str, sha256: str} for the defined "
                "bundle encoding; malformed components are a contract error, never an interpreter error"
            )
    pairs = sorted([c["name"], c["sha256"]] for c in components)
    return sha256_obj([HOST_TOOLCHAIN_BUNDLE_DOMAIN, pairs])


def _scan_leaks(node, depth=0, errors=None):
    """Defense-in-depth metadata hygiene scan (NOT a secrecy proof).

    E08: diagnostics NEVER incorporate untrusted key names into emitted
    paths -- the path is withheld together with the key text, so an arbitrary
    nested caller key can never reach the diagnostic through the path.
    """
    if errors is None:
        errors = []
    if depth > 32:
        return errors
    if isinstance(node, dict):
        for key, value in node.items():
            if key in LEAK_KEYS:
                errors.append(
                    ReceiptError(
                        "receipt contains a forbidden key (key and path withheld); runtime-input values "
                        "and secrets never appear in receipts (metadata hygiene; NOT a secrecy proof)"
                    )
                )
            _scan_leaks(value, depth + 1, errors)
    elif isinstance(node, list):
        for value in node:
            _scan_leaks(value, depth + 1, errors)
    return errors


def validate_receipt_bytes(manifest_bytes, receipt_bytes, envelope_bytes=None):
    receipt = load_json_bytes(receipt_bytes, "receipt")
    return validate_receipt(manifest_bytes, receipt, envelope_bytes=envelope_bytes)


def validate_receipt(manifest_bytes, receipt, envelope_bytes=None):
    """Validate a parsed receipt against exact manifest bytes.

    envelope_bytes: optional exact bytes of the caller's runtime-input
    envelope. When supplied, the receipt's recorded commitment must equal
    the envelope's validated commitment (and an uncommitted envelope can
    never back a receipt commitment).

    Returns a summary dict. Raises MultiError listing every violation.
    NEVER reports attestation success (F01).
    """
    errors = []
    if not isinstance(receipt, dict):
        raise MultiError([ReceiptError("receipt must be a JSON object")])

    found = set(receipt)
    # D06: unknown-key diagnostics withhold the caller-controlled text.
    for _key in found - RECEIPT_REQUIRED_KEYS:
        errors.append(
            ReceiptError(
                "receipt: unsupported key rejected (key text withheld); required keys are %s"
                % sorted(RECEIPT_REQUIRED_KEYS)
            )
        )
    for key in RECEIPT_REQUIRED_KEYS - found:
        errors.append(ReceiptError("receipt.%s is required" % key))
    if errors:
        raise MultiError(errors)

    if receipt["receipt_version"] != 4:
        errors.append(ReceiptError("receipt.receipt_version must be 4"))

    environment = receipt["environment"]
    if environment not in ENVIRONMENTS:
        errors.append(
            ReceiptError(
                "receipt.environment must be one of %s (execution domains are never conflated)" % (ENVIRONMENTS,)
            )
        )

    manifest, _ = validate_manifest_bytes(manifest_bytes)

    if receipt["manifest_sha256"] != sha256_hex(manifest_bytes):
        errors.append(ReceiptError("receipt.manifest_sha256 does not match the manifest bytes"))

    from .manifest import RUN_ID_RE

    run_id = receipt["run_id"]
    if not (isinstance(run_id, str) and RUN_ID_RE.match(run_id)):
        errors.append(ReceiptError("receipt.run_id must match the per-run identifier pattern"))

    # C04/ledger 2.3 + D01: the receipt binds the FULL checksum manifest --
    # every anchor and component hash, the verity root hash, the exact
    # cmdline and sizing -- not just the system-image digest.
    if receipt["base_vm"] != manifest["base_vm"]:
        errors.append(
            ReceiptError(
                "receipt.base_vm does not equal manifest.base_vm exactly (os_image_hash, metadata and "
                "component hashes, verity root hash, cmdline and sizing are all bound)"
            )
        )
    if receipt["runner"] != manifest["runner"]:
        errors.append(ReceiptError("receipt.runner must equal the manifest runner object (observed == requested)"))
    if receipt["harness_sha256"] != manifest["harness"]["sha256"]:
        errors.append(ReceiptError("receipt.harness_sha256 does not match manifest.harness.sha256"))

    # E02: the admission decision and the observed boot configuration are
    # REQUIRED receipt members, bound into the execution evidence.
    launch_summary = _validate_base_vm_launch(receipt["base_vm_launch"], manifest, environment, errors)

    _validate_observed(receipt["observed"], manifest, environment, errors)
    commitment_status = _validate_commitment(receipt["runtime_inputs_commitment"], manifest_bytes, envelope_bytes, errors)
    _validate_outputs(receipt["outputs"], manifest, errors)
    _validate_completion_consistency(receipt, manifest, errors)

    attestation = receipt["attestation"]
    attestation_shape = "none"
    if environment in (ENVIRONMENT_LINUX_TEST, ENVIRONMENT_VM):
        if attestation is not None:
            errors.append(
                ReceiptError(
                    "receipt.environment %r must carry attestation: null; non-null attestation is "
                    "claimed only by mac-attested receipts" % environment
                )
            )
    else:  # mac-attested: SHAPE ONLY -- never a verification claim (F01)
        attestation_shape = "present-unverified"
        if not isinstance(attestation, dict):
            errors.append(
                ReceiptError(
                    "receipt.environment 'mac-attested' requires a non-null attestation object; note "
                    "that shape validation does NOT verify attestation -- only the separate "
                    "verify-attestation boundary over a SIGNED trusted verifier report does"
                )
            )
        else:
            unknown = set(attestation) - ATTESTATION_REQUIRED_KEYS
            if unknown:
                errors.append(
                    ReceiptError(
                        "receipt.attestation has unsupported keys (names withheld); allowed keys are %s"
                        % sorted(ATTESTATION_REQUIRED_KEYS)
                    )
                )
            for field in sorted(ATTESTATION_REQUIRED_KEYS):
                if field not in attestation:
                    errors.append(ReceiptError("receipt.attestation.%s is required" % field))
            if attestation.get("provider") != "apple-appattest":
                errors.append(
                    ReceiptError(
                        "receipt.attestation.provider must be 'apple-appattest'; no other provider and "
                        "no simulated attestation is representable in this contract"
                    )
                )
            challenge = attestation.get("challenge")
            if not isinstance(challenge, str) or not challenge:
                errors.append(ReceiptError("receipt.attestation.challenge must be a non-empty freshness nonce"))
            counter = attestation.get("counter")
            if not isinstance(counter, int) or isinstance(counter, bool) or counter < 0:
                errors.append(ReceiptError("receipt.attestation.counter must be a non-negative integer"))
            stamp = attestation.get("generated_at_unix_s")
            if not isinstance(stamp, int) or isinstance(stamp, bool):
                errors.append(
                    ReceiptError(
                        "receipt.attestation.generated_at_unix_s must be an integer (canonical profile is "
                        "integers-only; receipts are hashed)"
                    )
                )
            for field in ("key_id_b64", "assertion_b64", "receipt_b64"):
                value = attestation.get(field)
                if not isinstance(value, str) or not value:
                    errors.append(ReceiptError("receipt.attestation.%s must be a non-empty string" % field))

    _scan_leaks(receipt, 0, errors)

    if errors:
        raise MultiError(errors)
    # E09: membership status summary. Without exact index bytes every
    # recorded claim is "recorded-unchecked" -- the receipt's own
    # index_verification label is a runner CLAIM, never local verification;
    # callers cross-check via verify_receipt_index_membership.
    membership = {}
    for entry in receipt["observed"]["services"]:
        if isinstance(entry, dict) and entry.get("index_digest") is not None:
            membership[entry.get("service")] = INDEX_MEMBERSHIP_RECORDED_UNCHECKED
    return {
        "environment": environment,
        "run_id": run_id,
        "manifest_sha256": receipt["manifest_sha256"],
        "base_vm_os_image_hash": receipt["base_vm"]["os_image_hash"],
        "base_vm_rootfs_sha256": receipt["base_vm"]["rootfs_sha256"],
        "base_vm_launch": {
            "admission_decision": launch_summary["admission"]["decision"],
            "admission_sha256": launch_summary["admission"]["admission_sha256"],
            "boot_loader_mode": launch_summary["boot"]["loader_mode"] if launch_summary["boot"] else None,
            # R02 + S01: structural validation NEVER asserts a byte-binding
            # claim. loader_mode is an UNAUTHENTICATED LOADER OBSERVATION --
            # a recorded claim. verified_byte_binding=true is reported ONLY
            # through the explicit authenticated-evidence hook of
            # verify_launch_observation, supplied by a trusted actual
            # verifier that authenticates the whole receipt; exact-byte
            # identity over public bundle metadata never establishes it.
            "verified_byte_binding": None,
            "boot_claim_status": "recorded-loader-claim",
        },
        "index_membership": membership,
        "observed": receipt["observed"],
        "runtime_inputs_commitment": receipt["runtime_inputs_commitment"],
        "runtime_inputs_commitment_status": commitment_status,
        "status": receipt["outputs"]["status"],
        "artifacts": [a["name"] for a in receipt["outputs"]["artifacts"]],
        "missing_artifacts": receipt["outputs"]["missing"],
        # F01: shape validation reports the attestation SHAPE, never success.
        "attestation_shape": attestation_shape,
        "attestation_verified": False,
        "attestation_note": (
            "shape validation NEVER verifies attestation; only the separate verify-attestation "
            "boundary over a SIGNED trusted verifier report can report attested=true"
        ),
    }


def _validate_base_vm_launch(launch, manifest, environment, errors):
    """E02: validate the admission decision + observed boot configuration.

    admission is REQUIRED in every environment; boot is REQUIRED non-null for
    vm/mac-attested and must be null for linux-test. Every boot field is
    checked against the manifest's admitted identity: the observed digests
    equal the component pins, the booted cmdline equals the manifest cmdline
    byte for byte (command-line immutability), cmdline_sha256 covers those
    exact bytes, and the verity block matches the manifest's verity root and
    the derived layout. loader_mode distinguishes the authoritative owned-copy
    invariant from held-fd engineering transport.
    """
    if not isinstance(launch, dict) or set(launch) - LAUNCH_ALLOWED_KEYS:
        errors.append(
            ReceiptError(
                "receipt.base_vm_launch must be an object with exactly %s (E02: the observed admission "
                "and boot configuration)" % sorted(LAUNCH_ALLOWED_KEYS)
            )
        )
        return {"admission": {}, "boot": None}
    admission = launch.get("admission")
    if not isinstance(admission, dict) or set(admission) != LAUNCH_ADMISSION_KEYS:
        errors.append(
            ReceiptError(
                "receipt.base_vm_launch.admission is REQUIRED and must have exactly %s (the external "
                "admission decision bound to the admission bytes)" % sorted(LAUNCH_ADMISSION_KEYS)
            )
        )
        admission = {}
    else:
        if admission["decision"] != "admitted":
            errors.append(ReceiptError("receipt.base_vm_launch.admission.decision must be 'admitted'"))
        if admission["os_image_hash"] != manifest["base_vm"]["os_image_hash"]:
            errors.append(
                ReceiptError(
                    "receipt.base_vm_launch.admission.os_image_hash does not equal the admitted "
                    "manifest base_vm.os_image_hash (the executed image must be the admitted one)"
                )
            )
        if not (isinstance(admission["admission_sha256"], str) and HEX64_RE.match(admission["admission_sha256"])):
            errors.append(ReceiptError("receipt.base_vm_launch.admission.admission_sha256 must be 64-hex"))
        if admission["admission_version"] != 1:
            errors.append(ReceiptError("receipt.base_vm_launch.admission.admission_version must be 1"))

    boot = launch.get("boot")
    if environment == ENVIRONMENT_LINUX_TEST:
        if boot is not None:
            errors.append(
                ReceiptError(
                    "receipt.base_vm_launch.boot must be null for linux-test receipts (no VM boots on a "
                    "test host); admission alone is recorded"
                )
            )
        return {"admission": admission, "boot": None}
    if not isinstance(boot, dict) or set(boot) != LAUNCH_BOOT_KEYS:
        errors.append(
            ReceiptError(
                "receipt.base_vm_launch.boot is REQUIRED for %s receipts and must have exactly %s (the "
                "observed owned-copy/fd boot configuration)" % (environment, sorted(LAUNCH_BOOT_KEYS))
            )
        )
        return {"admission": admission, "boot": None}
    if boot["loader_mode"] not in LOADER_MODES:
        errors.append(
            ReceiptError(
                "receipt.base_vm_launch.boot.loader_mode must be one of %s ('owned-copy' is the "
                "admitted-boot invariant; 'held-fd' is engineering transport)" % (list(LOADER_MODES),)
            )
        )
    base_vm = manifest["base_vm"]
    for field in ("kernel_sha256", "initrd_sha256", "rootfs_sha256", "metadata_sha256"):
        if boot.get(field) != base_vm.get(field):
            errors.append(
                ReceiptError(
                    "receipt.base_vm_launch.boot.%s does not equal the admitted component pin (the "
                    "boot observation must record the digests of the bytes that were actually "
                    "consumed, and they must be the admitted ones)" % field
                )
            )
    if boot.get("cmdline") != base_vm["cmdline"]:
        errors.append(
            ReceiptError(
                "receipt.base_vm_launch.boot.cmdline does not equal the manifest cmdline byte for byte "
                "(the command line is part of the verified tuple and is immutable after verification)"
            )
        )
    if boot.get("cmdline_sha256") != sha256_hex(boot["cmdline"] if isinstance(boot.get("cmdline"), str) else ""):
        errors.append(
            ReceiptError("receipt.base_vm_launch.boot.cmdline_sha256 must be the SHA256 of the exact booted cmdline bytes")
        )
    verity = boot.get("verity")
    if not isinstance(verity, dict) or set(verity) != LAUNCH_VERITY_KEYS:
        errors.append(
            ReceiptError(
                "receipt.base_vm_launch.boot.verity must have exactly %s (the observed verity "
                "configuration)" % sorted(LAUNCH_VERITY_KEYS)
            )
        )
    else:
        if verity["root_hash"] != base_vm["verity_root_hash"]:
            errors.append(
                ReceiptError("receipt.base_vm_launch.boot.verity.root_hash does not equal the manifest verity_root_hash")
            )
        data_bytes = verity["data_bytes"]
        if not (isinstance(data_bytes, int) and not isinstance(data_bytes, bool) and data_bytes > 0 and data_bytes % 4096 == 0):
            errors.append(ReceiptError("receipt.base_vm_launch.boot.verity.data_bytes must be a positive block-aligned integer"))
        else:
            if verity["hash_offset_bytes"] != data_bytes:
                errors.append(
                    ReceiptError("receipt.base_vm_launch.boot.verity.hash_offset_bytes must equal data_bytes (the dstack layout)")
                )
            # R02: the recorded geometry is bound to the ADMITTED TUPLE --
            # data_bytes must equal the cmdline's dstack.rootfs_size and
            # total_bytes must equal the frozen layout total (data +
            # superblock + top-down tree, superblock FIRST in the hash
            # region).
            from .image_admission import verity_layout

            cmdline = boot.get("cmdline") if isinstance(boot.get("cmdline"), str) else base_vm.get("cmdline")
            declared_size = None
            if isinstance(cmdline, str):
                for token in cmdline.split(" "):
                    if token.startswith("dstack.rootfs_size="):
                        digits = token[len("dstack.rootfs_size="):]
                        declared_size = int(digits) if digits.isascii() and digits.isdigit() and len(digits) <= 15 else None
                        break
            if declared_size is None:
                errors.append(
                    ReceiptError("receipt.base_vm_launch.boot.verity.data_bytes cannot be bound: the recorded cmdline carries no bounded dstack.rootfs_size")
                )
            elif data_bytes != declared_size:
                errors.append(
                    ReceiptError(
                        "receipt.base_vm_launch.boot.verity.data_bytes does not equal the cmdline "
                        "dstack.rootfs_size (the recorded geometry must be the admitted tuple's geometry)"
                    )
                )
            else:
                try:
                    layout = verity_layout(declared_size)
                except Exception:  # noqa: BLE001 - rejected above as a contract error
                    layout = None
                # S06: the recorded value's SHAPE is validated before the
                # dependent layout comparison, and the diagnostic is fixed
                # (the rejected total_bytes value is never echoed).
                total = verity["total_bytes"]
                total_shape_ok = (
                    isinstance(total, int) and not isinstance(total, bool) and total > 0 and total % 4096 == 0
                )
                if not total_shape_ok:
                    errors.append(
                        ReceiptError(
                            "receipt.base_vm_launch.boot.verity.total_bytes must be a positive "
                            "block-aligned integer"
                        )
                    )
                elif layout is not None and total != layout["total_bytes"]:
                    errors.append(
                        ReceiptError(
                            "receipt.base_vm_launch.boot.verity.total_bytes does not equal the frozen "
                            "layout total %d (data %d + superblock + tree, superblock first, leaves last)"
                            % (layout["total_bytes"], layout["data_bytes"])
                        )
                    )
        if verity["block_bytes"] != 4096 or verity["salt_hex"] != "0" * 64:
            errors.append(
                ReceiptError(
                    "receipt.base_vm_launch.boot.verity block_bytes/salt_hex must record the fixed "
                    "dstack verity parameters (4096-byte blocks, salt 0^64)"
                )
            )
    return {"admission": admission, "boot": boot}


def verify_launch_observation(
    manifest_bytes,
    receipt,
    admission_bytes=None,
    checksum_manifest_bytes=None,
    metadata_bytes=None,
    authenticated_evidence_hook=None,
):
    """E02 + R02 + S01: relying-party comparison with SEPARATE evidence classes.

    Structural receipt/image checks NEVER establish execution or verified byte
    consumption. Four distinct evidence classes are reported separately:

      - RECORDED LOADER CLAIMS: the boot object (loader_mode and recorded
        digests) is an UNAUTHENTICATED loader observation. Structural
        validation and this entry point ALWAYS report it as a recorded
        claim ("recorded-loader-claim") -- never as verification, no matter
        which other evidence classes succeed.

      - IDENTITY VERIFICATION (exact-byte, PUBLIC METADATA ONLY): when
        ``checksum_manifest_bytes`` and ``metadata_bytes`` (the EXACT dstack
        bundle metadata bytes) are supplied, the full image identity is
        RECOMPUTED over them (pins, metadata cmdline, verity root,
        architecture) and every recorded launch field is compared against
        the verified tuple. A match proves IMAGE IDENTITY and consistency
        of the recorded fields -- it does NOT prove that any owned copy was
        consumed or that any VM booted, and it NEVER sets
        verified_byte_binding (a fabricated boot observation accompanied by
        correct public bundle metadata stays unauthenticated).

      - ADMISSION POLICY: with ``admission_bytes`` (the exact external
        admission document), the recorded admission digest is confirmed to
        cover those bytes and the identity must be IN that set.

      - AUTHENTICATED EVIDENCE HOOK: verified execution binding
        (verified_byte_binding=true) is reported ONLY through
        ``authenticated_evidence_hook`` -- an explicit caller-supplied
        integration point for a TRUSTED ACTUAL VERIFIER that authenticates
        the WHOLE receipt (its own authenticated evidence chain). This
        contract ships no such verifier; until a trusted verifier supplies
        authenticated evidence through this hook,
        verified_byte_binding stays None and the boot object remains a
        recorded loader claim. The hook must be callable; it is invoked as
        ``hook(receipt, verdict)`` AFTER every other check passed and must
        return {"verified_byte_binding": bool, "boot_claim_status": str,
        "evidence_note": str}; a falsy verified_byte_binding leaves the
        recorded-claim verdict untouched, and a True result is reported
        WITH the hook's own status/evidence strings (the helper itself
        never derives execution truth).

    The COMPLETE receipt is validated first (manifest_sha256, environment,
    observed, outputs, commitment and attestation shape included) -- no
    partial-receipt shortcuts.

    Raises MultiError on any violation. Without authenticated evidence from
    the trusted-verifier hook the verdict reports recorded claims only
    (verified_byte_binding=None).
    """
    from .image_admission import ADMISSION_VERSION, parse_admission, verify_base_vm_identity

    # S01: the helper validates the COMPLETE receipt against the exact
    # manifest bytes -- manifest_sha256, environment, observed, outputs,
    # commitment and attestation shape -- not just the launch object.
    validate_receipt(manifest_bytes, receipt)
    manifest, _ = validate_manifest_bytes(manifest_bytes)
    errors = []
    summary = _validate_base_vm_launch(receipt.get("base_vm_launch"), manifest, receipt.get("environment"), errors)
    if errors:
        raise MultiError(errors)
    verdict = {
        "admission_decision_recorded": summary["admission"].get("decision"),
        "boot_loader_mode": summary["boot"]["loader_mode"] if summary["boot"] else None,
        # R02 + S01: the recorded boot object is a CLAIM. Exact-byte identity
        # verification over public bundle metadata establishes image identity
        # and recorded-field consistency ONLY; verified execution binding is
        # reported exclusively through authenticated_evidence_hook.
        "verified_byte_binding": None,
        "boot_claim_status": "recorded-loader-claim",
        "image_identity_verified": None,
        "admission_bytes_verified": None,
        "note": (
            "owned-copy is the authoritative boot-binding route; the receipt's boot object is a "
            "recorded loader claim. Exact-byte identity verification over the supplied public "
            "checksum-manifest and metadata bytes proves image identity and recorded-field "
            "consistency ONLY -- it never establishes execution or verified byte consumption. "
            "verified_byte_binding=true requires the authenticated-evidence hook supplied by a "
            "trusted actual verifier that authenticates the whole receipt. Host-root "
            "integrity/confidentiality and hardware qualification remain explicitly open."
        ),
    }
    boot = summary["boot"]
    if checksum_manifest_bytes is not None and metadata_bytes is not None:
        # COMPLETE IMAGE-IDENTITY HOOK: recompute the identity over the
        # exact bytes and bind EVERY recorded launch field to the verified
        # tuple. This is PUBLIC METADATA verification: identity + recorded
        # field consistency, never an execution or consumption claim.
        from .canonical import sha256_hex
        from .image_admission import _cmdline_field, _cmdline_rootfs_size, verity_layout

        try:
            identity = verify_base_vm_identity(manifest["base_vm"], checksum_manifest_bytes, metadata_bytes)
        except Exception as exc:  # noqa: BLE001 - surfaced as a contract violation
            raise MultiError([ReceiptError("the supplied bundle bytes fail image-identity verification: %s" % exc)]) from None
        if identity["os_image_hash"] != receipt["base_vm"]["os_image_hash"]:
            raise MultiError([ReceiptError("the verified image identity does not equal the receipt's recorded base_vm identity")])
        boot_errors = []
        if not boot:
            boot_errors.append("the receipt records no boot object to verify")
        else:
            for field in ("kernel_sha256", "initrd_sha256", "rootfs_sha256", "metadata_sha256"):
                path = {"kernel_sha256": "Image", "initrd_sha256": "initramfs.cpio.gz", "rootfs_sha256": "rootfs.squashfs.verity", "metadata_sha256": "metadata.json"}[field]
                if boot.get(field) != identity["components"].get(path):
                    boot_errors.append("recorded %s does not equal the byte-verified component pin" % field)
            if boot.get("cmdline") != identity["cmdline"]:
                boot_errors.append("the recorded cmdline does not equal the byte-verified authenticated cmdline")
            declared_size = _cmdline_rootfs_size(identity["cmdline"])
            if declared_size is None or boot.get("verity", {}).get("data_bytes") != declared_size:
                boot_errors.append("the recorded verity data_bytes do not equal the byte-verified dstack.rootfs_size")
            else:
                if boot.get("verity", {}).get("total_bytes") != verity_layout(declared_size)["total_bytes"]:
                    boot_errors.append("the recorded verity total_bytes do not equal the frozen layout total")
                if _cmdline_field(identity["cmdline"], "dstack.rootfs_hash") != boot.get("verity", {}).get("root_hash"):
                    boot_errors.append("the recorded verity root does not equal the byte-verified cmdline root")
        if boot_errors:
            raise MultiError([ReceiptError("launch observation failed exact-byte verification: %s" % "; ".join(boot_errors))])
        # S01: image identity is verified SEPARATELY from execution binding.
        verdict["image_identity_verified"] = True
    if admission_bytes is not None:
        from .canonical import sha256_hex

        recorded = summary["admission"].get("admission_sha256")
        if recorded != sha256_hex(admission_bytes):
            raise MultiError(
                [ReceiptError("base_vm_launch.admission.admission_sha256 does not cover the supplied admission bytes")]
            )
        policy = parse_admission(admission_bytes)
        if manifest["base_vm"]["os_image_hash"] not in policy["allowed_os_image_hashes"]:
            raise MultiError([ReceiptError("the recorded os_image_hash is not in the supplied admission set")])
        if summary["admission"].get("admission_version") != ADMISSION_VERSION:
            raise MultiError([ReceiptError("base_vm_launch.admission.admission_version must be 1")])
        verdict["admission_bytes_verified"] = True
    # S01: the EXPLICIT authenticated-evidence integration hook. Only a
    # trusted actual verifier authenticating the WHOLE receipt may report
    # verified execution binding, and only through this hook; structural,
    # identity and admission evidence above can never produce it.
    if authenticated_evidence_hook is not None:
        if not callable(authenticated_evidence_hook):
            raise ReceiptError(
                "authenticated_evidence_hook must be a callable trusted-verifier integration hook "
                "(this contract ships no verifier implementation; it authenticates the whole "
                "receipt and its decision is reported, never derived)"
            )
        hook_result = authenticated_evidence_hook(receipt, verdict)
        if not isinstance(hook_result, dict) or set(hook_result) != {
            "verified_byte_binding",
            "boot_claim_status",
            "evidence_note",
        }:
            raise ReceiptError(
                "authenticated_evidence_hook must return exactly {verified_byte_binding, "
                "boot_claim_status, evidence_note}; the helper reports the trusted verifier's "
                "decision and never fabricates one"
            )
        if hook_result["verified_byte_binding"] is True:
            if not (isinstance(hook_result["boot_claim_status"], str) and hook_result["boot_claim_status"]):
                raise ReceiptError("authenticated_evidence_hook.boot_claim_status must be a non-empty string when it reports verified_byte_binding=true")
            verdict["verified_byte_binding"] = True
            verdict["boot_claim_status"] = hook_result["boot_claim_status"]
            verdict["note"] = hook_result["evidence_note"]
        elif hook_result["verified_byte_binding"] is not False:
            raise ReceiptError(
                "authenticated_evidence_hook.verified_byte_binding must be literal true or false "
                "(anything else is not a verifier decision)"
            )
    return verdict


def verify_receipt_index_membership(manifest_bytes, receipt, index_blobs):
    """E09 + R08: independently verify recorded index membership.

    The helper is self-contained: it FIRST fully validates the receipt
    against the exact manifest bytes (so an entry whose index_digest does
    not equal the requested service's pinned image digest -- or any other
    recorded inconsistency -- is rejected here, not just in standalone
    validation), THEN enforces the requested service/image/index bindings
    itself (entry image == the manifest pin for that service; index_digest
    == the pinned digest), and only then runs
    oci_index.verify_index_membership over the supplied exact bytes and
    compares the hook result against EVERY recorded field (index_digest,
    the resolved child digest and the exact recorded index_entry).

    index_blobs: {index_digest ('sha256:<64hex>'): exact content-addressed
    index bytes}. Services whose digest has no supplied bytes stay
    'recorded-unchecked' (the receipt alone never self-certifies
    'verified'); wrong bytes fail the cross-check closed.
    Returns {service: "verified"} for the services it verified.
    """
    from .oci_index import verify_index_membership

    manifest, _ = validate_manifest_bytes(manifest_bytes)
    # R08: validate the RECEIPT, not just the manifest -- a receipt whose
    # manifest pins the child directly while it records an unrelated
    # (self-consistent) index can never reach the hook.
    if not isinstance(receipt, dict):
        raise ReceiptError("receipt must be a JSON object")
    validate_receipt(manifest_bytes, receipt)
    if not isinstance(index_blobs, dict):
        raise ReceiptError("index_blobs must map index digests to exact index bytes")
    requested_services = {entry["service"]: entry["image"] for entry in _service_images(manifest)}
    verified = {}
    for entry in receipt.get("observed", {}).get("services", []):
        if not isinstance(entry, dict):
            continue
        index_digest = entry.get("index_digest")
        if index_digest is None:
            continue
        service = entry.get("service")
        # R08: the requested service/image/index binding is enforced HERE,
        # by the public verification hook itself.
        if service not in requested_services:
            raise ReceiptError("observed service does not name a manifest-declared service")
        pinned = requested_services[service].split("@sha256:", 1)[1] if "@sha256:" in requested_services[service] else None
        if pinned is None or index_digest != "sha256:" + pinned:
            raise ReceiptError(
                "recorded index_digest is not the requested service's pinned image digest; membership "
                "can only be verified for an index the manifest itself pins"
            )
        if index_digest not in index_blobs:
            continue  # no bytes supplied: stays recorded-unchecked
        blob = index_blobs[index_digest]
        if not isinstance(blob, (bytes, bytearray)) or sha256_hex(blob) != index_digest.split(":", 1)[1]:
            raise ReceiptError(
                "the supplied index bytes do not hash to the recorded (pinned) index digest; the "
                "cross-check fails closed on wrong or unrelated bytes"
            )
        requested_platform = {
            k: manifest["image_platform"].get(k) for k in ("os", "architecture", "variant")
        }
        result = verify_index_membership(blob, index_digest, requested_platform)
        if result["resolved_manifest_digest"] != entry.get("resolved_manifest_digest"):
            raise ReceiptError(
                "recorded resolved_manifest_digest does not equal the digest resolved from the exact "
                "index bytes (forged or stale resolution)"
            )
        if result["index_entry"] != entry.get("index_entry"):
            raise ReceiptError(
                "recorded index_entry does not equal the exact byte-derived entry from the supplied "
                "index bytes (forged or stale membership proof)"
            )
        if entry.get("index_verification") != "verified":
            # S06: value-free diagnostic (the rejected recorded label is withheld).
            raise ReceiptError(
                "index bytes were supplied and verify, but the receipt does not record "
                "index_verification as 'verified'; a locally verified membership must be recorded "
                "as 'verified'"
            )
        verified[service] = INDEX_MEMBERSHIP_LOCALLY_VERIFIED
    return verified


def _validate_completion_consistency(receipt, manifest, errors):
    """R04: the designated completion result must agree with the recorded
    per-service termination observations.

    The run's exit evidence is the COMPLETION service's exit: its recorded
    exit_code must equal outputs.exit_code whenever the run finished
    (completed/failed). A contradictory pair (completed/exit_code=0 next to
    a failed completion container, or vice versa) is a rejection.
    Producer-first and completion-first orderings remain representable:
    auxiliary exits are recorded per service and never mask the completion
    exit.
    """
    outputs = receipt.get("outputs")
    observed = receipt.get("observed")
    if not isinstance(outputs, dict) or not isinstance(observed, dict):
        return
    services = observed.get("services")
    if not isinstance(services, list):
        return
    completion = manifest["outputs"].get("completion_service")
    if completion is None:
        names = [e["service"] for e in _service_images(manifest)]
        completion = names[0] if len(names) == 1 else None
    if not isinstance(completion, str):
        return
    status = outputs.get("status")
    exit_code = outputs.get("exit_code")
    completion_entry = None
    for entry in services:
        if isinstance(entry, dict) and entry.get("service") == completion:
            completion_entry = entry
    if completion_entry is None:
        return  # already reported by per-service validation
    recorded = completion_entry.get("exit_code")
    if status in ("completed", "failed") and isinstance(exit_code, int) and not isinstance(exit_code, bool):
        if not isinstance(recorded, int) or isinstance(recorded, bool):
            errors.append(
                ReceiptError(
                    "receipt.observed.services completion entry records no exit code but outputs "
                    "records one; the run's exit evidence is the completion service's termination"
                )
            )
        elif recorded != exit_code:
            errors.append(
                ReceiptError(
                    "receipt.outputs.exit_code does not equal the designated completion service's "
                    "recorded exit_code (contradictory exit evidence: the run's exit is the "
                    "completion service's exit)"
                )
            )
    if status == "cancelled" and recorded is not None and not isinstance(recorded, int):
        errors.append(ReceiptError("receipt.observed.services completion exit_code must be an integer when recorded"))


def _validate_observed(observed, manifest, environment, errors):
    """Requested vs observed identity (F02/C04/C06 + D03/D09/D10)."""
    if not isinstance(observed, dict):
        errors.append(ReceiptError("receipt.observed must be an object"))
        return
    unknown = set(observed) - OBSERVED_ALLOWED_KEYS
    if unknown:
        errors.append(
            ReceiptError(
                "receipt.observed has unsupported keys (names withheld); allowed keys are %s"
                % sorted(OBSERVED_ALLOWED_KEYS)
            )
        )
    services = observed.get("services")
    if not isinstance(services, list) or not services:
        errors.append(ReceiptError("receipt.observed.services must be a non-empty array (D09: per-service identity)"))
        return

    requested_services = {entry["service"]: entry["image"] for entry in _service_images(manifest)}
    seen_services = set()
    for entry in services:
        _validate_service_observation(entry, requested_services, manifest, environment, errors, seen_services)
    if seen_services != set(requested_services):
        missing = sorted(set(requested_services) - seen_services)
        errors.append(
            ReceiptError(
                "receipt.observed.services must cover every declared service exactly once; %d service(s) "
                "have no observation" % len(missing)
            )
        )

    # C04/D10: host-test binary identity is separate from VM-covered binaries
    # and now has a defined bundle encoding.
    host_toolchain = observed.get("host_toolchain")
    components = observed.get("host_toolchain_components")
    if environment == ENVIRONMENT_LINUX_TEST:
        if not (isinstance(host_toolchain, dict) and set(host_toolchain) == {"bundle_sha256"}):
            errors.append(
                ReceiptError(
                    "receipt.observed.host_toolchain is REQUIRED for linux-test receipts and must be "
                    "{bundle_sha256}: the digest of the host-side binary bundle actually executed "
                    "(defined encoding; its identity is recorded separately from VM-covered binaries)"
                )
            )
        elif not (isinstance(host_toolchain["bundle_sha256"], str) and HEX64_RE.match(host_toolchain["bundle_sha256"])):
            errors.append(ReceiptError("receipt.observed.host_toolchain.bundle_sha256 must be 64-hex"))
        # D10/E06: when the manifest declares a host toolchain policy, the
        # observed components are REQUIRED (omission no longer bypasses the
        # requested/admitted comparison).
        policy = manifest["runner"].get("host_toolchain_policy") if isinstance(manifest["runner"], dict) else None
        policy_declared = isinstance(policy, dict) and isinstance(policy.get("components"), list) and policy["components"]
        if components is None:
            if policy_declared:
                errors.append(
                    ReceiptError(
                        "receipt.observed.host_toolchain_components is REQUIRED when the manifest "
                        "declares runner.host_toolchain_policy (the comparison cannot be bypassed by "
                        "omitting the observed components)"
                    )
                )
        else:
            _validate_toolchain_components(components, errors)
            # E06: the bundle digest has a DEFINED preimage -- the canonical
            # encoding over the observed components -- and is checked when the
            # components are recorded.
            if components and all(
                isinstance(c, dict) and set(c) == set(TOOLCHAIN_COMPONENT_KEYS) and isinstance(c["name"], str) for c in components
            ):
                expected_bundle = host_toolchain_bundle_sha256(components)
                if isinstance(host_toolchain, dict) and host_toolchain.get("bundle_sha256") != expected_bundle:
                    errors.append(
                        ReceiptError(
                            "receipt.observed.host_toolchain.bundle_sha256 does not equal the defined "
                            "bundle encoding over the recorded host_toolchain_components"
                        )
                    )
            # D10: requested/admitted comparison -- computed ONLY over
            # shape-valid components (E07: a malformed name used to reach the
            # tuple comparison and crash after its error was recorded).
            if policy_declared and isinstance(components, list):
                valid_policy = [
                    c
                    for c in policy["components"]
                    if isinstance(c, dict) and isinstance(c.get("name"), str) and isinstance(c.get("sha256"), str)
                ]
                valid_observed = [
                    c
                    for c in components
                    if isinstance(c, dict) and set(c) == set(TOOLCHAIN_COMPONENT_KEYS) and isinstance(c["name"], str)
                ]
                if len(valid_policy) == len(policy["components"]) and len(valid_observed) == len(components):
                    declared = sorted((c["name"], c["sha256"]) for c in valid_policy)
                    observed_c = sorted((c["name"], c["sha256"]) for c in valid_observed)
                    if declared != observed_c:
                        errors.append(
                            ReceiptError(
                                "receipt.observed.host_toolchain_components does not equal "
                                "runner.host_toolchain_policy.components (requested/admitted comparison failed)"
                            )
                        )
    else:
        if host_toolchain is not None or components is not None:
            errors.append(
                ReceiptError(
                    "receipt.observed.host_toolchain/host_toolchain_components are only valid on "
                    "linux-test receipts; vm receipts are covered by the pinned base_vm bytes and the "
                    "runtime closure"
                )
            )


def _validate_toolchain_components(components, errors):
    if not isinstance(components, list) or not components or len(components) > 64:
        errors.append(ReceiptError("receipt.observed.host_toolchain_components must be a non-empty bounded array"))
        return
    names = set()
    for i, component in enumerate(components):
        if not isinstance(component, dict) or set(component) != set(TOOLCHAIN_COMPONENT_KEYS):
            errors.append(
                ReceiptError(
                    "receipt.observed.host_toolchain_components[%d] must have exactly {name, sha256}" % i
                )
            )
            continue
        if not isinstance(component["name"], str) or not component["name"]:
            errors.append(ReceiptError("receipt.observed.host_toolchain_components[%d].name must be a non-empty string" % i))
        if not (isinstance(component["sha256"], str) and HEX64_RE.match(component["sha256"])):
            errors.append(ReceiptError("receipt.observed.host_toolchain_components[%d].sha256 must be 64-hex" % i))
        # E07: hashable-guarded membership (a list-valued name used to reach
        # the set membership and crash with TypeError after its error was
        # recorded).
        if isinstance(component["name"], str):
            if component["name"] in names:
                errors.append(ReceiptError("receipt.observed.host_toolchain_components has duplicate component names"))
            names.add(component["name"])


def _validate_service_observation(entry, requested_services, manifest, environment, errors, seen_services):
    if not isinstance(entry, dict):
        errors.append(ReceiptError("receipt.observed.services[] entries must be objects"))
        return
    unknown = set(entry) - SERVICE_ALLOWED_KEYS
    if unknown:
        errors.append(
            ReceiptError(
                "receipt.observed.services[] has unsupported keys (names withheld); allowed keys are %s"
                % sorted(SERVICE_ALLOWED_KEYS)
            )
        )
    for field in ("service", "image", "resolved_manifest_digest", "platform", "container"):
        if field not in entry:
            errors.append(ReceiptError("receipt.observed.services[].%s is required" % field))
    if any(f not in entry for f in ("service", "image", "resolved_manifest_digest", "platform", "container")):
        return
    service = entry["service"]
    if not isinstance(service, str) or service not in requested_services:
        errors.append(ReceiptError("receipt.observed.services[].service must name a manifest-declared service"))
        return
    if service in seen_services:
        errors.append(ReceiptError("receipt.observed.services has a duplicate entry for service %s" % service))
    seen_services.add(service)

    if not isinstance(entry["image"], str) or not IMAGE_RE.match(entry["image"]):
        errors.append(ReceiptError("receipt.observed.services[].image must be repo@sha256:<64hex>"))
    elif entry["image"] != requested_services[service]:
        errors.append(
            ReceiptError(
                "receipt.observed.services[].image does not equal the requested pin for service %s; the "
                "receipt records the execution of the REQUESTED pinned reference" % service
            )
        )

    resolved = entry["resolved_manifest_digest"]
    if not isinstance(resolved, str) or not DIGEST_RE.match(resolved):
        errors.append(ReceiptError("receipt.observed.services[].resolved_manifest_digest must be exactly 'sha256:<64hex>'"))
        resolved = None

    pinned = None
    if isinstance(entry["image"], str) and "@sha256:" in entry["image"]:
        pinned = entry["image"].split("@sha256:", 1)[1]
    index_digest = entry.get("index_digest")
    if index_digest is not None:
        if not isinstance(index_digest, str) or not DIGEST_RE.match(index_digest):
            errors.append(ReceiptError("receipt.observed.services[].index_digest must be 'sha256:<64hex>' or absent"))
        elif resolved is not None and index_digest == resolved:
            errors.append(
                ReceiptError(
                    "receipt.observed.services[].index_digest must be the MULTI-ARCH INDEX digest, distinct "
                    "from the platform-child resolved_manifest_digest"
                )
            )
        if pinned is not None and isinstance(index_digest, str) and index_digest != "sha256:" + pinned:
            errors.append(
                ReceiptError(
                    "receipt.observed.services[].image pins a digest that index_digest does not match; when "
                    "the pinned reference is an index, index_digest must equal the pinned digest and "
                    "resolved_manifest_digest the platform child"
                )
            )
        # D03: membership claims are RECORDED, never self-certifying:
        # 'recorded-unchecked' records an unverified resolution and never
        # by itself backs verified membership; only verification over the
        # exact index bytes proves membership.
        verification = entry.get("index_verification")
        if verification not in INDEX_VERIFICATION_ACCEPTED:
            errors.append(
                ReceiptError(
                    "receipt.observed.services[].index_verification must be 'verified' or 'recorded-unchecked' "
                    "when index_digest is present: 'verified' records that membership was proven by "
                    "oci_index.verify_index_membership over the exact content-addressed index bytes, while "
                    "'recorded-unchecked' records an unverified resolution -- a recorded claim that never "
                    "by itself backs verified membership"
                )
            )
        index_entry = entry.get("index_entry")
        if not isinstance(index_entry, dict):
            errors.append(
                ReceiptError(
                    "receipt.observed.services[].index_entry is REQUIRED when index_digest is present: the "
                    "exact OCI index manifest entry for the resolved child (proof of membership)"
                )
            )
        else:
            extra = set(index_entry) - {"descriptor", "platform"}
            if extra:
                errors.append(
                    ReceiptError(
                        "receipt.observed.services[].index_entry has unsupported keys (names withheld); "
                        "allowed keys are ['descriptor', 'platform']"
                    )
                )
            descriptor = index_entry.get("descriptor")
            if not isinstance(descriptor, dict) or set(descriptor) - {"mediaType", "digest", "size"}:
                errors.append(ReceiptError("receipt.observed.services[].index_entry.descriptor must be {mediaType, digest, size}"))
            else:
                if descriptor.get("digest") != resolved:
                    errors.append(
                        ReceiptError(
                            "receipt.observed.services[].index_entry.descriptor.digest must equal the resolved "
                            "child manifest digest (index membership proof; an invented child is rejected)"
                        )
                    )
                if not isinstance(descriptor.get("mediaType"), str) or not descriptor["mediaType"]:
                    errors.append(ReceiptError("receipt.observed.services[].index_entry.descriptor.mediaType must be a non-empty string"))
                size = descriptor.get("size")
                if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
                    errors.append(ReceiptError("receipt.observed.services[].index_entry.descriptor.size must be a positive integer"))
            platform = index_entry.get("platform")
            if not isinstance(platform, dict):
                errors.append(ReceiptError("receipt.observed.services[].index_entry.platform must be an object"))
            else:
                requested = manifest["image_platform"]
                actual = {k: platform.get(k) for k in ("os", "architecture", "variant")}
                expected = {k: requested.get(k) for k in ("os", "architecture", "variant")}
                if actual != expected:
                    errors.append(
                        ReceiptError(
                            "receipt.observed.services[].index_entry.platform does not select the requested "
                            "platform (the executed child must be the requested platform's descriptor)"
                        )
                    )
    else:
        if resolved is not None and pinned is not None and resolved != "sha256:" + pinned:
            errors.append(
                ReceiptError(
                    "receipt.observed.services[].resolved_manifest_digest does not equal the pinned digest "
                    "and no index_digest is recorded; a direct pin must resolve to itself"
                )
            )
        if entry.get("index_entry") is not None or entry.get("index_verification") is not None:
            errors.append(
                ReceiptError("receipt.observed.services[].index_entry/index_verification are only valid together with index_digest")
            )

    platform = entry["platform"]
    if not isinstance(platform, dict):
        errors.append(ReceiptError("receipt.observed.services[].platform must be an object"))
        return
    unknown = set(platform) - {"os", "architecture", "variant"}
    if unknown:
        errors.append(ReceiptError("receipt.observed.services[].platform has unsupported keys (names withheld)"))
    requested_platform = manifest["image_platform"]
    if not (isinstance(platform.get("os"), str) and isinstance(platform.get("architecture"), str)):
        errors.append(ReceiptError("receipt.observed.services[].platform must include os and architecture strings"))
        return
    expected = {key: requested_platform.get(key) for key in ("os", "architecture", "variant")}
    actual = {key: platform.get(key) for key in ("os", "architecture", "variant")}
    if actual != expected:
        errors.append(
            ReceiptError(
                "receipt.observed.services[].platform does not equal the requested platform (per-platform "
                "resolution is exact; linux-test and vm receipts record the platform actually executed)"
            )
        )

    # R04: every service records its ACTUAL termination observation (the
    # lifecycle inspects every container before removal). The completion
    # service's code is cross-checked against outputs.exit_code in
    # _validate_completion_consistency; an auxiliary producer's nonzero exit
    # is RECORDED here without masking the completion exit.
    if "exit_code" not in entry or entry["exit_code"] is None:
        errors.append(
            ReceiptError(
                "receipt.observed.services[].exit_code is REQUIRED for every service (the frozen "
                "lifecycle inspects every container's State.ExitCode before removal; a missing or "
                "null termination observation cannot back the run's exit evidence)"
            )
        )
    else:
        ec = entry["exit_code"]
        if not isinstance(ec, int) or isinstance(ec, bool) or ec < 0:
            errors.append(ReceiptError("receipt.observed.services[].exit_code must be a non-negative integer"))

    # C04 + D10: observed registered runtime must equal the requested one, and
    # on vm receipts the observed EXECUTABLE bytes must equal the closure pin
    # with verified registration (same-name wrong-binary/wrong-args is
    # rejectable).
    container = entry["container"]
    if not isinstance(container, dict) or set(container) - CONTAINER_ALLOWED_KEYS:
        errors.append(
            ReceiptError(
                "receipt.observed.services[].container must be an object with exactly %s" % sorted(CONTAINER_ALLOWED_KEYS)
            )
        )
        return
    requested_runner = manifest["runner"]
    if container.get("name") != requested_runner.get("runtime_name"):
        errors.append(
            ReceiptError(
                "receipt.observed.services[].container.name does not equal the requested registered "
                "runtime; no fallback or substitution is representable"
            )
        )
    if container.get("version") != requested_runner.get("runtime_version"):
        errors.append(
            ReceiptError(
                "receipt.observed.services[].container.version does not equal the requested runtime "
                "release identity (live availability is verified against this exact release)"
            )
        )
    executable = container.get("executable_sha256")
    if not (isinstance(executable, str) and HEX64_RE.match(executable)):
        errors.append(
            ReceiptError(
                "receipt.observed.services[].container.executable_sha256 is REQUIRED (D10: the observed "
                "runtime executable/bundle bytes, rejectable against the runtime closure)"
            )
        )
    if container.get("registration_verified") is not True:
        errors.append(
            ReceiptError(
                "receipt.observed.services[].container.registration_verified must be true (D10: the "
                "registered path and exact arguments were verified against the closure before use)"
            )
        )
    # E06: the closure equality applies to BOTH VM environments (a
    # mac-attested receipt executes the same pinned guest closure; a
    # different observed binary is equally rejectable there).
    if environment in (ENVIRONMENT_VM, ENVIRONMENT_MAC_ATTESTED) and isinstance(executable, str):
        closure = requested_runner.get("runtime_closure") if isinstance(requested_runner, dict) else None
        component_name = RUNTIME_COMPONENT.get(requested_runner.get("runtime_name"))
        pinned_executable = None
        if isinstance(closure, dict) and isinstance(closure.get("components"), list):
            for component in closure["components"]:
                if isinstance(component, dict) and component.get("name") == component_name:
                    pinned_executable = component.get("sha256")
        if pinned_executable is None:
            errors.append(
                ReceiptError(
                    "%s receipts require the manifest to pin the runtime component in "
                    "runner.runtime_closure (the executable bytes live under the verity root)" % environment
                )
            )
        elif executable != pinned_executable:
            # S06: value-free diagnostic (the runtime component name is withheld).
            errors.append(
                ReceiptError(
                    "receipt.observed.services[].container.executable_sha256 does not equal the "
                    "observed runtime's runtime_closure pin (same-name wrong-binary registration "
                    "is rejected)"
                )
            )


def _validate_commitment(commitment, manifest_bytes, envelope_bytes, errors):
    """Validate the recorded commitment; returns its status string (C06).

    Full scope SHAPE is validated even without the envelope (a scope-less
    {} commitment is invalid everywhere). The envelope cross-check
    ('bound-to-validated-envelope') establishes CONSISTENCY between the
    recorded commitment and the caller-supplied validated envelope only;
    it neither observes execution nor authenticates an execution report,
    so it does not by itself establish which bytes actually executed --
    that requires the separate runner/verifier delivery interface and the
    authenticated-evidence obligations.
    """
    if commitment is None:
        if envelope_bytes is not None:
            envelope_summary = _validated_envelope(manifest_bytes, envelope_bytes, errors)
            if envelope_summary is not None and envelope_summary["commitment"] is not None:
                errors.append(
                    ReceiptError(
                        "receipt.runtime_inputs_commitment is null but the runtime-input envelope "
                        "carries a commitment; a receipt must record the caller's commitment exactly"
                    )
                )
        return "absent"
    if not isinstance(commitment, dict) or set(commitment) != {"alg", "scope", "inputs_sha256"}:
        errors.append(
            ReceiptError("receipt.runtime_inputs_commitment must be null or exactly {alg, scope, inputs_sha256}")
        )
        return "absent"
    if commitment["alg"] not in COMMITMENT_ALGS:
        errors.append(ReceiptError("receipt.runtime_inputs_commitment.alg must be one of %s" % (list(COMMITMENT_ALGS),)))
    ok, _include, _env_names, _file_slots = validate_commitment_scope_shape(commitment["scope"])
    if not ok:
        errors.append(
            ReceiptError(
                "receipt.runtime_inputs_commitment.scope must be the full validated scope shape "
                "({include} plus env_names/file_slots per selection) even in shape-only validation"
            )
        )
    if not (isinstance(commitment["inputs_sha256"], str) and HEX64_RE.match(commitment["inputs_sha256"])):
        errors.append(ReceiptError("receipt.runtime_inputs_commitment.inputs_sha256 must be 64-hex"))
    if envelope_bytes is None:
        return "recorded-unchecked"
    summary = _validated_envelope(manifest_bytes, envelope_bytes, errors)
    if summary is not None:
        env_commitment = summary["commitment"]
        if env_commitment is None:
            errors.append(
                ReceiptError(
                    "the runtime-input envelope carries NO commitment; an uncommitted run can never "
                    "acquire a receipt commitment (inputs are then NOT claimed fixed)"
                )
            )
            return "recorded-unchecked"
        else:
            # compare NORMALIZED forms (the envelope's commitment is
            # normalized during validation; the receipt records the caller's
            # exact object).
            normalized_receipt = dict(commitment, scope=_normalized_scope(commitment["scope"]))
            if env_commitment != normalized_receipt:
                errors.append(
                    ReceiptError(
                        "receipt.runtime_inputs_commitment does not equal the envelope's validated "
                        "commitment (alg/scope/digest must equal the supplied validated envelope's "
                        "commitment exactly)"
                    )
                )
                return "recorded-unchecked"
            return "bound-to-validated-envelope"
    return "recorded-unchecked"


def _validated_envelope(manifest_bytes, envelope_bytes, errors):
    from .runtime_inputs import validate_runtime_inputs_bytes

    try:
        return validate_runtime_inputs_bytes(manifest_bytes, envelope_bytes)
    except Exception as exc:  # noqa: BLE001 - surfaced as a contract error
        errors.append(ReceiptError("runtime-input envelope failed validation: %s" % exc))
        return None


def _validate_outputs(outputs, manifest, errors):
    if not isinstance(outputs, dict):
        errors.append(ReceiptError("receipt.outputs must be an object"))
        return
    required = {
        "status",
        "exit_code",
        "stdout",
        "stderr",
        "artifacts",
        "missing",
        "started_unix_s",
        "ended_unix_s",
        "cancel",
    }
    unknown = set(outputs) - required
    if unknown:
        errors.append(
            ReceiptError(
                "receipt.outputs has unsupported keys (names withheld); allowed keys are %s" % sorted(required)
            )
        )
    for field in sorted(required):
        if field not in outputs:
            errors.append(ReceiptError("receipt.outputs.%s is required" % field))
    if unknown or any(f not in outputs for f in required):
        return

    status = outputs["status"]
    if status not in STATUSES:
        errors.append(ReceiptError("receipt.outputs.status must be one of %s" % (STATUSES,)))
        status = None

    cancel = outputs["cancel"]
    if cancel is not None:
        if not isinstance(cancel, dict) or set(cancel) != {"reason", "at_unix_s"}:
            errors.append(ReceiptError("receipt.outputs.cancel must be null or {reason, at_unix_s}"))
        elif cancel.get("reason") not in CANCEL_REASONS:
            errors.append(ReceiptError("receipt.outputs.cancel.reason must be one of %s" % (list(CANCEL_REASONS),)))
        elif not isinstance(cancel.get("at_unix_s"), int) or isinstance(cancel.get("at_unix_s"), bool):
            errors.append(
                ReceiptError("receipt.outputs.cancel.at_unix_s must be an integer (canonical profile is integers-only; receipts are hashed)")
            )
    if status == "cancelled" and cancel is None:
        errors.append(ReceiptError("receipt.outputs.status 'cancelled' requires a non-null cancel object"))
    if status in ("completed", "failed") and cancel is not None:
        errors.append(ReceiptError("receipt.outputs.cancel must be null unless status is 'cancelled'"))

    exit_code = outputs["exit_code"]
    if exit_code is not None and (not isinstance(exit_code, int) or isinstance(exit_code, bool)):
        errors.append(ReceiptError("receipt.outputs.exit_code must be an integer or null"))
    # C06 status semantics: 'failed' preserves the ACTUAL exit code, including
    # exit 0 when a required artifact was missing at collection (a collection
    # failure is a failure). 'completed' alone asserts full success.
    if status == "completed" and exit_code != 0:
        errors.append(ReceiptError("receipt.outputs.status 'completed' requires exit_code == 0"))
    if status == "failed" and exit_code is None:
        errors.append(
            ReceiptError(
                "receipt.outputs.status 'failed' requires the actual exit code (an integer, possibly 0 "
                "when the workload exited 0 but collection found declared outputs missing)"
            )
        )
    if status == "cancelled" and exit_code is not None:
        errors.append(ReceiptError("receipt.outputs.status 'cancelled' requires exit_code null"))

    started = outputs["started_unix_s"]
    ended = outputs["ended_unix_s"]
    for field, value in (("started_unix_s", started), ("ended_unix_s", ended)):
        if not isinstance(value, int) or isinstance(value, bool):
            errors.append(
                ReceiptError(
                    "receipt.outputs.%s must be an integer (canonical profile is integers-only; receipts are hashed)"
                    % field
                )
            )
    if isinstance(started, int) and not isinstance(started, bool) and isinstance(ended, int) and not isinstance(ended, bool):
        if ended < started:
            errors.append(ReceiptError("receipt.outputs.ended_unix_s precedes started_unix_s"))

    declared_capture = set(manifest["outputs"]["capture"])
    for stream in ("stdout", "stderr"):
        node = outputs[stream]
        if stream in declared_capture:
            if not isinstance(node, dict) or set(node) != {"sha256", "bytes"}:
                errors.append(ReceiptError("receipt.outputs.%s must be {sha256, bytes} (declared capture)" % stream))
                continue
            digest = node["sha256"]
            nbytes = node["bytes"]
            if not (isinstance(nbytes, int) and not isinstance(nbytes, bool) and nbytes >= 0):
                errors.append(ReceiptError("receipt.outputs.%s.bytes must be a non-negative integer" % stream))
            if digest is None:
                if isinstance(nbytes, int) and nbytes != 0:
                    errors.append(ReceiptError("receipt.outputs.%s.sha256 may be null only when bytes is 0" % stream))
            elif not (isinstance(digest, str) and HEX64_RE.match(digest)):
                errors.append(ReceiptError("receipt.outputs.%s.sha256 must be 64-hex or null" % stream))
            if status == "completed" and digest is None:
                errors.append(ReceiptError("receipt.outputs.status 'completed' requires a digest for captured %s" % stream))
        else:
            if node is not None:
                errors.append(
                    ReceiptError(
                        "receipt.outputs.%s must be null; the manifest does not declare %s capture" % (stream, stream)
                    )
                )

    artifacts = outputs["artifacts"]
    if not isinstance(artifacts, list):
        errors.append(ReceiptError("receipt.outputs.artifacts must be an array"))
        artifacts = []
    missing = outputs["missing"]
    if not isinstance(missing, list) or any(not isinstance(m, str) for m in missing):
        errors.append(ReceiptError("receipt.outputs.missing must be an array of declared artifact names"))
        missing = []
    declared_artifacts = {a["name"]: a["path"] for a in manifest["outputs"]["artifacts"]}
    recorded_names = set()
    for entry in artifacts:
        if not isinstance(entry, dict) or set(entry) != {"name", "sha256", "bytes"}:
            errors.append(ReceiptError("receipt.outputs.artifacts[] entries need exactly {name, sha256, bytes}"))
            continue
        name = entry["name"]
        if not isinstance(name, str):
            errors.append(ReceiptError("receipt.outputs.artifacts[].name must be a string"))
            continue
        if name not in declared_artifacts:
            # E08: stop field-specific processing after rejecting an
            # undeclared name -- subsequent diagnostics for the same entry
            # used to echo the withheld name via digest/size messages.
            errors.append(
                ReceiptError(
                    "receipt.outputs.artifacts contains a name that was not declared in the manifest "
                    "(name withheld); only declared artifacts may be recorded"
                )
            )
            continue
        if name in recorded_names:
            errors.append(ReceiptError("receipt.outputs.artifacts has duplicate name %s" % name))
        recorded_names.add(name)
        if not (isinstance(entry["sha256"], str) and HEX64_RE.match(entry["sha256"])):
            errors.append(ReceiptError("receipt.outputs.artifacts[%s].sha256 must be 64-hex" % name))
        if not (isinstance(entry["bytes"], int) and not isinstance(entry["bytes"], bool) and entry["bytes"] >= 0):
            errors.append(ReceiptError("receipt.outputs.artifacts[%s].bytes must be a non-negative integer" % name))

    declared_names = set(declared_artifacts)
    unknown_missing = [m for m in missing if m not in declared_names]
    for _name in unknown_missing:
        # D06: caller-controlled names are withheld in diagnostics.
        errors.append(
            ReceiptError(
                "receipt.outputs.missing contains a name that was not declared in the manifest (name withheld)"
            )
        )
    # C06: recorded and missing sets must be unique and disjoint.
    duplicate_missing = len(missing) != len(set(missing))
    if duplicate_missing:
        errors.append(ReceiptError("receipt.outputs.missing has duplicate names"))
    overlap = recorded_names & set(missing)
    if overlap:
        errors.append(
            ReceiptError(
                "receipt.outputs records %d artifact(s) as BOTH recorded and missing; the sets must be "
                "disjoint" % len(overlap)
            )
        )
    # Missing-output semantics: every declared artifact is either recorded or
    # explicitly missing; nothing may silently vanish (F02).
    for name in sorted(declared_names - recorded_names - set(missing)):
        errors.append(
            ReceiptError(
                "declared artifact %s is neither recorded nor declared missing; receipts must account "
                "for every declared output" % name
            )
        )
    if status == "completed":
        if missing:
            errors.append(ReceiptError("receipt.outputs.status 'completed' forbids missing artifacts"))
        for name in sorted(declared_names):
            if name not in recorded_names:
                errors.append(ReceiptError("receipt.outputs.status 'completed' requires artifact %s to be recorded" % name))
