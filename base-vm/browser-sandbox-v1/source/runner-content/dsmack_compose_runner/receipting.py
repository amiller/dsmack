"""Receipt v4 assembly for linux-test (UNATTESTED) and vm runs.

Every receipt is self-checked with the shared library's ``validate_receipt``
BEFORE it is written: an invalid receipt is a runner error, never an output.

Environment (VM-OBSERVATIONS):
  * ``linux-test`` (default; host-unit/host-Docker reproduction): no VM boots,
    so ``base_vm_launch.boot`` is null, ``attestation`` null, and the observed
    host toolchain bundle is recorded.
  * ``vm``: a real guest VM booted the admitted image.  The caller MUST supply
    a VALIDATED boot observation gathered from the running VM (admitted recorded component/mode claims plus actual live cmdline and root verity geometry; preboot consumption requires the external authenticated full boot join); the
    receipt records ``base_vm_launch.boot`` as the frozen VM shape and OMITS the
    host-toolchain bundle (vm receipts are covered by the pinned base_vm bytes
    and the runtime closure).  ``attestation`` stays null (vm is NOT
    mac-attested) and ``loader_mode`` is recorded verbatim from the observation
    (``held-fd`` is honest engineering transport; it is NEVER upgraded to the
    cryptographic ``owned-copy`` invariant here).  A MISSING or malformed
    observation is a fail-closed runner error -- null boot data is NEVER
    relabelled as a VM boot (COORDINATOR policy).

Index pins use child-digest pins (resolved_manifest_digest == pin; no
index_digest) so membership stays honestly absent rather than
``recorded-unchecked`` theater.
"""

from __future__ import annotations

import hashlib

from dsmack_compose_contract import (
    canonical_bytes,
    sha256_hex,
    validate_receipt,
)

#: Environments this runner can PRODUCE. mac-attested is never produced here
#: (no attestation is minted by this runner).
PRODUCIBLE_ENVIRONMENTS = ("linux-test", "vm")

#: The exact boot-observation input shape the supervisor/CLI supply for a vm
#: run (``dsmack.vm-boot-observation/1``). Every field is REQUIRED; the receipt
#: builder assembles the frozen receipt boot shape from it and self_check binds
#: it to the manifest. Preboot consumption is established only by the mandatory
#: external join to authenticated native facts, never by these claims alone.
VM_BOOT_OBSERVATION_KEYS = {
    "loader_mode",
    "kernel_sha256",
    "initrd_sha256",
    "rootfs_sha256",
    "metadata_sha256",
    "cmdline",
    "verity_root_hash",
    "verity_data_bytes",
}
_LOADER_MODES = ("owned-copy", "held-fd")


def validate_boot_observation(obs) -> dict:
    """Fail-closed shape validation of a vm boot observation (VM-OBSERVATIONS).

    This is a STRUCTURAL gate only -- the binding to the admitted manifest
    identity is enforced by ``validate_receipt`` over the assembled receipt
    (self_check).  A None/malformed observation raises, so a vm run can NEVER
    acquire a null boot object. Structurally valid recorded claims alone are not authenticated consumption proof."""
    if not isinstance(obs, dict):
        raise ValueError("vm boot observation is required for a vm receipt and must be an object "
                         "(null boot data is never relabelled as a VM boot)")
    missing = sorted(VM_BOOT_OBSERVATION_KEYS - set(obs))
    extra = sorted(set(obs) - VM_BOOT_OBSERVATION_KEYS)
    if missing or extra:
        raise ValueError("vm boot observation must carry exactly %s (missing=%s extra=%s)"
                         % (sorted(VM_BOOT_OBSERVATION_KEYS), missing, extra))
    if obs["loader_mode"] not in _LOADER_MODES:
        raise ValueError("vm boot observation loader_mode must be one of %s" % (list(_LOADER_MODES),))
    for field in ("kernel_sha256", "initrd_sha256", "rootfs_sha256", "metadata_sha256",
                  "verity_root_hash"):
        v = obs[field]
        if not (isinstance(v, str) and len(v) == 64 and all(c in "0123456789abcdef" for c in v)):
            raise ValueError("vm boot observation %s must be a 64-hex recorded claim" % field)
    if not (isinstance(obs["cmdline"], str) and obs["cmdline"]):
        raise ValueError("vm boot observation cmdline must be the non-empty booted kernel cmdline")
    v = obs["verity_data_bytes"]
    if not (isinstance(v, int) and not isinstance(v, bool) and v > 0):
        raise ValueError("vm boot observation verity_data_bytes must be a positive integer")
    return obs


def _vm_boot(obs: dict) -> dict:
    """Assemble the frozen receipt base_vm_launch.boot object from the validated
    observation. The verity geometry is the canonical dstack layout: 4096-byte
    blocks, salt 0^64, hash_offset == data_bytes, and total_bytes DERIVED from
    the observed data_bytes via the contract's frozen ``verity_layout`` (the
    same formula validate_receipt checks against, so the derived total can never
    disagree with the admitted geometry). validate_receipt then binds every
    recorded value to the admitted manifest identity."""
    from dsmack_compose_contract.image_admission import verity_layout

    cmdline = obs["cmdline"]
    data_bytes = obs["verity_data_bytes"]
    total_bytes = verity_layout(data_bytes)["total_bytes"]
    return {
        "loader_mode": obs["loader_mode"],
        "kernel_sha256": obs["kernel_sha256"],
        "initrd_sha256": obs["initrd_sha256"],
        "rootfs_sha256": obs["rootfs_sha256"],
        "metadata_sha256": obs["metadata_sha256"],
        "cmdline": cmdline,
        "cmdline_sha256": sha256_hex(cmdline),
        "verity": {
            "block_bytes": 4096,
            "data_bytes": data_bytes,
            "hash_offset_bytes": data_bytes,
            "root_hash": obs["verity_root_hash"],
            "salt_hex": "0" * 64,
            "total_bytes": total_bytes,
        },
    }


def host_toolchain_bundle_sha256(components) -> str:
    """The defined preimage: canonical(["dsmack.host-toolchain-bundle/1",
    [[name, sha256], ...] sorted by name])."""
    payload = ["dsmack.host-toolchain-bundle/1", sorted(([c["name"], c["sha256"]] for c in components))]
    return sha256_hex(canonical_bytes(payload))


def build_receipt(*, manifest_bytes, manifest, run_id, admission, runtime_observation,
                  image_identity_by_service, lifecycle_observation, toolchain_components,
                  commitment=None, environment="linux-test", boot_observation=None) -> dict:
    if environment not in PRODUCIBLE_ENVIRONMENTS:
        raise ValueError("runner bug: environment %r is not producible by this runner (%s)"
                         % (environment, PRODUCIBLE_ENVIRONMENTS))
    # VM-OBSERVATIONS: vm requires live cmdline/root observations plus admitted claims;
    # a linux-test receipt forbids one (no VM boots on the test host).
    if environment == "vm":
        boot = _vm_boot(validate_boot_observation(boot_observation))
    else:
        if boot_observation is not None:
            raise ValueError("runner bug: a boot observation was supplied for a linux-test "
                             "receipt (no VM boots on the test host; boot is null)")
        boot = None

    services = []
    for service, service_obs in sorted(lifecycle_observation["services"].items()):
        exit_code = service_obs["exit_code"]
        if exit_code is None:
            # No observed termination code is never invented; the receipt
            # validator rejects a missing observation, so this is a runner
            # bug surfaced honestly rather than a fabricated code.
            raise ValueError("runner bug: service %s has no observed exit code" % service)
        identity = image_identity_by_service[service]
        services.append(
            {
                "service": service,
                "image": manifest_image_pin(manifest, service),
                "resolved_manifest_digest": identity["resolved_manifest_digest"],
                "platform": {
                    "os": identity["os"],
                    "architecture": identity["architecture"],
                },
                "exit_code": exit_code,
                "container": {
                    "name": runtime_observation["runtime_name"],
                    "version": runtime_observation["runtime_version"],
                    "executable_sha256": runtime_observation["executable_sha256"],
                    "registration_verified": bool(runtime_observation["registration_verified"]),
                },
            }
        )

    streams = {}
    for stream in ("stdout", "stderr"):
        if stream in manifest["outputs"]["capture"]:
            data = lifecycle_observation["streams"].get(stream)
            if data is None:
                raise ValueError("runner bug: declared stream %s was never captured" % stream)
            streams[stream] = {
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
            }
        else:
            streams[stream] = None

    artifacts = []
    recorded_names = set()
    for entry in lifecycle_observation["artifacts"]:
        artifacts.append({"name": entry["name"], "sha256": entry["sha256"], "bytes": entry["bytes"]})
        recorded_names.add(entry["name"])
    missing = []
    for name in lifecycle_observation["missing"]:
        if name in recorded_names:
            raise ValueError("runner bug: artifact %s is both recorded and missing" % name)
        missing.append(name)

    cancelled = lifecycle_observation["status"] == "cancelled"
    outputs = {
        "status": lifecycle_observation["status"],
        "exit_code": lifecycle_observation["exit_code"],
        "stdout": streams["stdout"],
        "stderr": streams["stderr"],
        "artifacts": artifacts,
        "missing": missing,
        "started_unix_s": lifecycle_observation["started_unix_s"],
        "ended_unix_s": lifecycle_observation["ended_unix_s"],
        "cancel": lifecycle_observation["cancel"],
    }
    if cancelled and outputs["exit_code"] is not None:
        raise ValueError("runner bug: cancelled run recorded a non-null exit code")

    # VM-OBSERVATIONS: the observed host-toolchain bundle is a LINUX-TEST
    # artifact (host-Docker binaries). A vm receipt is covered by the pinned
    # base_vm bytes and the runtime closure instead and MUST NOT carry it (the
    # validator rejects host_toolchain on vm receipts), so it is included only
    # for linux-test and the toolchain is required only there.
    if environment == "linux-test":
        if not toolchain_components:
            raise ValueError("runner bug: the observed host toolchain was never recorded")
        observed = {
            "services": services,
            "host_toolchain": {
                "bundle_sha256": host_toolchain_bundle_sha256(toolchain_components),
            },
            "host_toolchain_components": [
                {"name": c["name"], "sha256": c["sha256"]} for c in toolchain_components
            ],
        }
    else:
        observed = {"services": services}

    receipt = {
        "receipt_version": 4,
        "environment": environment,
        "run_id": run_id,
        "manifest_sha256": sha256_hex(manifest_bytes),
        "base_vm": manifest["base_vm"],
        "base_vm_launch": {
            "admission": {
                "decision": admission["decision"],
                "os_image_hash": admission["os_image_hash"],
                "admission_sha256": admission["admission_sha256"],
                "admission_version": admission["admission_version"],
            },
            # VM-OBSERVATIONS: null for linux-test; the frozen VM boot shape
            # (live observations plus recorded admitted claims) for vm.
            "boot": boot,
        },
        "runner": manifest["runner"],
        "harness_sha256": manifest["harness"]["sha256"],
        # The caller's validated commitment recorded VERBATIM (or null -- an
        # uncommitted run never acquires one). With the envelope supplied at
        # self-check time the library cross-binds it; the check is
        # consistency with the supplied validated envelope only.
        "runtime_inputs_commitment": commitment,
        "observed": observed,
        "outputs": outputs,
        "attestation": None,
    }
    return receipt


def manifest_image_pin(manifest, service) -> str:
    for entry in manifest_compose_services(manifest):
        if entry[0] == service:
            return entry[1]
    raise ValueError("runner bug: unknown service %s" % service)


def manifest_compose_services(manifest):
    import json

    doc = json.loads(manifest["docker_compose_file"])
    return [(name, svc["image"]) for name, svc in doc["services"].items() if isinstance(svc, dict)]


def self_check(manifest_bytes, receipt, envelope_bytes=None) -> dict:
    """The shared library is the arbiter: a receipt that does not validate
    is a runner error and is never written."""
    return validate_receipt(manifest_bytes, receipt, envelope_bytes=envelope_bytes)
