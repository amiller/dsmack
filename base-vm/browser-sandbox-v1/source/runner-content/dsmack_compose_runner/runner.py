"""The runner orchestration: validate -> admit -> lower -> resolve ->
deliver -> execute -> collect -> receipt -> cleanup.

Every fail-closed gate the contract assigns to the runner lives here in
explicit order, and cleanup runs after EVERY outcome. The pre-lowering
daemon bootstrap probe uses the same explicit-allowlist env shape the
lowered config will produce (endpoint from the caller, isolated empty
dirs) -- the ambient environment is never read at any point.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import signal
import subprocess
import time

from dsmack_compose_contract import (
    RUNTIME_RUNC,
    delivery_plan,
    lower,
    render_compose_file,
    validate_manifest_bytes,
    validate_runtime_inputs_bytes,
)
from dsmack_compose_contract.image_admission import admit_image
from dsmack_compose_contract.lowering import local_image_ref
from dsmack_compose_contract.manifest import _effective_limits

from .control import ControlContext
from .errors import RunnerError
from .identity import ensure_image, resolve_harness, verify_runtime_closure
from .lifecycle import CANCEL_EXTERNAL, CancelEvent, execute
from .receipting import build_receipt, manifest_compose_services, self_check
from .workspace import Workspace

_CONTROL_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def _toolchain_components(closure_path: str) -> list:
    """The observed host toolchain: the actual docker CLI, compose plugin
    and runtime executable bytes this run used (measured, sha256)."""
    components = []
    docker_path = next(
        (p for p in ("/usr/bin/docker", "/usr/local/bin/docker") if os.path.isfile(p)), None
    )
    if docker_path is None:
        raise RunnerError("toolchain-unmeasurable", "the docker CLI binary was not found at a known path")
    components.append(_component("docker", docker_path))
    compose_path = next(
        (
            p
            for p in (
                "/usr/libexec/docker/cli-plugins/docker-compose",
                "/usr/lib/docker/cli-plugins/docker-compose",
                "/usr/local/lib/docker/cli-plugins/docker-compose",
                "/usr/local/libexec/docker/cli-plugins/docker-compose",
                "/usr/local/bin/docker-compose",
            )
            if os.path.isfile(p)
        ),
        None,
    )
    if compose_path is None:
        raise RunnerError("toolchain-unmeasurable", "the compose plugin binary was not found at a known path")
    components.append(_component("docker-compose", compose_path))
    components.append(_component("runc", closure_path))
    return components


def _component(name: str, path: str) -> dict:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return {"name": name, "sha256": digest.hexdigest()}


def _workload_delivery(plan: dict) -> dict:
    """The WORKLOAD-ONLY view of a validated delivery plan handed to the
    private workspace.

    Broker-audience inputs (``broker_env`` / ``broker_files``, e.g. the
    ``CLAUDE_SUBSCRIPTION_OAUTH`` bearer credential) are held by the per-run
    sentinel, staged out-of-band by the harness, and are NEVER materialized
    under the workload workspace (C03). The caller keeps the FULL validated
    ``plan`` for commitment/audience accounting and for rendering the
    workload env; only this filtered view crosses the workspace boundary.

    The workspace guard stays fail-closed and UNCHANGED: it is handed no
    broker data here, and a plan still carrying broker inputs that is passed
    to ``Workspace.materialize_delivery`` directly (a forged or misused call)
    is still refused. This view carries only ``workload_files`` and
    ``user_config``; it never fabricates or substitutes a credential."""
    workload_delivery = dict(plan)
    workload_delivery["broker_env"] = {}
    workload_delivery["broker_files"] = []
    return workload_delivery


def run_manifest(
    manifest_bytes: bytes,
    *,
    envelope_bytes: bytes | None,
    daemon_endpoint: str,
    run_id: str,
    workspace_root: str,
    control_dir: str,
    base_bundle_dir: str,
    admission_path: str,
    receipt_out_path: str | None = None,
    summary_out_path: str | None = None,
    export_artifacts_dir: str | None = None,
    export_outputs_dir: str | None = None,
    broker: dict | None = None,
    environment: str = "linux-test",
    boot_observations_path: str | None = None,
) -> tuple[dict, dict]:
    """Execute one manifest (with optional runtime inputs) and return
    (receipt_dict, run_summary); both are written when *_out_path given.
    Raises RunnerError on any fail-closed condition; cleanup runs even
    then."""
    from .workspace import write_private_file

    workspace = None
    receipt = None
    run_summary = None
    per_run_control_dir = None  # F04: destroyed in finally (holds rendered values)
    started_wall = int(time.time())
    try:
        # -- 1. validate the exact manifest bytes (identity) ----------------
        manifest, summary = validate_manifest_bytes(manifest_bytes)
        manifest_sha256 = summary["manifest_sha256"]

        # VM-OBSERVATIONS: resolve the environment + the (validated) real VM
        # boot observation. 'vm' REQUIRES an observation input gathered from the
        # running VM; a missing one fails closed here (null boot data is never
        # relabelled as a VM boot). 'linux-test' forbids one. The observation is
        # bound to the admitted manifest identity later by the receipt self-check.
        if environment not in ("linux-test", "vm"):
            raise RunnerError("environment-unsupported",
                              "--environment must be 'linux-test' or 'vm' (mac-attested is not produced here)")
        boot_observation = None
        if environment == "vm":
            if not boot_observations_path:
                raise RunnerError("vm-observations-missing",
                                  "--environment vm REQUIRES --boot-observations <json> gathered from "
                                  "the running VM; refusing to fabricate a boot object")
            try:
                with open(boot_observations_path, "rb") as _h:
                    boot_observation = json.loads(_h.read().decode("utf-8"))
            except (OSError, ValueError) as exc:
                raise RunnerError("vm-observations-unreadable",
                                  "the boot-observations input could not be read/parsed: %s"
                                  % type(exc).__name__) from None
            # a declared schema is accepted but not required by the receipt shape
            if isinstance(boot_observation, dict):
                boot_observation.pop("schema", None)
        elif boot_observations_path:
            raise RunnerError("vm-observations-unexpected",
                              "--boot-observations is only valid with --environment vm")

        # -- 2. control context (explicit endpoint; isolated empty dirs) ----
        # The control dir is PER-RUN (the caller passes the parent): the
        # generated compose file and parser diagnostics are private to this
        # run and destroyed with it. All runner paths are REQUIRED absolute
        # (relative paths would make the workspace-boundary mount check and
        # compose source resolution ambiguous).
        for label, path in (("--workspace-root", workspace_root), ("--control-dir", control_dir)):
            if not os.path.isabs(path):
                raise RunnerError("path-not-absolute", "%s must be an absolute path" % label)
        control_dir = os.path.join(control_dir, run_id)
        if os.path.lexists(control_dir):
            raise RunnerError("control-dir-collision", "the per-run control directory already exists; run_id must be fresh")
        os.makedirs(control_dir, mode=0o700)
        os.chmod(control_dir, 0o700)
        per_run_control_dir = control_dir
        control = ControlContext(
            daemon_endpoint=daemon_endpoint,
            control_dir=control_dir,
            compose_pin=manifest["runner"]["compose_tool"]["version"],
        )

        # -- 3. bootstrap daemon probe under an explicit allowlist env ------
        bootstrap_env = {
            "PATH": _CONTROL_PATH,
            "DOCKER_HOST": daemon_endpoint,
            "HOME": control.docker_config_dir,
        }
        info = _daemon_info_bootstrap(bootstrap_env)
        registered = set((info.get("Runtimes") or {}).keys())
        if "io.containerd.runc.v2" in registered:
            registered.add("runc")
        requested_runtime = manifest["runner"]["runtime_name"]
        if requested_runtime not in registered:
            raise RunnerError(
                "runtime-unavailable",
                "the manifest requests registered runtime %r which the live daemon does not "
                "register; the contract REQUIRES failing closed -- no silent fallback"
                % requested_runtime,
            )

        # -- 4. external admission over the REAL bundle bytes (fail closed) -
        admission_result = admit_base_bundle(manifest, base_bundle_dir, admission_path)

        # -- 5. lower (deterministic; fail-closed runtime/broker checks) ----
        workspace_path = os.path.join(workspace_root, "%s-%s" % (run_id, manifest_sha256[:12]))
        # F02: the broker is a CALLER-SUPPLIED capability (the harness/pinned
        # adapter launches the per-run sentinel and passes its endpoint) --
        # the runner no longer hardcodes broker=None. A credential-required
        # manifest with NO broker still fails closed; a supplied broker makes
        # both credential profiles executable (broker-audience inputs route
        # through the sentinel, never to the workload directly).
        if broker is not None and not (isinstance(broker, dict) and isinstance(broker.get("endpoint"), str) and broker["endpoint"]):
            raise RunnerError("broker-invalid", "a supplied broker must carry a string endpoint")
        lowered = lower(
            manifest,
            manifest_sha256,
            daemon_endpoint=daemon_endpoint,
            run_id=run_id,
            workspace_host_dir=workspace_path,
            runtime_available=tuple(sorted(registered)),
            broker=broker,
        )
        if lowered["requires_broker"] and broker is None:
            raise RunnerError(
                "broker-unavailable",
                "this run requires a credential broker; broker-audience inputs are never handed to "
                "a workload directly and no broker is configured -- failing closed",
            )
        sentinel_endpoint = broker["endpoint"] if broker is not None else None
        control.install_lowered_env(lowered)
        if control.build_env().get("DOCKER_HOST") != daemon_endpoint:
            raise RunnerError("control-env-endpoint-mismatch", "the lowered endpoint diverged from the explicit selection")
        tools = control.check_tools()

        # -- 6. live identity: runtime closure, images, harness -------------
        runtime_observation = verify_runtime_closure(control, manifest)
        image_identity = {}
        completion_service = lowered["completion_service"]
        for service, pin in manifest_compose_services(manifest):
            image_identity[service] = {
                "pin": pin,
                "resolved_manifest_digest": "sha256:" + pin.split("@sha256:", 1)[1],
                **ensure_image(control, local_image_ref(pin), manifest["image_platform"]),
            }
        completion_pin = image_identity[completion_service]["pin"]
        harness_observation = resolve_harness(control, manifest, local_image_ref(completion_pin))

        # -- 7. runtime inputs (validated envelope; optional) ----------------
        envelope_dict = None
        env_summary = None
        stdin_bytes = None
        plan = None
        if envelope_bytes is not None:
            env_summary = validate_runtime_inputs_bytes(manifest_bytes, envelope_bytes)
            envelope_dict = json.loads(envelope_bytes.decode("utf-8"))
            plan = delivery_plan(manifest, envelope_dict)
            if (plan["broker_env"] or plan["broker_files"]) and broker is None:
                raise RunnerError(
                    "broker-unavailable",
                    "broker-audience inputs require a credential broker; failing closed",
                )
            # When a broker IS supplied, broker-audience inputs are held by the
            # per-run sentinel (staged by the harness out-of-band) and are never
            # materialized into the workload workspace; the workload reaches
            # them only through the sentinel endpoint rendered below (F02).
            if plan["stdin_b64"] is not None:
                stdin_bytes = base64.b64decode(plan["stdin_b64"])

        # -- 8. private workspace + materialization --------------------------
        limits = _effective_limits(manifest)
        workspace = Workspace(
            root=workspace_root,
            run_id=run_id,
            manifest_sha256=manifest_sha256,
            cap_bytes=limits["workspace_max_bytes"],
        )
        cap_mode = workspace.prepare_cap(["inputs", "state", "artifacts"])
        delivered = {"files": [], "user_config": None}
        if plan is not None:
            # PRODUCT-DELIVERY: reaching here means the fail-closed broker gates
            # already passed -- step 5 (lowering requires_broker) and step 7 (the
            # envelope broker-audience check) both refuse a required broker with
            # none supplied BEFORE any workspace exists. The workspace receives a
            # WORKLOAD-ONLY view (_workload_delivery): broker-audience inputs
            # (e.g. CLAUDE_SUBSCRIPTION_OAUTH) are held by the per-run sentinel
            # out-of-band and are NEVER materialized under the workload
            # workspace. The full validated `plan` is preserved for
            # commitment/audience accounting and for workload_env rendering
            # below; the workspace guard stays fail-closed and unchanged.
            delivered = workspace.materialize_delivery(_workload_delivery(plan))

        # -- 9. render + execute the frozen lifecycle ------------------------
        # F02: when a broker is configured, the concrete workload-reachable
        # sentinel endpoint is rendered into the broker-capability services;
        # render fails closed if a broker is required but no endpoint is given.
        compose_text = render_compose_file(
            manifest, lowered, workload_env=(plan or {}).get("workload_env", {}),
            sentinel_endpoint=sentinel_endpoint,
        )
        cancel = CancelEvent()
        previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}

        def _handler(signum, frame, _cancel=cancel):
            _cancel.cancel(CANCEL_EXTERNAL)

        for sig in previous:
            signal.signal(sig, _handler)
        try:
            observation = execute(
                control,
                lowered,
                manifest,
                workspace,
                compose_text.encode("utf-8"),
                cancel=cancel,
                stdin_bytes=stdin_bytes,
            )
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)

        # -- 10. toolchain + receipt (self-checked before writing) ------------
        toolchain = _toolchain_components(runtime_observation["executable_path"])
        receipt = build_receipt(
            manifest_bytes=manifest_bytes,
            manifest=manifest,
            run_id=run_id,
            admission=admission_result,
            runtime_observation=runtime_observation,
            image_identity_by_service=image_identity,
            lifecycle_observation=observation,
            toolchain_components=toolchain,
            commitment=(env_summary or {}).get("commitment"),
            environment=environment,
            boot_observation=boot_observation,
        )
        self_check(manifest_bytes, receipt, envelope_bytes=envelope_bytes)

        # The exact artifact source paths inside the (not-yet-destroyed)
        # private workspace, keyed by recorded artifact name.
        artifact_sources = {
            entry["name"]: os.path.join(workspace.artifacts, _artifact_segment(manifest, entry["name"]))
            for entry in observation["artifacts"]
        }

        # Explicit PUBLIC EXPORT of collected artifacts (legacy, artifact-only):
        # recorded entries are copied out of the private workspace before
        # cleanup destroys it. Symlinks/special files were never collected.
        if export_artifacts_dir is not None:
            os.makedirs(export_artifacts_dir, mode=0o755, exist_ok=True)
            import stat as stat_module

            for entry in observation["artifacts"]:
                source = artifact_sources[entry["name"]]
                st = os.lstat(source)
                if stat_module.S_ISLNK(st.st_mode) or not stat_module.S_ISREG(st.st_mode):
                    raise RunnerError("export-refused", "refusing to export a non-regular artifact entry")
                target = os.path.join(export_artifacts_dir, entry["name"])
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
                with os.fdopen(fd, "wb") as handle, open(source, "rb") as src:
                    handle.write(src.read())

        run_summary = _summarize(
            run_id=run_id,
            manifest_sha256=manifest_sha256,
            daemon_endpoint=daemon_endpoint,
            tools=tools,
            admission_result=admission_result,
            runtime_observation=runtime_observation,
            image_identity=image_identity,
            observation=observation,
            receipt=receipt,
            env_summary=env_summary,
            envelope_dict=envelope_dict,
            manifest=manifest,
            workspace=workspace,
            harness_observation=harness_observation,
            started_wall=started_wall,
        )

        # I/O-CONTINUITY: the COMPLETE result-image package -- the ACTUAL
        # completion stdout/stderr bytes AND artifact bytes AND the frozen v4
        # receipt written through this lifecycle to the CANONICAL guest
        # result-image layout, with the per-selector outputs/EXPORT-COMPLETE
        # marker published LAST, BEFORE the finally-cleanup destroys the
        # workspace. The receipt is committed before the marker; digests/
        # lengths are bound to the receipt; a failure leaves no marker (no
        # false complete). The SELECTOR is the MANIFEST NAME (a confined single
        # segment) so a shared result root carries one subtree per manifest
        # (multi-selector completion); run_id stays the receipt's run identity.
        if export_outputs_dir is not None:
            from dsmack_compose_contract import canonical_bytes
            from .export_outputs import export_run_outputs

            selector = manifest["name"]
            receipt_bytes = canonical_bytes(receipt) + b"\n"
            summary_bytes = json.dumps(run_summary, indent=1, sort_keys=True).encode("utf-8") + b"\n"
            export_index = export_run_outputs(
                export_outputs_dir,
                selector=selector,
                receipt=receipt,
                receipt_bytes=receipt_bytes,
                streams=observation["streams"],
                artifact_sources=artifact_sources,
                stream_truncated=observation.get("stream_truncated"),
                summary_bytes=summary_bytes,
            )
            run_summary["output_export"] = {
                "result_root": export_outputs_dir,
                "selector": selector,
                "receipt_sha256": export_index["receipt_sha256"],
                "marker": "outputs/EXPORT-COMPLETE",
            }
    finally:
        if workspace is not None:
            cleanup_stats = workspace.cleanup()
            if run_summary is not None:
                run_summary["cleanup"] = cleanup_stats
                run_summary["workspace_removed"] = not os.path.exists(workspace.path)
        # F04: the per-run control directory holds the rendered compose file
        # and parser diagnostics (runtime env VALUES). It is separately
        # allocated from the workspace and MUST be destroyed on every outcome
        # -- not left behind with the workspace removed.
        if per_run_control_dir is not None:
            import shutil as _shutil

            _shutil.rmtree(per_run_control_dir, ignore_errors=True)
            if run_summary is not None:
                run_summary["control_dir_removed"] = not os.path.exists(per_run_control_dir)

    if receipt_out_path is not None:
        from dsmack_compose_contract import canonical_bytes

        write_private_file(os.path.dirname(receipt_out_path) or ".", os.path.basename(receipt_out_path),
                           canonical_bytes(receipt) + b"\n")
        os.chmod(receipt_out_path, 0o644)
        _fsync_path_and_parent(receipt_out_path)
    if summary_out_path is not None:
        _write_and_fsync(summary_out_path,
                         json.dumps(run_summary, indent=1, sort_keys=True).encode("utf-8") + b"\n")
    return receipt, run_summary


def _fsync_path_and_parent(path: str) -> None:
    """Durably commit a written file AND its parent directory entry (GIO05)."""
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    dfd = os.open(os.path.dirname(path) or ".", os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def _write_and_fsync(path: str, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    try:
        offset, view = 0, memoryview(data)
        while offset < len(data):
            written = os.write(fd, view[offset:])
            if written <= 0:
                raise RunnerError("summary-short-write", "a checked summary write made no progress")
            offset += written
        os.fsync(fd)
    finally:
        os.close(fd)
    _fsync_path_and_parent(path)


def _summarize(*, run_id, manifest_sha256, daemon_endpoint, tools, admission_result, runtime_observation,
               image_identity, observation, receipt, env_summary, envelope_dict, manifest, workspace,
               harness_observation, started_wall) -> dict:
    # VM-OBSERVATIONS: the summary reflects the receipt's ACTUAL environment and
    # boot object (linux-test => boot null; vm => the observed boot), never a
    # hardcoded linux-test label.
    _env = receipt["environment"]
    _boot = receipt["base_vm_launch"]["boot"]
    _env_label = ("linux-test (UNATTESTED host-Docker engineering evidence)" if _env == "linux-test"
                  else "vm (UNATTESTED engineering VM boot; attestation=null, loader_mode=%s)"
                  % (_boot or {}).get("loader_mode"))
    summary = {
        "run_id": run_id,
        "manifest_sha256": manifest_sha256,
        "environment": _env_label,
        "started_unix_s": started_wall,
        "ended_unix_s": int(time.time()),
        "status": receipt["outputs"]["status"],
        "exit_code": receipt["outputs"]["exit_code"],
        "cancel": receipt["outputs"]["cancel"],
        "admission": {
            "os_image_hash": admission_result["os_image_hash"],
            "admission_sha256": admission_result["admission_sha256"],
            "boot": _boot,
            "note": ("linux-test: admission recorded over real bundle bytes; NO VM boot happened"
                     if _env == "linux-test"
                     else "vm: admission recorded over real bundle bytes; boot observed from the running VM"),
        },
        "daemon_endpoint_kind": daemon_endpoint.split(":", 1)[0],
        "docker_engine": tools.get("docker_engine"),
        "compose_version": tools.get("compose"),
        "runtime": {
            "requested": runtime_observation["runtime_name"],
            "version_observed": runtime_observation["runtime_version"],
            "executable_sha256": runtime_observation["executable_sha256"],
        },
        "images": {
            service: {
                "pin": identity["pin"],
                "image_id": identity["image_id"],
                "architecture": identity["architecture"],
                "os": identity["os"],
            }
            for service, identity in image_identity.items()
        },
        "harness_resolved": harness_observation["path"],
        # GIO03: the generated compose bytes carry PRIVATE runtime env values and
        # the broker endpoint; they are destroyed at cleanup and NEITHER they nor
        # a digest of them is published here (a hash of private content is a
        # forbidden private-input content hash). The committed-inputs evidence is
        # the frozen v4 commitment recorded in the receipt.
        "container_observations": {
            service: {
                "container_name": obs["container_name"],
                "state": obs["state"],
                "exit_code": obs["exit_code"],
                "oom_killed": obs["oom_killed"],
                "runtime": obs["runtime"],
            }
            for service, obs in observation["services"].items()
        },
        "artifact_digests": {
            entry["name"]: {"bytes": entry["bytes"], "sha256": entry["sha256"]}
            for entry in receipt["outputs"]["artifacts"]
        },
        "missing_artifacts": receipt["outputs"]["missing"],
        "stream_bytes": {
            "stdout": receipt["outputs"]["stdout"]["bytes"] if receipt["outputs"]["stdout"] else 0,
            "stderr": receipt["outputs"]["stderr"]["bytes"] if receipt["outputs"]["stderr"] else 0,
        },
        "input_env_names": sorted((env_summary or {}).get("env_names", [])),
        "committed": bool((env_summary or {}).get("commitment")),
        "emulation_note": (
            "runs of linux/arm64 images on this x86_64 daemon execute under the pre-existing "
            "qemu-aarch64 binfmt (EMULATED, not native, not KVM)"
        )
        if manifest["image_platform"].get("architecture") == "arm64"
        else None,
        "workspace_cap_mode": workspace.cap_mode,
        "receipt_note": (
            "linux-test receipt: UNATTESTED; boot=null; attestation=null; uncommitted inputs are "
            "not attested fixed" if _env == "linux-test" else
            "vm receipt: UNATTESTED engineering VM boot; boot observed (loader_mode=%s); "
            "attestation=null; uncommitted inputs are not attested fixed"
            % (_boot or {}).get("loader_mode")
        ),
    }
    # Canary discipline: no runtime-input VALUE may appear in the summary.
    # Values shorter than 8 bytes are skipped: a tiny value (e.g. "6")
    # occurs in counts/timestamps by coincidence, and scanning it proves
    # nothing -- real sensitive values are longer.
    if envelope_dict is not None:
        blob = json.dumps(summary)
        for value in (envelope_dict.get("env") or {}).values():
            if isinstance(value, str) and len(value) >= 8 and value in blob:
                raise RunnerError("summary-leak", "a runtime input value leaked into the run summary")
    return summary


def image_platform_is_arm64(manifest) -> bool:
    return manifest["image_platform"].get("architecture") == "arm64"


def _artifact_segment(manifest, artifact_name: str) -> str:
    for declared in manifest["outputs"]["artifacts"]:
        if declared["name"] == artifact_name:
            prefix = "/workspace/artifacts/"
            return declared["path"][len(prefix):]
    raise RunnerError("export-unknown-artifact", "the receipt records an artifact the manifest does not declare")


def _daemon_info_bootstrap(proc_env: dict) -> dict:
    out = subprocess.run(
        ["docker", "info", "--format", "{{json .}}"],
        env=proc_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
    )
    if out.returncode != 0:
        raise RunnerError("daemon-unreachable", "docker info failed under the explicit daemon endpoint")
    try:
        return json.loads(out.stdout.decode("utf-8"))
    except ValueError:
        raise RunnerError("daemon-info-unparseable", "docker info did not return JSON") from None


def admit_base_bundle(manifest, base_bundle_dir: str, admission_path: str) -> dict:
    """External admission over the REAL delivered bundle bytes.

    Consumes the bundle's OWN serialized checksum manifest (sha256sum.txt)
    as the exact os_image_hash preimage plus the four component files and
    the external admission document; runs the library's ``admit_image``
    (fail closed on any identity not admitted and on any tuple/geometry
    mismatch) and returns the recorded admission facts."""
    checksum_path = os.path.join(base_bundle_dir, "sha256sum.txt")
    paths = {
        "Image": os.path.join(base_bundle_dir, "Image"),
        "initramfs.cpio.gz": os.path.join(base_bundle_dir, "initramfs.cpio.gz"),
        "metadata.json": os.path.join(base_bundle_dir, "metadata.json"),
        "rootfs.squashfs.verity": os.path.join(base_bundle_dir, "rootfs.squashfs.verity"),
    }
    missing = [name for name, path in paths.items() if not os.path.isfile(path)]
    if missing or not os.path.isfile(checksum_path):
        raise RunnerError("bundle-incomplete", "the base bundle is missing declared components (names withheld)")
    with open(checksum_path, "rb") as handle:
        checksum_manifest_bytes = handle.read()
    # Bundle-sanity: the serialized manifest must name exactly these four
    # components with the hashes of the bytes present (independent of
    # admission; a foreign checksum file fails loudly here).
    for line in checksum_manifest_bytes.decode("ascii").splitlines():
        expected_hash, name = line.split("  ", 1)
        if name not in paths:
            raise RunnerError("bundle-layout-foreign", "the checksum manifest names a component outside the bundle layout")
        if _sha256_file(paths[name]) != expected_hash:
            raise RunnerError("bundle-component-hash-mismatch", "a bundle component does not match the serialized checksum manifest")
    with open(paths["metadata.json"], "rb") as handle:
        metadata_bytes = handle.read()
    with open(admission_path, "rb") as handle:
        admission_bytes = handle.read()
    decision = admit_image(manifest["base_vm"], checksum_manifest_bytes, metadata_bytes, admission_bytes)
    return {
        "decision": decision["decision"],
        "os_image_hash": decision["os_image_hash"],
        "admission_sha256": decision["admission_sha256"],
        "admission_version": decision["admission_version"],
    }


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 22), b""):
            digest.update(chunk)
    return digest.hexdigest()
