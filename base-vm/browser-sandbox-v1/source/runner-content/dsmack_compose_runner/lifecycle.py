"""The frozen compose lifecycle: start, wait, stop, inspect, collect, down.

Implements exactly the lifecycle the contract freezes (lowering.py
_lifecycle / compose-runner-interface.md):

  `compose up --detach --quiet-pull` (stdin pipe: `compose run -i -T`)
  -> bounded wait on the COMPLETION service only (poll
     `docker compose ps --all --format json` -- `--all` is REQUIRED: the
     pinned v2.35.1 ps defaults to running-only and a STOPPED container
     would vanish; a never-created container fails closed)
  -> `compose stop` (writers stopped, containers preserved)
  -> `docker inspect` EVERY service container BEFORE removal
  -> output collection (demuxed completion-service streams, O_NOFOLLOW
     artifacts)
  -> `compose down` last; workspace cleanup by the caller after every
     outcome.

Timeout / external cancel / workspace-cap / output-cap cancel the run
(status cancelled, exit_code null, cancel {reason, at_unix_s}); every
service still gets its ACTUAL observed termination. A start failure or a
`dead` container fails closed with NO receipt (nothing honest to record).

Stream capture demuxes the completion service's output exactly:
`docker logs` relays stdout frames on its own stdout and stderr frames on
its own stderr (docker's stdcopy), so separate capture is the exact split.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat as stat_module
import subprocess
import time

from .errors import RunnerError
from dsmack_compose_contract.lowering import AGENT_SOCKET_DIR, GUEST_RESOLV_CONF

POLL_INTERVAL_S = 0.5
STOP_GRACE_S = 10

# The frozen compose_argv prefix emitted by lowering._compose_argv:
# docker compose --project-name <pn> --project-directory {dir} -f {file}
_ARGV_PREFIX_LEN = 8

CANCEL_TIMEOUT = "timeout"
CANCEL_EXTERNAL = "external"
CANCEL_LIMIT_OUTPUT = "limit-output"
CANCEL_LIMIT_WORKSPACE = "limit-workspace"


class CancelEvent:
    def __init__(self):
        self.reason = None

    def cancel(self, reason: str) -> None:
        if self.reason is None:
            self.reason = reason

    @property
    def cancelled(self) -> bool:
        return self.reason is not None


def _compose_argv(command: list, control, project_name: str) -> list:
    return ["docker", "compose", "--project-name", project_name,
            "--project-directory", control.project_dir,
            "-f", os.path.join(control.control_dir, "compose.json")] + command


def _lowered_command(control, lowered) -> list:
    """The lowered compose_argv's command tail after the frozen 8-element
    prefix, with the project/file placeholders re-bound to THIS control
    context. The prefix shape is asserted (a drifted lowering fails
    closed)."""
    argv = lowered["compose_argv"]
    prefix, tail = argv[:_ARGV_PREFIX_LEN], argv[_ARGV_PREFIX_LEN:]
    if (
        prefix[0:2] != ["docker", "compose"]
        or prefix[2] != "--project-name"
        or prefix[4:6] != ["--project-directory", "{isolated_project_dir}"]
        or prefix[6:8] != ["-f", "{generated_compose_file}"]
    ):
        raise RunnerError("compose-argv-drift", "the lowered compose_argv prefix is not the frozen form")
    rebuilt = _compose_argv(tail, control, prefix[3])
    if rebuilt[3] != prefix[3]:
        raise RunnerError("compose-argv-drift", "the lowered project name does not match the run identity")
    return rebuilt


def parser_validate(control, lowered, project_name: str) -> dict:
    """Check the generated compose file with the ACTUAL pinned parser, then
    re-assert the security-critical invariants on the parser's NORMALIZED
    output (never on the renderer's own text alone). The normalized config
    carries runtime env VALUES: checked in memory, discarded -- never
    logged, never written outside the private control dir."""
    rc, out, _err = control.run(
        _compose_argv(["config", "--format", "json"], control, project_name), timeout_s=120
    )
    if rc != 0:
        raise RunnerError(
            "compose-config-rejected",
            "the pinned docker compose parser rejected the generated configuration (diagnostic "
            "withheld; captured privately)",
        )
    try:
        normalized = json.loads(out.decode("utf-8"))
    except ValueError:
        raise RunnerError("compose-config-unparseable", "the parser's normalized output was not JSON") from None

    expected_services = list(lowered["mounts_by_service"].keys())
    services = normalized.get("services") or {}
    if sorted(services.keys()) != sorted(expected_services):
        raise RunnerError("config-services-drift", "the normalized config does not carry exactly the declared services")
    ws = lowered["workspace_host_dir"]
    for name, service in services.items():
        if service.get("runtime") != lowered["requires_runtime"]:
            raise RunnerError("config-runtime-drift", "the normalized config does not pin the requested runtime")
        if service.get("user") != "%d:%d" % (lowered["workload_uid_gid"][0], lowered["workload_uid_gid"][1]):
            raise RunnerError("config-user-drift", "the normalized config does not pin the fixed nonroot workload user")
        if service.get("read_only") is not True:
            raise RunnerError("config-readonly-drift", "the normalized config is not read-only-root")
        if service.get("privileged"):
            raise RunnerError("config-privileged", "the normalized config grants privileged mode")
        if lowered.get("security_profiles", {}).get(name):
            from dsmack_compose_contract.security import validate_normalized
            try:
                validate_normalized(service)
                expected_mounts = sorted((m["source"], m["target"], m["mode"] == "ro")
                                         for m in lowered["mounts_by_service"][name]["mounts"])
                actual_mounts = sorted((m.get("source"), m.get("target"), m.get("read_only", False))
                                       for m in service.get("volumes", []))
                if actual_mounts != expected_mounts:
                    raise ValueError("browser normalized mount identity drift")
            except (ValueError, OSError) as exc:
                raise RunnerError("config-browser-preset-drift", str(exc)) from None
        for volume in service.get("volumes") or []:
            source = volume.get("source") or ""
            if volume.get("type") != "bind" or (volume.get("bind") or {}).get("propagation") != "rprivate":
                raise RunnerError("config-mount-drift", "mounts must be rprivate binds")
            agent_sock = (source, volume.get("target"), volume.get("read_only")) == (
                "%s/%s.sock" % (AGENT_SOCKET_DIR, name), "/var/run/dstack.sock", True)
            resolv = (source, volume.get("target"), volume.get("read_only")) == (GUEST_RESOLV_CONF, "/etc/resolv.conf", True)
            runtime = any(m["slot"] == "runtime" and
                          (source, volume.get("target"), volume.get("read_only", False)) ==
                          (m["source"], m["target"], m["mode"] == "ro")
                          for m in lowered["mounts_by_service"][name]["mounts"])
            if not source.startswith(ws + os.sep) and not agent_sock and not resolv and not runtime:
                raise RunnerError("config-mount-outside-workspace", "a mount source leaves the private per-run workspace")
        if (service.get("network_mode") or None) != lowered["network_mode"]:
            raise RunnerError("config-network-drift", "the normalized network mode does not equal the lowered mode")
    return {"services": sorted(services.keys())}


def execute(control, lowered, manifest, workspace, compose_text: bytes, *, cancel: CancelEvent, stdin_bytes: bytes | None) -> dict:
    """Run the frozen lifecycle under an ENCOMPASSING teardown guarantee.

    F04: once this function touches compose, `compose down` MUST run on every
    exit path -- normal return, fail-closed RunnerError, or any unexpected
    exception raised between start and collection (e.g. an uninspectable or
    unreadable-stream container). The inner body no longer calls down itself;
    this single ``finally`` is the one teardown owner (down is idempotent and
    best-effort, so a never-started project is a harmless no-op)."""
    project_name = lowered["project_name"]
    try:
        return _execute_inner(
            control, lowered, manifest, workspace, compose_text, cancel=cancel, stdin_bytes=stdin_bytes
        )
    finally:
        _best_effort_down(control, project_name)


def _execute_inner(control, lowered, manifest, workspace, compose_text: bytes, *, cancel: CancelEvent, stdin_bytes: bytes | None) -> dict:
    """The frozen lifecycle body; teardown is guaranteed by execute()."""
    project_name = lowered["project_name"]
    completion_service = lowered["completion_service"]
    pipe_mode = manifest["runtime_inputs"]["stdin"]["mode"] == "pipe"
    timeout_s = manifest["limits"]["timeout_s"]
    output_cap = manifest["limits"].get("output_max_bytes")
    started = int(time.time())
    deadline = started + timeout_s

    observation = {
        "started_unix_s": started,
        "ended_unix_s": None,
        "status": None,
        "exit_code": None,
        "cancel": None,
        "services": {},
        "streams": {},
        "missing": [],
        "artifacts": [],
        "compose_project": project_name,
        # GIO03: the rendered compose bytes carry PRIVATE runtime env VALUES and
        # the broker capability endpoint. A public digest of them is a
        # private-input content hash (a cache id by any other name) and is NOT
        # computed or published. The committed-inputs evidence is the frozen v4
        # commitment (receipt.runtime_inputs_commitment), not a hash of the
        # rendered private configuration.
    }

    def finish(status, exit_code=None, cancel_reason=None):
        observation["ended_unix_s"] = int(time.time())
        observation["status"] = status
        observation["exit_code"] = exit_code
        if cancel_reason is not None:
            observation["cancel"] = {"reason": cancel_reason, "at_unix_s": observation["ended_unix_s"]}
        return observation

    def fail_closed(code: str, message: str):
        # Teardown is owned by execute()'s encompassing finally (F04).
        raise RunnerError(code, message)

    # -- write the generated compose file privately, parser-validate ------
    from .workspace import write_private_file

    compose_path = os.path.join(control.control_dir, "compose.json")
    if os.path.lexists(compose_path):
        raise RunnerError("compose-file-collision", "the generated compose path already exists")
    write_private_file(control.control_dir, "compose.json", compose_text)
    parser_validate(control, lowered, project_name)

    # -- start -------------------------------------------------------------
    completion_container = None
    start_cmd = _lowered_command(control, lowered)
    if pipe_mode:
        proc = subprocess.Popen(
            start_cmd,
            env=control.build_env(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            proc.stdin.write(stdin_bytes or b"")
            proc.stdin.close()
        except OSError:
            pass
        while proc.poll() is None:
            if time.time() > deadline:
                cancel.cancel(CANCEL_TIMEOUT)
                break
            if cancel.cancelled:
                break
            if _workspace_over_cap(workspace):
                cancel.cancel(CANCEL_LIMIT_WORKSPACE)
                break
            time.sleep(POLL_INTERVAL_S)
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=30)
        proc.communicate()
        completion_container = "%s-main" % project_name
        if not cancel.cancelled:
            if proc.returncode < 0:
                fail_closed("compose-run-signaled", "the stdin-pipe compose process died from a signal; failing closed")
            observation["pipe_exit_code"] = proc.returncode
    else:
        rc, _out, _err = control.run(start_cmd, timeout_s=120)
        if rc != 0:
            fail_closed(
                "start-failed",
                "the detached start failed closed; no execution evidence exists to record "
                "(diagnostic withheld; captured privately)",
            )
        # Discover the per-service container names from `ps --all` (a
        # container never created within the bound fails closed).
        bound = time.time() + min(60, timeout_s)
        while True:
            names, completion_container = _ps_containers(control, lowered, project_name)
            if completion_container is not None:
                break
            if time.time() > bound:
                fail_closed(
                    "container-never-created",
                    "the completion service's container was never created within the start bound; "
                    "failing closed",
                )
            time.sleep(POLL_INTERVAL_S)

    # -- bounded wait on the completion service only -----------------------
    if not pipe_mode:
        while True:
            if cancel.cancelled:
                break
            if time.time() > deadline:
                cancel.cancel(CANCEL_TIMEOUT)
                break
            if _workspace_over_cap(workspace):
                cancel.cancel(CANCEL_LIMIT_WORKSPACE)
                break
            state = _container_state(control, completion_container)
            if state == "exited":
                break
            if state == "dead":
                fail_closed("container-dead", "the completion container reached state 'dead'; failing closed")
            time.sleep(POLL_INTERVAL_S)

    # -- stop writers (up path only), inspect EVERY service BEFORE down ----
    if not pipe_mode:
        control.run(
            _compose_argv(["stop", "-t", str(STOP_GRACE_S)], control, observation["compose_project"]),
            timeout_s=180,
        )
    names, completion_container = _ps_containers(control, lowered, project_name)
    services_out = {}
    for service in lowered["mounts_by_service"]:
        name = names.get(service) or (completion_container if service == completion_service else None)
        if name is None:
            fail_closed(
                "container-missing",
                "a declared service has no container to inspect; every service's ACTUAL termination "
                "must be observed (failing closed)",
            )
        services_out[service] = _inspect_container(control, name)
    observation["services"] = services_out
    completion_exit = services_out[completion_service]["exit_code"]
    if pipe_mode and not cancel.cancelled:
        completion_exit = observation["pipe_exit_code"]

    # -- collect (after stop; no writer can mutate outputs) ----------------
    observation["stream_truncated"] = {"stdout": False, "stderr": False}
    try:
        observation["streams"] = _capture_streams(control, services_out[completion_service], output_cap, manifest["outputs"]["capture"])
    except _StreamOverflow as overflow:
        # GIO06: an output-limit cancellation is a FROZEN-v4-COMPATIBLE
        # cancellation, NOT a lost receipt. The bounded bytes captured up to
        # the cap are RETAINED (the receipt records their exact digest/length,
        # which the validator requires for a declared-capture stream -- a null
        # declared stream is rejected), the run is cancelled with reason
        # limit-output, and the per-stream truncation is recorded so the
        # export index marks the stream truncated instead of presenting a
        # bounded digest as a complete one.
        cancel.cancel(CANCEL_LIMIT_OUTPUT)
        observation["streams"] = {"stdout": overflow.stdout, "stderr": overflow.stderr}
        observation["stream_truncated"] = {
            "stdout": overflow.stdout_overflow,
            "stderr": overflow.stderr_overflow,
        }

    _collect_artifacts(manifest, workspace, observation)

    if cancel.cancelled:
        return finish("cancelled", None, cancel.reason)
    if observation["missing"]:
        # Collection failure is a failure and preserves the workload's exit
        # code (interface: failed preserves the ACTUAL exit, even 0).
        return finish("failed", completion_exit)
    return finish("completed" if completion_exit == 0 else "failed", completion_exit)


# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------


def _workspace_over_cap(workspace) -> bool:
    """Unprivileged cap enforcement: a usage poll (see workspace.py for the
    honest tmpfs-vs-poll distinction)."""
    if workspace is None or workspace.cap_mode != "poll-cancel":
        return False
    return workspace.usage_bytes() > workspace.cap_bytes


def _best_effort_down(control, project_name: str) -> None:
    try:
        control.run(
            _compose_argv(["down", "-t", str(STOP_GRACE_S)], control, project_name), timeout_s=300
        )
    except Exception:  # noqa: BLE001 - teardown is best effort after failures
        pass


def _compose_ps(control, project_name) -> list:
    rc, out, _err = control.run(
        _compose_argv(["ps", "--all", "--format", "json"], control, project_name), timeout_s=60
    )
    if rc != 0:
        return []
    try:
        data = json.loads(out.decode("utf-8") or "[]")
    except ValueError:
        return []
    return data if isinstance(data, list) else [data]


def _ps_containers(control, lowered, project_name):
    """Map service -> container Name from `compose ps --all` (stopped
    containers included). Returns (names_by_service, completion_container)."""
    names = {}
    completion = None
    for entry in _compose_ps(control, project_name):
        service = entry.get("Service")
        name = entry.get("Name")
        if isinstance(service, str) and isinstance(name, str):
            names.setdefault(service, name)
            if service == lowered["completion_service"]:
                completion = name
    return names, completion


def _container_state(control, container_name: str):
    rc, out, _err = control.run(["docker", "container", "inspect", container_name], timeout_s=30)
    if rc != 0:
        return None
    try:
        info = json.loads(out.decode("utf-8"))[0]
    except (ValueError, IndexError):
        return None
    return (info.get("State") or {}).get("Status")


def _inspect_container(control, container_name: str) -> dict:
    rc, out, _err = control.run(["docker", "container", "inspect", container_name], timeout_s=60)
    if rc != 0:
        raise RunnerError(
            "container-uninspectable",
            "a service container could not be inspected before removal; every service's ACTUAL "
            "termination must be observed (failing closed)",
        )
    try:
        info = json.loads(out.decode("utf-8"))[0]
    except (ValueError, IndexError):
        raise RunnerError("container-inspect-unparseable", "docker container inspect did not return JSON") from None
    state = info.get("State") or {}
    return {
        "container_name": container_name,
        "state": state.get("Status"),
        "exit_code": state.get("ExitCode"),
        "oom_killed": bool(state.get("OOMKilled")),
        "image_id": info.get("Image"),
        "runtime": (info.get("HostConfig") or {}).get("Runtime"),
        "log_path": (info.get("LogPath") or None),
    }


class _StreamOverflow(Exception):
    """Raised when a declared-capture stream exceeds the output cap. Carries
    the BOUNDED bytes retained up to the cap and the per-stream overflow flags
    (GIO06: the cancellation retains its exact required bytes)."""

    def __init__(self, stdout: bytes, stderr: bytes, stdout_overflow: bool, stderr_overflow: bool):
        super().__init__("output cap exceeded")
        self.stdout = stdout
        self.stderr = stderr
        self.stdout_overflow = stdout_overflow
        self.stderr_overflow = stderr_overflow


def _capture_streams(control, service_obs: dict, output_cap, capture) -> dict:
    """Capture the COMPLETION service's streams demuxed.

    `docker logs` relays the container's multiplexed stream with stdout
    frames on the client's stdout and stderr frames on the client's stderr
    (docker's stdcopy demux), so separate capture of the control process's
    stdout/stderr IS the exact per-stream split. Capped at
    limits.output_max_bytes (overflow cancels with reason limit-output).
    The cap is enforced WHILE reading (GIO06) -- an over-cap log is never
    fully materialized in memory. Unavailable logs fail closed -- the runner
    never records a stream digest it did not capture."""
    if not capture:
        return {}
    container = service_obs.get("container_name")
    if not container:
        raise RunnerError(
            "streams-unreadable",
            "the completion container's log stream is unavailable; declared capture cannot be "
            "recorded honestly (failing closed)",
        )
    if output_cap is None:
        rc, out, err = control.run(["docker", "logs", container], timeout_s=300)
        if rc != 0:
            raise RunnerError(
                "streams-unreadable",
                "docker logs failed for the completion container; declared capture cannot be recorded "
                "honestly (failing closed)",
            )
        return {s: data or b"" for s, data in (("stdout", out), ("stderr", err)) if s in capture}
    rc, out, err, out_over, err_over = control.run_capped(
        ["docker", "logs", container], cap_bytes=output_cap, timeout_s=300
    )
    if rc != 0:
        raise RunnerError(
            "streams-unreadable",
            "docker logs failed for the completion container; declared capture cannot be recorded "
            "honestly (failing closed)",
        )
    out_over = out_over and "stdout" in capture
    err_over = err_over and "stderr" in capture
    if out_over or err_over:
        raise _StreamOverflow(out if "stdout" in capture else b"", err if "stderr" in capture else b"", out_over, err_over)
    return {s: data for s, data in (("stdout", out), ("stderr", err)) if s in capture}


def _collect_artifacts(manifest, workspace, observation) -> None:
    """Collect declared artifacts from /workspace/artifacts/<segment> with
    O_NOFOLLOW semantics. A symlink/special file/directory at an artifact
    path is NOT collected -- recorded missing. Never collect from inputs or
    state (refused even if a manifest could express it)."""
    for declared in manifest["outputs"]["artifacts"]:
        name = declared["name"]
        path = declared["path"]
        prefix = "/workspace/artifacts/"
        if not path.startswith(prefix):
            observation["missing"].append(name)
            continue
        segment = path[len(prefix):]
        if not segment or "/" in segment or segment in (".", ".."):
            observation["missing"].append(name)
            continue
        target = os.path.join(workspace.artifacts, segment)
        try:
            st = os.lstat(target)
        except OSError:
            observation["missing"].append(name)
            continue
        if stat_module.S_ISLNK(st.st_mode) or not stat_module.S_ISREG(st.st_mode):
            observation["missing"].append(name)
            continue
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(target, flags)
        except OSError:
            observation["missing"].append(name)
            continue
        digest = hashlib.sha256()
        size = 0
        with os.fdopen(fd, "rb") as handle:
            while True:
                chunk = handle.read(1 << 20)
                if not chunk:
                    break
                digest.update(chunk)
                size += len(chunk)
        observation["artifacts"].append(
            {"name": name, "bytes": size, "sha256": digest.hexdigest()}
        )
