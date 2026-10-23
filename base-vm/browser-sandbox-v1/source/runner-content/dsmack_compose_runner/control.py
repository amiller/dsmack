"""Control-process isolation: the ONLY way the runner talks to Docker.

Rules implemented here (contract astra C05/E04 and lowering.py):
  - the daemon endpoint is EXPLICIT and REQUIRED -- no default, no
    discovery, no Docker contexts, no ambient host environment;
  - the compose control process environment is EXACTLY the lowered
    allowlist (``lowered["control_env"]``) with the placeholders replaced
    by isolated EMPTY per-run directories -- nothing else, ever;
  - the pinned compose tool version is verified live before any use;
  - child processes are run with a bounded output capture so daemon
    diagnostics that may embed private rendered values stay private.
"""

from __future__ import annotations

import json
import os
import re
import subprocess

from .errors import RunnerError

# Placeholders emitted by lower()/render plumbing and replaced HERE (and
# only here), from runner-private per-run paths.
_PLACEHOLDERS = (
    "{isolated_project_dir}",
    "{isolated_docker_config_dir}",
    "{generated_compose_file}",
)

_ENDPOINT_RE = re.compile(r"^(unix|tcp)://\S+$")


class ControlContext:
    """The isolated control environment for one run."""

    def __init__(self, daemon_endpoint: str, control_dir: str, compose_pin: str):
        if not isinstance(daemon_endpoint, str) or not _ENDPOINT_RE.match(daemon_endpoint):
            raise RunnerError(
                "daemon-endpoint-invalid",
                "daemon_endpoint must be an explicit unix:// or tcp:// endpoint; the runner never "
                "discovers or defaults a Docker endpoint and never consults Docker contexts",
            )
        if not isinstance(compose_pin, str) or not re.match(r"^[0-9A-Za-z.+-]+$", compose_pin):
            raise RunnerError("compose-pin-invalid", "compose_tool.version must be a pinned release identity")
        self.daemon_endpoint = daemon_endpoint
        self.control_dir = control_dir  # runner-private per-run control dir (0700)
        self.compose_pin = compose_pin
        # Isolated EMPTY per-run dirs: no .env, no override files, no
        # contexts can exist for the control process (F05/C05).
        self.project_dir = os.path.join(control_dir, "project")
        self.docker_config_dir = os.path.join(control_dir, "docker-config")
        for path in (self.project_dir, self.docker_config_dir):
            os.makedirs(path, mode=0o700, exist_ok=True)
        os.chmod(control_dir, 0o700)
        self._env = None
        self.tool_versions = None  # measured after check_tools()

    def build_env(self) -> dict:
        """The control env: EXACTLY the lowered allowlist keys, values with
        the private per-run placeholders substituted."""
        if self._env is None:
            raise RunnerError(
                "control-env-not-lowered",
                "build_env is called by the runner with the lowered control_env; nothing else may "
                "shape the control process environment",
            )
        return dict(self._env)

    def install_lowered_env(self, lowered: dict) -> None:
        """Freeze the control env from the lowered config's allowlist."""
        allowlist = lowered.get("control_env")
        if not isinstance(allowlist, dict) or not allowlist:
            raise RunnerError("control-env-missing", "the lowered config carries no control_env allowlist")
        if "DOCKER_CONTEXT" in allowlist:
            raise RunnerError("control-env-context", "the control env must never carry DOCKER_CONTEXT")
        unknown = set(allowlist) - {"COMPOSE_PROJECT_DIRECTORY", "DOCKER_CONFIG", "DOCKER_HOST", "PATH"}
        if unknown:
            raise RunnerError(
                "control-env-unknown-key",
                "the lowered control_env carries keys outside the frozen allowlist (names withheld)",
            )
        if allowlist.get("DOCKER_HOST") != self.daemon_endpoint:
            raise RunnerError(
                "control-env-endpoint-mismatch",
                "the lowered DOCKER_HOST does not equal the explicitly selected daemon endpoint",
            )
        env = {}
        for key, value in allowlist.items():
            if not isinstance(value, str):
                raise RunnerError("control-env-value-type", "control_env values must be strings")
            for placeholder in _PLACEHOLDERS:
                value = value.replace(placeholder, {
                    "{isolated_project_dir}": self.project_dir,
                    "{isolated_docker_config_dir}": self.docker_config_dir,
                    "{generated_compose_file}": os.path.join(self.control_dir, "compose.json"),
                }.get(placeholder, placeholder))
            env[key] = value
        # The isolated dirs are EMPTY (created fresh above); assert no .env or
        # context config could have been sourced from them.
        for path in (self.project_dir, self.docker_config_dir):
            if os.listdir(path):
                raise RunnerError("control-dir-not-empty", "the isolated control directory is not empty")
        if "DOCKER_CONTEXT" in env:
            raise RunnerError("control-env-context", "the control env must never carry DOCKER_CONTEXT")
        self._env = env
        return env

    # ------------------------------------------------------------------
    # Process execution under the isolated env
    # ------------------------------------------------------------------

    def run(self, argv, *, stdin_bytes=None, timeout_s=None, stdout_sink=None):
        """Run a control command with the EXACT isolated env.

        stdout goes to stdout_sink (a writable binary file object) when
        given -- used for daemon/compose output that may embed private
        rendered values -- else captured in memory. Returns
        (returncode, captured_stdout_bytes_or_None, stderr_bytes).
        """
        if self._env is None:
            raise RunnerError("control-env-not-lowered", "install_lowered_env must run before any control command")
        env = self.build_env()
        try:
            proc = subprocess.Popen(
                list(argv),
                env=env,
                stdin=subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE if stdout_sink is None else stdout_sink,
                stderr=subprocess.PIPE,
            )
        except FileNotFoundError:
            raise RunnerError("tool-absent", "a pinned control tool is not installed: %s" % argv[0]) from None
        try:
            out, err = proc.communicate(input=stdin_bytes, timeout=timeout_s)
        except subprocess.TimeoutExpired:
            # F04: a control command that exceeds its bound must be killed and
            # reaped -- never left running past the deadline. Kill, drain, then
            # fail closed (the bound is the contract; a silent overrun is not).
            proc.kill()
            try:
                proc.communicate(timeout=30)
            except subprocess.TimeoutExpired:
                pass
            raise RunnerError(
                "control-command-timeout",
                "a control command exceeded its bounded deadline and was killed; failing closed",
            ) from None
        return proc.returncode, out, err

    def run_capped(self, argv, *, cap_bytes, timeout_s=None):
        """Run a control command capturing stdout/stderr with a HARD per-stream
        memory bound.

        Unlike ``run`` (which buffers the entire child output via
        ``communicate`` before any cap is consulted), this reads both pipes
        incrementally and retains at most ``cap_bytes`` per stream; any byte
        beyond the cap is drained-and-discarded (so the child never blocks on a
        full pipe) and flagged as an overflow.  Returns
        ``(returncode, stdout_bytes, stderr_bytes, stdout_overflow,
        stderr_overflow)`` where the retained bytes are bounded to exactly
        ``cap_bytes`` on overflow.  The cap is enforced WHILE reading (GIO06):
        a multi-gigabyte log can never be materialized in memory."""
        import selectors
        import time as _time

        if self._env is None:
            raise RunnerError("control-env-not-lowered", "install_lowered_env must run before any control command")
        if not (isinstance(cap_bytes, int) and not isinstance(cap_bytes, bool) and cap_bytes >= 0):
            raise RunnerError("capture-cap-invalid", "the capture cap must be a non-negative integer")
        env = self.build_env()
        try:
            proc = subprocess.Popen(
                list(argv), env=env, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        except FileNotFoundError:
            raise RunnerError("tool-absent", "a pinned control tool is not installed: %s" % argv[0]) from None
        buffers = {proc.stdout: bytearray(), proc.stderr: bytearray()}
        overflow = {proc.stdout: False, proc.stderr: False}
        deadline = None if timeout_s is None else _time.monotonic() + timeout_s
        sel = selectors.DefaultSelector()
        for pipe in (proc.stdout, proc.stderr):
            os.set_blocking(pipe.fileno(), False)
            sel.register(pipe, selectors.EVENT_READ)
        open_pipes = 2
        try:
            while open_pipes > 0:
                if deadline is not None:
                    remaining = deadline - _time.monotonic()
                    if remaining <= 0:
                        proc.kill()
                        raise RunnerError(
                            "control-command-timeout",
                            "a bounded-capture control command exceeded its deadline and was killed; failing closed",
                        )
                else:
                    remaining = None
                events = sel.select(timeout=remaining if remaining is None else min(remaining, 1.0))
                if not events:
                    continue
                for key, _mask in events:
                    pipe = key.fileobj
                    chunk = pipe.read(1 << 20)
                    if chunk is None:  # not ready under non-blocking
                        continue
                    if chunk == b"":
                        sel.unregister(pipe)
                        open_pipes -= 1
                        continue
                    buf = buffers[pipe]
                    if len(buf) < cap_bytes:
                        take = min(len(chunk), cap_bytes - len(buf))
                        buf.extend(chunk[:take])
                        if take < len(chunk):
                            overflow[pipe] = True
                    else:
                        overflow[pipe] = True
                    # bytes beyond the cap are discarded, not retained
        finally:
            sel.close()
            try:
                proc.wait(timeout=30 if timeout_s is None else min(30, max(1, int(timeout_s))))
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            for pipe in (proc.stdout, proc.stderr):
                try:
                    pipe.close()
                except OSError:
                    pass
        return (proc.returncode, bytes(buffers[proc.stdout]), bytes(buffers[proc.stderr]),
                overflow[proc.stdout], overflow[proc.stderr])

    # ------------------------------------------------------------------
    # Live tool identity
    # ------------------------------------------------------------------

    def check_tools(self, docker_version: str | None = None) -> dict:
        """Verify the live compose plugin version equals the pin.

        The manifest pins compose_tool.version; a different live version is
        a parser/tool drift, not a pass (contract D11 discipline). Returns
        the measured {compose, docker_engine} versions for the run record.
        """
        rc, out, err = self.run(["docker", "compose", "version", "--short"], timeout_s=60)
        if rc != 0:
            raise RunnerError(
                "compose-tool-unusable",
                "the docker compose plugin did not report a version; the pinned compose tool is required",
            )
        compose_version = out.decode("utf-8", "replace").strip().lstrip("v")
        if compose_version != self.compose_pin:
            raise RunnerError(
                "compose-tool-drift",
                "live compose version does not equal the manifest-pinned compose_tool.version; qualify "
                "the new parser under a new freeze (no silent tool drift)",
            )
        rc, out, err = self.run(["docker", "version", "--format", "{{.Server.Version}}"], timeout_s=60)
        engine = out.decode("utf-8", "replace").strip() if rc == 0 else None
        if docker_version is not None and engine is not None and engine != docker_version:
            # Informational pin (the manifest does not pin the engine); a
            # caller MAY require an exact engine. Recorded either way.
            raise RunnerError(
                "docker-engine-drift",
                "live docker engine version does not equal the required engine version",
            )
        self.tool_versions = {"compose": compose_version, "docker_engine": engine}
        return dict(self.tool_versions)

    def daemon_info(self) -> dict:
        """`docker info` as JSON under the isolated env (live runtime state)."""
        rc, out, err = self.run(["docker", "info", "--format", "{{json .}}"], timeout_s=60)
        if rc != 0:
            raise RunnerError("daemon-unreachable", "docker info failed under the explicit daemon endpoint")
        try:
            return json.loads(out.decode("utf-8"))
        except ValueError:
            raise RunnerError("daemon-info-unparseable", "docker info did not return JSON") from None
