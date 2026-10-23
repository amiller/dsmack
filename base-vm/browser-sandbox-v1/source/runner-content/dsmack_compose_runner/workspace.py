"""Private per-run workspace: creation, materialization, cap, cleanup.

The workspace is a PRIVATE per-run directory of the fixed nonroot workload
uid:gid (1000:1000); the runner asserts it can create exactly that
ownership. Inputs are materialized as SINGLE REGULAR FILES with
O_NOFOLLOW|O_EXCL before start and never rewritten. Cleanup is an lstat
walk that never follows symlinks and runs after EVERY outcome.

Cap honesty: as root the workspace is mounted as a size-capped tmpfs
(growth past the cap is ENOSPC to the workload, the contract's hard-cap
shape); unprivileged (this lane's Zed account) the cap is enforced by a
0.5 s poll that cancels the run with reason `limit-workspace` -- a
monitor, not a mount-quota ENOSPC boundary. The difference is recorded in
every run summary and must be disclosed wherever evidence is presented.
"""

from __future__ import annotations

import base64
import errno
import hashlib
import os
import shutil
import stat

from .errors import RunnerError

WORKLOAD_UID = 1000
WORKLOAD_GID = 1000


class Workspace:
    def __init__(self, root: str, run_id: str, manifest_sha256: str, cap_bytes: int):
        os.makedirs(root, mode=0o700, exist_ok=True)
        if os.geteuid() == 0:
            self.owner_uid, self.owner_gid = WORKLOAD_UID, WORKLOAD_GID
        else:
            # Unprivileged runner: the workspace is owned by the runner
            # account. The contract's workload uid must still be the
            # effective owner for the ownership claim to hold.
            if (os.getuid(), os.getgid()) != (WORKLOAD_UID, WORKLOAD_GID):
                raise RunnerError(
                    "workspace-ownership-unavailable",
                    "the runner process cannot create a workspace owned by the fixed workload "
                    "uid:gid; run the runner as root or as the workload uid",
                )
            self.owner_uid, self.owner_gid = os.getuid(), os.getgid()
        self.cap_bytes = cap_bytes
        self.cap_mode = None  # set by prepare(): "tmpfs-enospc" or "poll-cancel"
        self.path = os.path.join(root, "%s-%s" % (run_id, manifest_sha256[:12]))
        if os.path.lexists(self.path):
            raise RunnerError("workspace-collision", "the per-run workspace path already exists; run_id must be fresh")
        os.makedirs(self.path, mode=0o700)
        os.chmod(self.path, 0o700)
        self.inputs = os.path.join(self.path, "inputs")
        self.state = os.path.join(self.path, "state")
        self.artifacts = os.path.join(self.path, "artifacts")
        self.control = os.path.join(self.path, "control")  # runner-private; never mounted
        for d in (self.inputs, self.state, self.artifacts, self.control):
            os.mkdir(d, 0o700)
            os.chmod(d, 0o700)
        self._mounted_tmpfs = False

    # ------------------------------------------------------------------
    # Cap enforcement
    # ------------------------------------------------------------------

    def prepare_cap(self, subpaths) -> str:
        """Enforce the workspace cap. Root: size-capped tmpfs per writable
        subpath (ENOSPC by construction). Unprivileged: poll+cancel."""
        total = self.cap_bytes
        if os.geteuid() == 0:
            for sub in subpaths:
                target = getattr(self, sub)
                rc = os.system("mount -t tmpfs -o size=%d,mode=0700,uid=%d,gid=%d tmpfs %s"
                               % (total, WORKLOAD_UID, WORKLOAD_GID, json_escape(target)))
                if rc != 0:
                    self.cleanup()
                    raise RunnerError("workspace-cap-mount-failed", "the size-capped workspace mount failed")
                self._mounted_tmpfs = True
            self.cap_mode = "tmpfs-enospc"
        else:
            self.cap_mode = "poll-cancel"
        return self.cap_mode

    def usage_bytes(self) -> int:
        total = 0
        for root, _dirs, files in os.walk(self.path):
            for name in files:
                try:
                    st = os.lstat(os.path.join(root, name))
                    total += st.st_size
                except OSError:
                    continue
        return total

    # ------------------------------------------------------------------
    # Input materialization (D04)
    # ------------------------------------------------------------------

    def materialize_segment(self, subdir: str, segment: str, data: bytes | None, *, empty_ok: bool = True) -> dict:
        """Materialize ONE single regular file at <subdir>/<segment>.

        data None means an explicitly omitted optional input: an EMPTY
        regular file. Writes are O_NOFOLLOW|O_EXCL (never rewritten;
        collisions are fatal). Returns the delivered-bytes receipt facts.
        """
        if os.sep in segment or "/" in segment or segment in ("", ".", ".."):
            raise RunnerError("segment-invalid", "a delivery segment must be a single safe path segment")
        target = os.path.join(getattr(self, subdir), segment)
        payload = b"" if data is None else data
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(target, flags, 0o644)
        except FileExistsError:
            raise RunnerError("segment-collision", "a delivery destination already exists; inputs are never rewritten") from None
        except OSError as exc:
            if exc.errno == errno.ENOSPC:
                raise
            raise RunnerError("segment-write-failed", "materializing an input destination failed") from None
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        # D04: verify delivered bytes per destination (read back).
        with open(target, "rb") as handle:
            delivered = handle.read()
        if delivered != payload:
            raise RunnerError("segment-verify-failed", "delivered input bytes do not verify after write")
        return {"segment": segment, "bytes": len(delivered), "sha256": hashlib.sha256(delivered).hexdigest()}

    def materialize_delivery(self, plan: dict) -> dict:
        """Materialize every workload-audience destination from the
        validated delivery plan (files + user_config). Broker-audience
        entries are REFUSED here (they go only to a broker store; with no
        broker the run already failed closed at lowering)."""
        if plan.get("broker_env") or plan.get("broker_files"):
            raise RunnerError(
                "broker-input-without-broker",
                "broker-audience inputs cannot be delivered by this runner without a credential "
                "broker; they are never materialized under the workload workspace",
            )
        delivered = {"files": [], "user_config": None}
        for entry in plan.get("workload_files", []):
            data = None
            if not entry.get("materialize_empty"):
                data = base64.b64decode(entry["content_base64"])
            delivered["files"].append(self.materialize_segment("inputs", entry["segment"], data, empty_ok=True))
        uc = plan.get("user_config")
        if uc is not None:
            data = None
            if not uc.get("materialize_empty"):
                data = base64.b64decode(uc["content_base64"])
            delivered["user_config"] = self.materialize_segment("inputs", uc["segment"], data, empty_ok=True)
        return delivered

    # ------------------------------------------------------------------
    # Cleanup (lstat walk; never follows symlinks)
    # ------------------------------------------------------------------

    def cleanup(self) -> dict:
        """Destroy the workspace WITHOUT following symlinks. Runs after
        every outcome; errors are recorded, never raised past the caller's
        bookkeeping."""
        removed = {"files": 0, "symlinks": 0, "dirs": 0, "errors": []}
        if not os.path.lexists(self.path):
            return removed
        if self._mounted_tmpfs:
            for sub in ("inputs", "state", "artifacts", "control"):
                os.system("umount %s 2>/dev/null" % json_escape(os.path.join(self.path, sub)))
        # Bottom-up lstat walk: directories are emptied then rmdir'd; links
        # and files are unlinked in place (never descended into).
        for root, dirs, files, in os.walk(self.path, topdown=False, followlinks=False):
            for name in files + dirs:
                target = os.path.join(root, name)
                try:
                    st = os.lstat(target)
                    if stat.S_ISLNK(st.st_mode):
                        os.unlink(target)
                        removed["symlinks"] += 1
                    elif stat.S_ISDIR(st.st_mode):
                        os.rmdir(target)
                        removed["dirs"] += 1
                    else:
                        os.unlink(target)
                        removed["files"] += 1
                except OSError as exc:
                    removed["errors"].append("%s" % exc.errno)
        try:
            os.rmdir(self.path)
            removed["dirs"] += 1
        except OSError as exc:
            removed["errors"].append("%s" % exc.errno)
        return removed


def json_escape(path: str) -> str:
    return "'" + path.replace("'", "'\\''") + "'"


def write_private_file(directory: str, name: str, data: bytes) -> str:
    """Write a runner-private file (mode 0600) -- the rendered compose
    config and other material that must never be public."""
    path = os.path.join(directory, name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    return path
