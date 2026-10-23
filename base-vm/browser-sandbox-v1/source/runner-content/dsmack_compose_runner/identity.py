"""Live identity resolution: images, runtimes, harness -- fail closed.

Nothing here trusts names: every identity is resolved against the live
daemon or real bytes and compared to the measured manifest pins.
  - image pins (repo@sha256:<child>) must exist in the daemon with the pin
    in RepoDigests and Architecture/Os equal to image_platform;
  - the requested registered runtime must exist live (runsc absent =>
    reject, never fallback), its closure component bytes must hash to the
    pin, and its live version must equal runner.runtime_version;
  - the harness path must resolve inside the image rootfs through
    symlink-free components to a regular file whose sha256 equals
    harness.sha256 (R05 harness_resolution_duty).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tarfile

from .errors import RunnerError

HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _inspect_image(control, image_ref: str) -> dict:
    rc, out, err = control.run(["docker", "image", "inspect", image_ref], timeout_s=120)
    if rc != 0:
        return None
    try:
        return json.loads(out.decode("utf-8"))[0]
    except (ValueError, KeyError, IndexError):
        raise RunnerError("image-inspect-unparseable", "docker image inspect did not return parseable JSON") from None


def ensure_image(control, image_ref: str, platform: dict) -> dict:
    """Resolve the EXACT pinned child image against the live daemon.

    A missing image is pulled BY DIGEST ONLY (bounded by the pin -- never a
    floating tag, never a speculative multi-arch pull). Any mismatch
    between the daemon image and the pinned child digest or platform is a
    fail-closed refusal.
    """
    info = _inspect_image(control, image_ref)
    if info is None:
        rc, out, err = control.run(["docker", "pull", "--quiet", image_ref], timeout_s=600)
        if rc != 0:
            raise RunnerError(
                "image-unresolvable",
                "the pinned image is absent from the daemon and an exact-digest pull failed "
                "(diagnostic withheld)",
            )
        info = _inspect_image(control, image_ref)
        if info is None:
            raise RunnerError("image-unresolvable", "the pinned image is absent from the daemon after pull")
    repo_digests = info.get("RepoDigests") or []
    if image_ref not in repo_digests:
        raise RunnerError(
            "image-mismatch",
            "the daemon image does not carry the pinned RepoDigest; refusing to execute an image "
            "other than the requested pinned child manifest",
        )
    arch = info.get("Architecture")
    os_name = info.get("Os")
    if arch != platform.get("architecture") or os_name != platform.get("os"):
        raise RunnerError(
            "image-platform-mismatch",
            "the daemon image platform does not equal the manifest image_platform (per-platform "
            "resolution is exact)",
        )
    variant = platform.get("variant")
    if variant is not None and info.get("Variant") != variant:
        raise RunnerError("image-platform-mismatch", "the daemon image variant does not equal the requested variant")
    return {
        "image_id": info.get("Id"),
        "repo_digests": list(repo_digests),
        "architecture": arch,
        "os": os_name,
    }


# S07: per-runtime REGISTRATION ARGUMENT POLICY. The daemon registration (and
# the manifest closure pin) must carry exactly the policy-required arguments:
# a runsc registered without an explicit platform/network selection -- or with
# a different one -- is NOT the reviewed runtime policy, even if the binary
# bytes match. runsc must run systrap + netstack; runsc-hostnet is a DISTINCT
# policy (systrap + host networking) and never satisfies a runsc request.
RUNTIME_ARG_POLICY = {
    "runc": (),
    "runsc": ("--platform=systrap", "--network=sandbox"),
    "runsc-hostnet": ("--platform=systrap", "--network=host"),
}


def _resolve_registered_path(control, reg_path: str) -> str:
    """Resolve the daemon-registered runtime path to an absolute path. docker
    registers the default runc shim with a bare command name; resolve it the
    way the daemon would (PATH lookup) and fail closed when that cannot be
    established."""
    if reg_path.startswith("/"):
        return reg_path
    rc, out, _err = control.run(["/bin/sh", "-c", "command -v -- %s" % reg_path], timeout_s=60)
    resolved = out.decode("utf-8", "replace").strip()
    if rc != 0 or not resolved.startswith("/"):
        raise RunnerError(
            "runtime-registration-unverifiable",
            "the daemon-registered runtime path cannot be resolved to an absolute executable; "
            "refusing to assert registration_verified",
        )
    return resolved


def verify_runtime_closure(control, manifest, runtime_available: tuple | None = None) -> dict:
    """D10 duties the runner performs against the LIVE host daemon.

    - the requested registered runtime must be registered with the daemon
      (docker info Runtimes); runsc/runsc-hostnet requested on a host
      without them FAILS CLOSED (no fallback, ever);
    - S07: the daemon's ACTUAL registration is verified, not merely the
      runtime NAME: the registered executable path must resolve, its BYTES
      must hash to the closure pin, and the registered runtimeArgs must
      equal the closure registration_args AND the per-runtime argument
      policy (systrap + explicit netstack/host for runsc classes). When the
      daemon does not expose the registration detail, this FAILS CLOSED
      (runtime-registration-unverifiable) instead of asserting
      registration_verified on name presence alone;
    - the runtime_closure component must exist at its pinned path with
      bytes hashing to its pinned sha256 (same-name wrong-binary is a
      rejection);
    - the component's live version output must equal runner.runtime_version.
    """
    runner = manifest["runner"]
    runtime_name = runner["runtime_name"]
    runtime_version = runner["runtime_version"]

    info = control.daemon_info()
    runtimes = info.get("Runtimes") or {}
    if not isinstance(runtimes, dict):
        raise RunnerError(
            "runtime-registration-unverifiable",
            "the daemon does not expose its runtime registrations; refusing to assert "
            "registration_verified",
        )
    registered = set(runtimes)
    # docker info exposes the effective runc as io.containerd.runc.v2 too;
    # both the plain name and the containerd v2 shim satisfy a runc request.
    reg_entry = None
    if runtime_name == "runc":
        for candidate_name in ("runc", "io.containerd.runc.v2"):
            if candidate_name in runtimes:
                reg_entry = runtimes[candidate_name]
                break
    else:
        reg_entry = runtimes.get(runtime_name)
    if reg_entry is None:
        raise RunnerError(
            "runtime-unavailable",
            "the manifest requests registered runtime %r which the live daemon does not register; "
            "the contract REQUIRES failing closed -- no silent fallback to another runtime" % runtime_name,
        )

    closure = runner.get("runtime_closure") or {}
    components = closure.get("components") if isinstance(closure, dict) else None
    expected_name = "runc" if runtime_name == "runc" else "runsc"
    component = None
    for entry in components or []:
        if isinstance(entry, dict) and entry.get("name") == expected_name:
            component = entry
            break
    if component is None:
        raise RunnerError(
            "runtime-closure-missing",
            "the manifest pins no runtime_closure component for the requested runtime",
        )
    path = component.get("path")
    pinned_sha = component.get("sha256", "")
    if not isinstance(path, str) or not path.startswith("/") or not HEX64.match(pinned_sha or ""):
        raise RunnerError("runtime-closure-pin-invalid", "the runtime_closure component pin is malformed")
    # S07: the closure registration_args must equal the per-runtime POLICY
    # table (not themselves): runc registers bare; runsc classes register an
    # explicit systrap platform and an explicit netstack/host network choice.
    policy_args = RUNTIME_ARG_POLICY.get(runtime_name)
    if policy_args is None:
        raise RunnerError("runtime-closure-args-invalid", "no registration-argument policy exists for this runtime")
    pinned_args = component.get("registration_args")
    if not isinstance(pinned_args, list) or tuple(pinned_args) != policy_args:
        raise RunnerError(
            "runtime-closure-args-invalid",
            "the runtime_closure registration args do not equal the reviewed per-runtime policy "
            "(explicit platform/network selection is required; it is never implied)",
        )

    def _sha256_file(p):
        try:
            with open(p, "rb") as handle:
                digest = hashlib.sha256()
                while True:
                    chunk = handle.read(1 << 20)
                    if not chunk:
                        break
                    digest.update(chunk)
            return digest.hexdigest()
        except OSError:
            return None

    observed_sha = _sha256_file(path)
    if observed_sha is None:
        raise RunnerError(
            "runtime-binary-absent",
            "the pinned runtime executable is absent at its closure path; refusing to run without "
            "the pinned bytes",
        )
    if observed_sha != pinned_sha:
        raise RunnerError(
            "runtime-binary-mismatch",
            "the runtime executable bytes at the closure path do not equal the pinned sha256 "
            "(same-name wrong-binary registration is rejected)",
        )

    # S07: verify the daemon's ACTUAL registration, not the name. The
    # registered executable must be establishable, its bytes must equal the
    # SAME pin (a registration pointing at different bytes/platform/network
    # than the verified closure path is a rejection), and the registered
    # arguments must equal the policy-checked closure arguments.
    if not isinstance(reg_entry, dict) or not reg_entry.get("path"):
        raise RunnerError(
            "runtime-registration-unverifiable",
            "the daemon registration exposes no executable path for the requested runtime; "
            "refusing to assert registration_verified on name presence alone",
        )
    registered_path = _resolve_registered_path(control, str(reg_entry["path"]))
    registered_sha = _sha256_file(registered_path)
    if registered_sha is None:
        raise RunnerError(
            "runtime-registration-unverifiable",
            "the daemon-registered runtime executable cannot be read; refusing to assert "
            "registration_verified",
        )
    if registered_sha != pinned_sha:
        raise RunnerError(
            "runtime-registration-mismatch",
            "the daemon-registered runtime executable bytes do not equal the pinned closure "
            "sha256 (the daemon would execute different bytes than the verified closure)",
        )
    registered_args = reg_entry.get("runtimeArgs") or []
    if not isinstance(registered_args, list) or tuple(registered_args) != policy_args:
        raise RunnerError(
            "runtime-registration-mismatch",
            "the daemon-registered runtimeArgs do not equal the reviewed per-runtime policy "
            "(platform/network registration must match the manifest closure exactly)",
        )

    rc, out, _err = control.run([path, "--version"], timeout_s=60)
    version_line = out.decode("utf-8", "replace").strip().splitlines()
    observed_version = None
    for line in version_line:
        if "version" in line:
            observed_version = line.split("version", 1)[1].strip()
            break
    if rc != 0 or observed_version != runtime_version:
        raise RunnerError(
            "runtime-version-mismatch",
            "the live runtime version does not equal the manifest-pinned runner.runtime_version "
            "(live availability is verified against this exact release)",
        )
    return {
        "runtime_name": runtime_name,
        "runtime_version": runtime_version,
        "executable_path": path,
        "executable_sha256": observed_sha,
        "registered_path": registered_path,
        "registered_sha256": registered_sha,
        "registered_args": list(registered_args),
        "registration_verified": True,
        "daemon_registered": sorted(registered),
    }


def resolve_harness(control, manifest, image_ref: str) -> dict:
    """Resolve manifest.harness.path inside the image rootfs (R05).

    The image is exported (docker create + docker export, container never
    started) and the path is walked through the tar: EVERY component must
    be image-contained and symlink-free (any symlink or hardlink component
    is a launch rejection), and the final entry must be a REGULAR file
    whose sha256 equals manifest.harness.sha256.
    """
    harness = manifest["harness"]
    target = harness.get("path")
    pinned_sha = harness.get("sha256", "")
    if not isinstance(target, str) or not target.startswith("/") or not HEX64.match(pinned_sha or ""):
        raise RunnerError("harness-pin-invalid", "the manifest harness pin is malformed")
    parts = [p for p in target.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise RunnerError("harness-path-noncanonical", "the harness path is not canonical")

    # A per-process probe name (valid docker charset, no collision between
    # concurrent runs) holds the never-started container whose rootfs is
    # exported for the resolution walk.
    probe = "dsmack-harness-probe-%d" % os.getpid()
    rc, _out, _err = control.run(
        ["docker", "create", "--name", probe, "--entrypoint", "/dev/null", image_ref],
        timeout_s=120,
    )
    if rc != 0:
        raise RunnerError("harness-probe-failed", "docker create for the harness probe failed (diagnostic withheld)")
    try:
        rc_export, tar_stream, _err2 = control.run(["docker", "export", probe], timeout_s=600)
        if rc_export != 0:
            raise RunnerError("harness-probe-failed", "docker export for the harness probe failed")
        import io

        with tarfile.open(fileobj=io.BytesIO(tar_stream), mode="r:") as tar:
            members = {}
            for member in tar:
                # docker export tar names carry no leading slash; normalize
                # to absolute form so the walk compares like with like.
                members["/" + member.name.rstrip("/").lstrip("/")] = member
            resolved = []
            current = ""
            for part in parts:
                current = (current + "/" + part) if current else "/" + part
                member = members.get(current)
                if member is None:
                    raise RunnerError(
                        "harness-path-unresolvable",
                        "the harness path does not resolve inside the image rootfs",
                    )
                if member.issym() or member.islnk():
                    raise RunnerError(
                        "harness-path-symlink",
                        "a harness path component is a link; any symlinked component is a launch "
                        "rejection",
                    )
                resolved.append(current)
            final = members[current]
            if not final.isreg():
                raise RunnerError("harness-not-regular", "the resolved harness is not a regular file")
            extracted = tar.extractfile(final)
            digest = hashlib.sha256()
            while True:
                chunk = extracted.read(1 << 20)
                if not chunk:
                    break
                digest.update(chunk)
            observed_sha = digest.hexdigest()
        if observed_sha != pinned_sha:
            raise RunnerError(
                "harness-mismatch",
                "the resolved harness bytes do not equal the pinned harness.sha256 (the executed "
                "harness is not the measured one)",
            )
        return {"path": target, "sha256": observed_sha, "components": resolved}
    finally:
        control.run(["docker", "rm", "--force", probe], timeout_s=120)
