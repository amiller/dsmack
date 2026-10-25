"""Manifest validation for dsmack.app-compose/4 (contract4).

Validates the workload manifest AND the embedded compose document against the
v4 restricted subset. Unsupported/forbidden fields fail explicitly; nothing
is silently dropped or silently reinterpreted. Unknown-KEY diagnostics are
VALUE-FREE (the offender text is withheld; the allowed set is named) so a
secret smuggled in an unexpected key cannot reach stderr (D06).

v4 changes vs v3 (contract3-review D findings):
  D01 - base_vm is a CONCRETE serialized checksum manifest identity: it adds
        os_image_hash (SHA256 of the exact sha256sum.txt bytes) and
        metadata_sha256 (the image metadata document binding cmdline);
        image_admission.py binds every pin to those bytes.
  D04 - slot mounts are keyed by TARGET segment; user_config target-segment
        collisions with slot targets are rejected; omitted opaque user_config
        has an explicit delivery entry (materialize-empty).
  D05 - every type is validated BEFORE indexing/membership (adapter profile,
        user_config target, network object, ...); explicit null optional keys
        (limits/env_policy/credentials) are rejected instead of silently
        treated as absent.
  D07 - credentials.required requires a bridge-gateway network mode (the
        sentinel transport is bridge-only; 'none' is rejected); broker FILE
        slots require the generic-broker-file/1 profile (claude-api-key/1 is
        env-only).
  D08 - harness gains `path`: the in-image harness location, which MUST equal
        the compose entrypoint[0]; the runner extracts and verifies the bytes
        against harness.sha256 from the pinned image (image-contained
        harness model).
  D09 - a BOUNDED multi-service subset: 1..MAX_SERVICES services, a required
        completion_service when multi-service, per-input service audiences,
        and explicit rejection of everything outside the subset.
  D10 - runner.runtime_closure pins the runtime executable/bundle bytes and
        their exact registration arguments, bound to the base-vm checksum
        manifest (the bytes live under the verity root).
"""

import re

from .canonical import load_json_bytes, sha256_hex
from .errors import ComposeSubsetError, ManifestError, MultiError

NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
SLOT_RE = NAME_RE
WORKSPACE_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
IMAGE_RE = re.compile(r"^[^@\s]+@sha256:[0-9a-f]{64}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SERVICE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
CONTAINER_PATH_RE = re.compile(r"^/[A-Za-z0-9._/-]{1,255}$")
URL_RE = re.compile(r"^https://[A-Za-z0-9._~:/?#\[\]@!&'()*+,;=%-]+$")
RUN_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
#: Version/release identity: semver AND dated-release forms (astra C04:
#: release-20260622.0 must be representable faithfully).
RELEASE_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z+._-]{0,62}$")
#: Kernel command line: printable bounded ASCII, no '$', no quotes/backslashes.
CMDLINE_RE = re.compile(r"^[A-Za-z0-9 .,=:/+_-]{1,512}$")

CONTRACT_WORKSPACE_ROOT = "/workspace"
INPUTS_ROOT = "/workspace/inputs"
STATE_ROOT = "/workspace/state"
ARTIFACTS_ROOT = "/workspace/artifacts"
SHARED_ROOT = "/workspace/shared"
# The one host bind: lowering renders it as the per-service guest agent socket.
DSTACK_SOCK_VOLUME = "/var/run/dstack.sock:/var/run/dstack.sock:ro"
DEFAULT_USER_CONFIG_TARGET = "/workspace/inputs/user-config.json"

#: Slot names the workspace ABI reserves for the harness itself.
RESERVED_SLOT_NAMES = {"artifacts", "inputs", "state", "control", "shared"}

#: Container/platform architecture compatibility: a manifest is
#: single-platform; base VM bytes are per-architecture and never shared
#: across amd64/arm64.
ARCH_COMPAT = {"amd64": "x86_64", "arm64": "aarch64"}
SUPPORTED_ARCHITECTURES = ("amd64", "arm64")

AUDIENCES = ("workload", "broker")

#: Registered runtime names (astra C04). runsc-hostnet is a DISTINCT
#: registered runtime whose network syscalls pass through the container
#: network namespace while gVisor mediates everything else; it is NOT
#: Docker network_mode host.
RUNTIME_RUNC = "runc"
RUNTIME_RUNSC = "runsc"
RUNTIME_RUNSC_HOSTNET = "runsc-hostnet"
REGISTERED_RUNTIMES = (RUNTIME_RUNC, RUNTIME_RUNSC, RUNTIME_RUNSC_HOSTNET)
#: The runtime-closure component that must be pinned for each registered
#: runtime (D10): runsc and runsc-hostnet are registrations of the SAME
#: runsc executable/bundle.
RUNTIME_COMPONENT = {RUNTIME_RUNC: "runc", RUNTIME_RUNSC: "runsc", RUNTIME_RUNSC_HOSTNET: "runsc"}

#: Bounded multi-service subset (D09).
MAX_SERVICES = 4
MIN_SERVICES = 1

#: Frozen credential-adapter profiles (astra C10 + D07). The signed app and
#: the contract know the vocabulary; interpretation stays in the adapter
#: layer. claude-api-key/1 is ENV-ONLY (api_key -> ANTHROPIC_API_KEY);
#: broker FILE slots require the separate generic-broker-file/1 profile,
#: which carries no provider route and no broker env names.
#:
#: claude-subscription/1 (PROPOSED DELTA, lane claude-subscription-import,
#: pending independent review) is ENV-ONLY like claude-api-key/1 but carries
#: the OAuth subscription credential object (claudeAiOauth) on broker env
#: CLAUDE_SUBSCRIPTION_OAUTH; the measured provider route is the same single
#: origin https://api.anthropic.com (both the pinned harness's OAuth
#: token/refresh endpoint /v1/oauth/token and inference /v1/* live there).
#: The upstream-side credential replacement is Authorization: Bearer + the
#: oauth beta header (never x-api-key) — profile semantics live in the
#: adapter/sentinel layer, exactly like the api-key profile.
ADAPTER_PROFILES = {
    "claude-api-key/1": {
        "accepted_fields": ("api_key",),
        "provider_route": "https://api.anthropic.com",
        "broker_env_names": ("ANTHROPIC_API_KEY",),
        "broker_files": False,
    },
    "claude-subscription/1": {
        "accepted_fields": ("claudeAiOauth",),
        "provider_route": "https://api.anthropic.com",
        "broker_env_names": ("CLAUDE_SUBSCRIPTION_OAUTH",),
        "broker_files": False,
    },
    "generic-broker-file/1": {
        "accepted_fields": (),
        "provider_route": None,
        "broker_env_names": (),
        "broker_files": True,
    },
}

#: Env names the runtime-input interface may not touch unless the measured
#: manifest explicitly permits them (env_policy.permit_reserved_envs).
RESERVED_ENV_NAMES = {
    "PATH",
    "HOME",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "PYTHONPATH",
    "PYTHONHOME",
    "DOCKER_HOST",
}
RESERVED_ENV_PREFIXES = ("DSMACK_",)

COMPOSE_ALLOWED_TOP_KEYS = {"services"}
COMPOSE_ALLOWED_SERVICE_KEYS = {
    "image",
    "entrypoint",
    "command",
    "environment",
    "working_dir",
    "security_profile",
    "read_only",
    "deploy",
    "volumes",
}

MANIFEST_REQUIRED_KEYS = {
    "manifest_version",
    "name",
    "runner",
    "base_vm",
    "harness",
    "image_platform",
    "docker_compose_file",
    "allowed_envs",
    "required_envs",
    "allowed_files",
    "runtime_inputs",
    "network",
    "outputs",
}
MANIFEST_OPTIONAL_KEYS = {"env_policy", "credentials", "limits"}

# ---- policy bounds (mirrored from CONTRACT.json policy_constants; keep in sync)
MAX_VCPUS = 64
MIN_MEMORY_MB = 64
MAX_MEMORY_MB = 65536
MAX_ALLOWED_ENVS = 64
MAX_FILE_SLOTS = 16
MAX_SLOT_BYTES = 1073741824  # 1 GiB
MIN_WORKSPACE_BYTES = 1048576  # 1 MiB
MAX_WORKSPACE_BYTES = 8589934592  # 8 GiB
DEFAULT_WORKSPACE_BYTES = 268435456  # 256 MiB
MAX_STREAM_INPUT_BYTES = 16777216  # 16 MiB
MAX_TIMEOUT_S = 86400
DEFAULT_TIMEOUT_S = 600
MAX_LISTEN_PORTS = 16
MAX_ARTIFACTS = 16
MAX_REGISTRATION_ARGS = 16


def _is_reserved_env(name):
    return isinstance(name, str) and (
        name in RESERVED_ENV_NAMES or name.startswith(RESERVED_ENV_PREFIXES)
    )


def _check_type(value, types, path, errors):
    if not isinstance(value, types):
        errors.append(ManifestError("%s must be %s, got %s" % (path, types, type(value).__name__)))
        return False
    return True


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _check_pattern(value, pattern, path, errors):
    if not pattern.match(value):
        errors.append(ManifestError("%s does not match required pattern" % path))
        return False
    return True


def _object_keys(obj, allowed, path, errors, err_cls=ManifestError):
    """Fail-explicit unknown-key check with VALUE-FREE diagnostics (D06).

    The offending key text is caller-controlled and is WITHHELD (a secret
    supplied in an unexpected key must never reach stderr); the allowed set
    is contract text and is always named.
    """
    for key in obj:
        if key not in allowed:
            errors.append(
                err_cls(
                    "%s: contains an unsupported key (key text withheld); allowed keys are %s "
                    "(fail-explicit subset)" % (path, sorted(allowed))
                )
            )


def _reject_dollar(value, path, errors):
    """Any '$' is rejected in compose string values.

    Compose would expand ${VAR} and $VAR from the ambient host environment
    and treats $$ as an escape; this contract has no ambient host
    environment and no literal-dollar representable in the compose subset,
    so ALL dollar forms fail explicitly. Values needing '$' must travel as
    runtime inputs (env/file/stdin/user_config), never as compose bytes.
    """
    if isinstance(value, str) and "$" in value:
        errors.append(
            ComposeSubsetError(
                "%s contains '$'; interpolation (${VAR}, $VAR) and escapes ($$) are rejected "
                "-- the compose subset has no ambient host environment (deterministic config only)"
                % path
            )
        )


def validate_compose_document(doc, manifest, errors):
    """Validate the decoded embedded compose document against the v4 subset.

    Cross-checks against the manifest: volume slots/targets/modes and
    env-name separation (compose static env must be disjoint from the
    workload-audience allowed_envs and may never use the harness-reserved
    DSMACK_ prefix). Volume entries may reference WORKLOAD-audience slots
    only -- broker-audience material is never mounted into the workload
    (astra C03). BOUNDED multi-service subset (D09): 1..MAX_SERVICES
    services, each individually subset-checked.
    """
    if not _check_type(doc, dict, "docker_compose_file", errors):
        return
    _object_keys(doc, COMPOSE_ALLOWED_TOP_KEYS, "compose", errors, ComposeSubsetError)
    if "services" not in doc:
        errors.append(ComposeSubsetError("compose.services is required"))
        return
    services = doc["services"]
    if not _check_type(services, dict, "compose.services", errors):
        return
    if not (MIN_SERVICES <= len(services) <= MAX_SERVICES):
        errors.append(
            ComposeSubsetError(
                "compose.services must contain between %d and %d services, got %d (bounded "
                "multi-service subset; anything larger is rejected explicitly, not ignored)"
                % (MIN_SERVICES, MAX_SERVICES, len(services))
            )
        )
        return

    for service_name in services:
        if not isinstance(service_name, str) or not SERVICE_NAME_RE.match(service_name):
            errors.append(ComposeSubsetError("compose service name is invalid"))
            continue
        service = services[service_name]
        spath = "compose.services.%s" % service_name
        if not _check_type(service, dict, spath, errors):
            continue
        _object_keys(service, COMPOSE_ALLOWED_SERVICE_KEYS, spath, errors, ComposeSubsetError)
        _validate_single_service(service_name, service, manifest, errors)


def _service_names(doc):
    """Declared service names from a VALIDATED compose doc (best effort)."""
    try:
        services = doc["services"]
        if isinstance(services, dict):
            return [name for name in services if isinstance(name, str)]
    except Exception:  # noqa: BLE001 - summary helper only
        pass
    return []


def _validate_single_service(service_name, service, manifest, errors):
    spath = "compose.services.%s" % service_name

    # E07: type-validate BEFORE traversal (a truthy scalar allowed_envs used
    # to be iterated here and crash with TypeError).
    allowed_envs_node = manifest.get("allowed_envs")
    workload_envs = {
        entry["name"]
        for entry in (allowed_envs_node if isinstance(allowed_envs_node, list) else [])
        if isinstance(entry, dict) and isinstance(entry.get("name"), str) and entry.get("audience") == "workload"
    }

    if "image" not in service:
        errors.append(ComposeSubsetError("%s.image is required and must be digest-pinned" % spath))
    else:
        image = service["image"]
        if not isinstance(image, str) or not IMAGE_RE.match(image):
            errors.append(
                ComposeSubsetError(
                    "%s.image must be repo@sha256:<64hex> (floating tags are rejected)" % spath
                )
            )
        else:
            _reject_dollar(image, "%s.image" % spath, errors)

    # C02: argv is ARRAY-ONLY. String forms have two different
    # interpretations across tooling and are rejected outright.
    for field in ("entrypoint", "command"):
        if field in service:
            value = service[field]
            if not (isinstance(value, list) and value and all(isinstance(v, str) for v in value)):
                errors.append(
                    ComposeSubsetError(
                        "%s.%s must be a NON-EMPTY ARRAY of strings (string form is rejected: "
                        "argv semantics must be unambiguous)" % (spath, field)
                    )
                )
            else:
                for item in value:
                    _reject_dollar(item, "%s.%s" % (spath, field), errors)

    if "security_profile" in service:
        try:
            from .security import require_selection
            require_selection(service, manifest)
        except (ValueError, OSError) as exc:
            errors.append(ComposeSubsetError("%s security profile refused: %s" % (spath, exc)))

    if "working_dir" in service:
        if not isinstance(service["working_dir"], str):
            errors.append(ComposeSubsetError("%s.working_dir must be a string" % spath))
        else:
            _reject_dollar(service["working_dir"], "%s.working_dir" % spath, errors)

    # C02: the workload runs with a read-only rootfs, period. A submitted
    # read_only:false is REJECTED (never silently replaced).
    if "read_only" in service and service["read_only"] is not True:
        errors.append(
            ComposeSubsetError(
                "%s.read_only must be literal true when present; false is rejected (the workload "
                "rootfs is read-only by contract; writable state lives in declared slots)" % spath
            )
        )

    if "environment" in service:
        env = service["environment"]
        if not _check_type(env, dict, spath + ".environment", errors):
            env = None
        if env is not None:
            for key, value in env.items():
                if not isinstance(key, str) or not ENV_NAME_RE.match(key):
                    errors.append(ComposeSubsetError("%s.environment has an invalid env name" % spath))
                    continue
                if not isinstance(value, str):
                    errors.append(
                        ComposeSubsetError(
                            "%s.environment[%s] must be a static string literal; "
                            "null/numbers/lists and interpolation are rejected" % (spath, key)
                        )
                    )
                else:
                    _reject_dollar(value, "%s.environment[%s]" % (spath, key), errors)
                if key in workload_envs:
                    errors.append(
                        ComposeSubsetError(
                            "%s.environment[%s] collides with manifest.allowed_envs; a name is either "
                            "a runtime input or a static value, never both" % (spath, key)
                        )
                    )
                if key.startswith(RESERVED_ENV_PREFIXES):
                    errors.append(
                        ComposeSubsetError(
                            "%s.environment[%s] uses the harness-reserved DSMACK_ prefix" % (spath, key)
                        )
                    )

    allowed_slots = _declared_slots(manifest)
    if "volumes" in service:
        volumes = service["volumes"]
        if not _check_type(volumes, list, spath + ".volumes", errors):
            volumes = None
        if volumes is not None:
            for vol in volumes:
                if not isinstance(vol, str):
                    errors.append(ComposeSubsetError("%s.volumes entries must be strings" % spath))
                    continue
                if vol == DSTACK_SOCK_VOLUME:
                    continue
                _reject_dollar(vol, "%s.volumes" % spath, errors)
                parts = vol.split(":")
                if len(parts) != 3:
                    errors.append(
                        ComposeSubsetError(
                            "%s.volumes entry must be '<slot>:<container_path>:<ro|rw>' referencing a "
                            "manifest workspace slot; arbitrary host binds are rejected" % spath
                        )
                    )
                    continue
                slot, target, mode = parts
                if not isinstance(slot, str) or slot not in allowed_slots:
                    # E08: value-free diagnostic -- the undeclared caller-supplied
                    # slot name is withheld.
                    errors.append(
                        ComposeSubsetError(
                            "%s.volumes references an undeclared slot (slot name withheld); mounts may "
                            "only use manifest-declared workspace slots" % spath
                        )
                    )
                    continue
                slot_def = allowed_slots[slot]
                if slot_def.get("audience") == "broker":
                    errors.append(
                        ComposeSubsetError(
                            "%s.volumes references broker-audience slot %r; broker material is NEVER "
                            "mounted into the workload (astra C03)" % (spath, slot)
                        )
                    )
                    continue
                if target != slot_def.get("target") or mode != slot_def.get("mode"):
                    errors.append(
                        ComposeSubsetError(
                            "%s.volumes slot %r must match the manifest declaration exactly "
                            "(target %r, mode %r)" % (spath, slot, slot_def["target"], slot_def["mode"])
                        )
                    )

    if "deploy" in service:
        deploy = service["deploy"]
        if _check_type(deploy, dict, spath + ".deploy", errors):
            _object_keys(deploy, {"resources"}, spath + ".deploy", errors, ComposeSubsetError)
            if "resources" in deploy:
                resources = deploy["resources"]
                if _check_type(resources, dict, spath + ".deploy.resources", errors):
                    _object_keys(resources, {"limits"}, spath + ".deploy.resources", errors, ComposeSubsetError)
                    if "limits" in resources:
                        limits = resources["limits"]
                        if _check_type(limits, dict, spath + ".deploy.resources.limits", errors):
                            _object_keys(
                                limits,
                                {"cpus", "memory"},
                                spath + ".deploy.resources.limits",
                                errors,
                                ComposeSubsetError,
                            )
                            if "cpus" in limits and not (
                                isinstance(limits["cpus"], (int, float))
                                and not isinstance(limits["cpus"], bool)
                                and 0 < limits["cpus"] <= 64
                            ):
                                errors.append(
                                    ComposeSubsetError(
                                        "%s.deploy.resources.limits.cpus must be a number in (0, 64]" % spath
                                    )
                                )
                            if "memory" in limits and not _bounded_ascii_uint(limits["memory"], 68719476736):
                                errors.append(
                                    ComposeSubsetError(
                                        "%s.deploy.resources.limits.memory must be a plain DIGIT STRING "
                                        "byte count (the pinned Docker Compose parser requires strings; "
                                        "unit suffixes are ambiguous and rejected)" % spath
                                    )
                                )


def _bounded_ascii_uint(value, maximum, max_digits=12):
    """R06: bounded ASCII-only non-negative integer string check.

    ``str.isdigit()`` accepts non-ASCII digit characters (e.g. '²') that
    ``int()`` then rejects or misparses; this check admits ONLY ASCII
    digits, bounded length and range, so numeric parsing can never raise an
    interpreter error on malformed caller input.
    """
    if not isinstance(value, str) or not value or len(value) > max_digits:
        return False
    if not value.isascii() or not value.isdigit():
        return False
    try:
        parsed = int(value)
    except ValueError:  # pragma: no cover - isascii+isdigit precludes this
        return False
    return 0 < parsed <= maximum


def _declared_slot_admitted(entry):
    """U02: the exact shape a declaration must have to be ADMITTED to the
    dependent Compose volume crosschecks. A declaration failing ANY of these
    predicates is rejected on the allowed_files validation path and is
    EXCLUDED here, so the crosschecks can neither crash on it (missing
    target/mode reached slot_def indexing) nor echo any of its rejected
    values (a referencing volume gets the value-free undeclared-slot
    diagnostic instead)."""
    if not isinstance(entry, dict):
        return False
    slot = entry.get("slot")
    if not (isinstance(slot, str) and SLOT_RE.match(slot)) or slot in RESERVED_SLOT_NAMES:
        return False
    target = entry.get("target")
    if not (
        isinstance(target, str)
        and target.startswith(INPUTS_ROOT + "/")
        and WORKSPACE_SEGMENT_RE.match(target[len(INPUTS_ROOT) + 1:])
    ):
        return False
    if entry.get("mode") not in ("ro", "rw"):
        return False
    if entry.get("audience") not in AUDIENCES:
        return False
    max_bytes = entry.get("max_bytes")
    if not (_is_int(max_bytes) and 1 <= max_bytes <= MAX_SLOT_BYTES):
        return False
    return isinstance(entry.get("required", False), bool)


def _declared_slots(manifest):
    """Declared input slots plus the ABI built-ins (artifacts, state).

    U02: only SHAPE-VALID declarations are admitted (_declared_slot_admitted);
    declarations are validated (on the allowed_files path, which runs BEFORE
    the Compose crosschecks) so an admitted entry always carries its
    target/mode/audience -- the volume crosscheck can never KeyError on a
    malformed declaration and never interpolates a rejected value.
    """
    slots = {}
    allowed_files_node = manifest.get("allowed_files")
    for entry in allowed_files_node if isinstance(allowed_files_node, list) else []:
        if _declared_slot_admitted(entry):
            slots[entry["slot"]] = entry
    slots["artifacts"] = {"slot": "artifacts", "target": ARTIFACTS_ROOT, "mode": "rw", "audience": "workload"}
    slots["state"] = {"slot": "state", "target": STATE_ROOT, "mode": "rw", "audience": "workload"}
    return slots


#: dstack app-compose.json fields a dsmack guest accepts around the "dsmack" block.
#: The values below are the only ones with a meaning here; anything else is refused.
DSTACK_APP_COMPOSE_FIXED = {"manifest_version": 2, "runner": "docker-compose", "kms_enabled": True, "key_provider": "kms"}
DSTACK_APP_COMPOSE_KEYS = {"name", "docker_compose_file", "allowed_envs", "dsmack", "public_logs", "public_sysinfo",
                           "public_tcbinfo", "gateway_enabled"} | set(DSTACK_APP_COMPOSE_FIXED)


def unwrap_dstack_app_compose(app):
    """dstack's app-compose.json with dsmack's own fields under "dsmack", as a v4 manifest.

    sha256 of the exact app-compose.json bytes is then both dstack's compose_hash and
    dsmack's manifest_sha256, so one admitted hash covers both platforms.
    """
    errors = []
    _object_keys(app, DSTACK_APP_COMPOSE_KEYS, "app-compose", errors)
    for key, value in DSTACK_APP_COMPOSE_FIXED.items():
        if key in app and app[key] != value:
            errors.append(ManifestError("app-compose.%s must be %r" % (key, value)))
    inner = app["dsmack"]
    if not _check_type(inner, dict, "app-compose.dsmack", errors):
        raise MultiError(errors)
    for key in ("manifest_version", "name", "docker_compose_file", "allowed_envs"):
        if key in inner:
            errors.append(ManifestError("app-compose.dsmack.%s belongs at the top level" % key))
    if errors:
        raise MultiError(errors)
    return dict(inner, manifest_version=4, name=app.get("name"), docker_compose_file=app.get("docker_compose_file"),
                allowed_envs=app.get("allowed_envs", []))


def validate_manifest_bytes(manifest_bytes):
    """Validate exact manifest bytes; returns (parsed_manifest, summary dict)."""
    manifest = load_json_bytes(manifest_bytes, "manifest")
    if isinstance(manifest, dict) and "dsmack" in manifest:
        manifest = unwrap_dstack_app_compose(manifest)
    summary = validate_manifest(manifest)
    summary["manifest_sha256"] = sha256_hex(manifest_bytes)
    return manifest, summary


def validate_manifest(manifest):
    """Validate a parsed manifest dict; returns a summary dict.

    Raises MultiError listing every violation found (fail-explicit, bounded).
    """
    errors = []
    if not _check_type(manifest, dict, "manifest", errors):
        raise MultiError(errors)

    _object_keys(manifest, MANIFEST_REQUIRED_KEYS | MANIFEST_OPTIONAL_KEYS, "manifest", errors)

    for key in MANIFEST_REQUIRED_KEYS:
        if key not in manifest:
            errors.append(ManifestError("manifest.%s is required" % key))
    if errors:
        raise MultiError(errors)

    if manifest["manifest_version"] != 4:
        errors.append(ManifestError("manifest.manifest_version must be 4"))

    # D05: optional keys present with an EXPLICIT null are rejected, never
    # silently treated as absent (schema/library parity).
    for key in ("env_policy", "credentials", "limits"):
        if key in manifest and manifest[key] is None:
            errors.append(ManifestError("manifest.%s must be an object when present (explicit null is rejected)" % key))

    if _check_type(manifest["name"], str, "manifest.name", errors):
        _check_pattern(manifest["name"], NAME_RE, "manifest.name", errors)

    _validate_runner(manifest["runner"], errors)
    _validate_base_vm(manifest["base_vm"], errors)
    _validate_harness(manifest["harness"], errors)
    _validate_platform(manifest["image_platform"], manifest["base_vm"], errors)

    compose_doc = None
    if _check_type(manifest["docker_compose_file"], str, "manifest.docker_compose_file", errors):
        compose_bytes = manifest["docker_compose_file"].encode("utf-8")
        try:
            compose_doc = load_json_bytes(compose_bytes, "manifest.docker_compose_file")
        except Exception as exc:  # noqa: BLE001 - re-raise as contract error with context
            errors.append(
                ManifestError(
                    "manifest.docker_compose_file must be strict-JSON text parseable by the contract "
                    "profile (embedded compose is measured as EXACT bytes; canonical form is NOT "
                    "required): %s" % exc
                )
            )
        else:
            # U02: the allowed_files declarations are validated BEFORE the
            # dependent Compose crosschecks, so a malformed declaration is
            # rejected on its own path and (via _declared_slots) excluded
            # from the volume checks -- the crosschecks can neither crash on
            # it nor interpolate any of its rejected values.
            _validate_allowed_files(manifest["allowed_files"], compose_doc, errors)
            validate_compose_document(compose_doc, manifest, errors)
    else:
        # Compose bytes that never parsed leave no crosschecks to run, but
        # the declarations are still validated on their own path.
        _validate_allowed_files(manifest["allowed_files"], None, errors)

    allowed_envs = manifest["allowed_envs"]
    required_envs = manifest["required_envs"]
    _validate_env_lists(allowed_envs, required_envs, manifest, compose_doc, errors)
    _validate_runtime_inputs_decl(manifest["runtime_inputs"], allowed_envs, required_envs, compose_doc, errors)
    _validate_network(manifest["network"], manifest["runner"], errors)
    _validate_outputs(manifest["outputs"], compose_doc, errors)
    _validate_credentials(manifest.get("credentials"), allowed_envs, manifest["allowed_files"], errors)
    _validate_limits(manifest.get("limits"), errors)
    # R05: the designated completion service (declared, or the single
    # service) must be the one that exercises the verified harness claim.
    declared_services = _service_names(compose_doc) if isinstance(compose_doc, dict) else []
    completion_node = manifest["outputs"].get("completion_service") if isinstance(manifest["outputs"], dict) else None
    effective_completion = completion_node if isinstance(completion_node, str) else (declared_services[0] if len(declared_services) == 1 else None)
    _validate_harness_entrypoint_binding(manifest["harness"], compose_doc, effective_completion, errors)

    # Input delivery targets must be disjoint: every TARGET SEGMENT under
    # /workspace/inputs/ names the single host source file backing the
    # delivery (D04: mounts are keyed by target segment, so two deliveries
    # sharing a segment would share bytes). The user_config target segment
    # participates in the same namespace.
    slot_targets = set()
    if isinstance(manifest["allowed_files"], list):
        for entry in manifest["allowed_files"]:
            if isinstance(entry, dict) and isinstance(entry.get("target"), str):
                slot_targets.add(entry["target"])
    uc_node = manifest["runtime_inputs"].get("user_config") if isinstance(manifest["runtime_inputs"], dict) else {}
    if isinstance(uc_node, dict) and uc_node.get("mode") == "opaque-file":
        uc_target = uc_node.get("target", DEFAULT_USER_CONFIG_TARGET)
        # D05: type-check BEFORE set membership (a list target used to reach
        # `in` unguarded and crash with TypeError).
        if not isinstance(uc_target, str):
            errors.append(ManifestError("manifest.runtime_inputs.user_config.target must be a string"))
        else:
            if uc_target in slot_targets:
                errors.append(
                    ManifestError(
                        "manifest.runtime_inputs.user_config.target collides with an allowed_files slot "
                        "target; deliveries are keyed by target segment and must not share a source path"
                    )
                )
            uc_segment = uc_target[len(INPUTS_ROOT) + 1:] if uc_target.startswith(INPUTS_ROOT + "/") else uc_target
            for target in sorted(slot_targets):
                if target.startswith(INPUTS_ROOT + "/") and target[len(INPUTS_ROOT) + 1:] == uc_segment:
                    errors.append(
                        ManifestError(
                            "an allowed_files slot target shares the user_config target segment; input "
                            "deliveries must not share a host source"
                        )
                    )
    # Broker-audience inputs (env OR file) REQUIRE the credentials declaration
    # (astra C03: file-only broker manifests failed the v2 check).
    broker_names = _broker_input_names(allowed_envs, manifest["allowed_files"])
    if broker_names and not (
        isinstance(manifest.get("credentials"), dict) and manifest["credentials"].get("required") is True
    ):
        errors.append(
            ManifestError(
                "manifest declares %d broker-audience input(s) but credentials.required is not true"
                % len(broker_names)
            )
        )
    # D07: the sentinel transport is a compose bridge-gateway endpoint; a
    # broker manifest with network 'none' has no representable transport.
    if isinstance(manifest.get("credentials"), dict) and manifest["credentials"].get("required") is True:
        network_mode = (
            manifest["network"].get("mode")
            if isinstance(manifest["network"], dict)
            else None
        )
        if network_mode == "none":
            errors.append(
                ManifestError(
                    "manifest.credentials.required is incompatible with network.mode 'none': the only "
                    "supported sentinel transport is a workload-reachable TCP endpoint on the compose "
                    "bridge gateway; declare network 'nat' or reject the combination"
                )
            )
    # C05: stdin pipe delivery uses the compose run path, which publishes no
    # ports and targets exactly ONE service; multi-service pipe is outside
    # the subset (D09). Also type-guard network indexing (D05).
    stdin_node = (
        manifest["runtime_inputs"].get("stdin") if isinstance(manifest["runtime_inputs"], dict) else None
    )
    network_node = manifest["network"] if isinstance(manifest["network"], dict) else {}
    if isinstance(stdin_node, dict):
        listen_ports = network_node.get("listen_ports")
        has_ports = isinstance(listen_ports, list) and len(listen_ports) > 0
        if stdin_node.get("mode") == "pipe" and has_ports:
            errors.append(
                ManifestError(
                    "manifest.runtime_inputs.stdin.mode 'pipe' cannot be combined with network.listen_ports "
                    "(pipe delivery uses the compose run path, which publishes no ports); declare stdin 'none' "
                    "or network 'none'"
                )
            )
        if stdin_node.get("mode") == "pipe" and compose_doc is not None and isinstance(compose_doc, dict):
            services = compose_doc.get("services")
            if isinstance(services, dict) and len(services) > 1:
                errors.append(
                    ManifestError(
                        "manifest.runtime_inputs.stdin.mode 'pipe' targets exactly one service and is "
                        "single-service only in the v4 subset; multi-service manifests must declare "
                        "stdin 'none'"
                    )
                )
    # E04: the renderer emits the SAME published ports on EVERY service, so a
    # multi-service manifest with listen_ports creates N duplicate host
    # bindings (a binding conflict). Per-service port ownership is not defined
    # in the bounded subset: multi-service publishing is rejected explicitly.
    if compose_doc is not None and isinstance(compose_doc, dict):
        ms_services = compose_doc.get("services")
        ms_ports = manifest["network"].get("listen_ports") if isinstance(manifest["network"], dict) else None
        if (
            isinstance(ms_services, dict)
            and len(ms_services) > 1
            and isinstance(ms_ports, list)
            and ms_ports
        ):
            errors.append(
                ManifestError(
                    "manifest.network.listen_ports cannot be combined with multi-service manifests "
                    "(the same host ports would be published once per service, a binding conflict); "
                    "port publishing is single-service in the bounded subset"
                )
            )

    if errors:
        raise MultiError(errors)

    return {
        "name": manifest["name"],
        "container_runtime": manifest["runner"]["container_runtime"],
        "runtime_name": manifest["runner"]["runtime_name"],
        "base_vm_architecture": manifest["base_vm"]["architecture"],
        "base_vm_os_image_hash": manifest["base_vm"]["os_image_hash"],
        "base_vm_rootfs_sha256": manifest["base_vm"]["rootfs_sha256"],
        "harness": "%s@%s" % (manifest["harness"]["name"], manifest["harness"]["version"]),
        "image_platform": _platform_string(manifest["image_platform"]),
        "services": _service_images(manifest),
        "service_image": _primary_service_image(manifest),
        "timeout_s": _effective_limits(manifest)["timeout_s"],
    }


def _broker_input_names(allowed_envs, allowed_files):
    """Names of every broker-audience input (env names + file slots)."""
    names = []
    if isinstance(allowed_envs, list):
        names += [
            entry.get("name")
            for entry in allowed_envs
            if isinstance(entry, dict) and isinstance(entry.get("name"), str) and entry.get("audience") == "broker"
        ]
    if isinstance(allowed_files, list):
        names += [
            entry.get("slot")
            for entry in allowed_files
            if isinstance(entry, dict) and isinstance(entry.get("slot"), str) and entry.get("audience") == "broker"
        ]
    return names


def _platform_string(platform):
    if not isinstance(platform, dict):
        return None
    text = "%s/%s" % (platform.get("os"), platform.get("architecture"))
    if platform.get("variant"):
        text += "/" + platform["variant"]
    return text


def _service_images(manifest):
    """Per-service requested image pins, in compose document order."""
    try:
        doc = load_json_bytes(manifest["docker_compose_file"].encode("utf-8"), "compose")
        services = doc["services"]
        if not isinstance(services, dict):
            return []
        return [{"service": name, "image": svc.get("image")} for name, svc in services.items() if isinstance(svc, dict)]
    except Exception:  # noqa: BLE001 - summary helper only
        return []


def _primary_service_image(manifest):
    images = _service_images(manifest)
    return images[0]["image"] if images else None


def _service_image(manifest):
    """Backwards-compatible single accessor (first service image)."""
    return _primary_service_image(manifest)


def _effective_limits(manifest):
    limits = manifest.get("limits") if isinstance(manifest.get("limits"), dict) else {}
    return {
        "timeout_s": limits.get("timeout_s", DEFAULT_TIMEOUT_S),
        "workspace_max_bytes": limits.get("workspace_max_bytes", DEFAULT_WORKSPACE_BYTES),
        "output_max_bytes": limits.get("output_max_bytes", DEFAULT_WORKSPACE_BYTES),
    }


def _validate_runner(runner, errors):
    if not _check_type(runner, dict, "manifest.runner", errors):
        return
    _object_keys(
        runner,
        {"kind", "container_runtime", "runtime_name", "runtime_version", "runsc", "compose_tool", "runtime_closure", "host_toolchain_policy"},
        "manifest.runner",
        errors,
    )
    if runner.get("kind") != "oci-compose":
        errors.append(ManifestError("manifest.runner.kind must be 'oci-compose' in v4"))
    runtime = runner.get("container_runtime")
    if runtime not in ("runc", "runsc"):
        errors.append(
            ManifestError(
                "manifest.runner.container_runtime must be 'runc' or 'runsc' (explicit; no silent fallback)"
            )
        )
    # C04: the registered runtime name is explicit and consistent.
    runtime_name = runner.get("runtime_name")
    if runtime_name not in REGISTERED_RUNTIMES:
        errors.append(
            ManifestError(
                "manifest.runner.runtime_name must be one of %s (the registered runtime passed as the "
                "compose runtime key)" % (list(REGISTERED_RUNTIMES),)
            )
        )
    # C04: release-style identities are representable (release-20260622.0).
    if not (isinstance(runner.get("runtime_version"), str) and RELEASE_RE.match(runner["runtime_version"])):
        errors.append(
            ManifestError(
                "manifest.runner.runtime_version must be a pinned release identity (semver or dated "
                "release string, e.g. 1.3.4 or release-20260622.0)"
            )
        )
    tool = runner.get("compose_tool")
    if not _check_type(tool, dict, "manifest.runner.compose_tool", errors):
        return
    _object_keys(tool, {"name", "version"}, "manifest.runner.compose_tool", errors)
    # C02/ledger 4.4: docker-compose only; nerdctl-compose is rejected until
    # implemented (the v2 schema advertised a tool the renderer never used).
    if tool.get("name") != "docker-compose":
        errors.append(
            ManifestError(
                "manifest.runner.compose_tool.name must be 'docker-compose' (other tools are rejected "
                "until implemented; the renderer emits Docker Compose only)"
            )
        )
    if not (isinstance(tool.get("version"), str) and RELEASE_RE.match(tool["version"])):
        errors.append(ManifestError("manifest.runner.compose_tool.version must be a pinned release identity"))

    runsc = runner.get("runsc")
    if runtime == "runsc":
        # Explicit gVisor policy is REQUIRED (fail closed): platform systrap is
        # the supported in-VM platform; network netstack|host is explicit and
        # binds the registered runtime name (C04).
        if not _check_type(runsc, dict, "manifest.runner.runsc", errors):
            return
        _object_keys(runsc, {"platform", "network"}, "manifest.runner.runsc", errors)
        if runsc.get("platform") != "systrap":
            errors.append(
                ManifestError("manifest.runner.runsc.platform must be 'systrap' (the supported in-VM platform)")
            )
        network = runsc.get("network")
        if network not in ("netstack", "host"):
            errors.append(
                ManifestError(
                    "manifest.runner.runsc.network must be 'netstack' or 'host' (host means gVisor "
                    "network syscalls pass through the container netns -- a distinct registered "
                    "runtime, NOT Docker host networking)"
                )
            )
        if isinstance(runtime_name, str):
            expected_name = RUNTIME_RUNSC_HOSTNET if network == "host" else RUNTIME_RUNSC
            if runtime_name != expected_name:
                # S06: value-free diagnostic -- an invalid runtime_name has
                # already been rejected by the vocabulary check above and is
                # never echoed here.
                errors.append(
                    ManifestError(
                        "manifest.runner.runtime_name is inconsistent with runsc.network (the registered "
                        "runtime name must be the one matching the declared network policy); the "
                        "registered runtime name and the network policy must agree"
                    )
                )
    else:
        # S05: absence and explicit null are distinct at this optional-object
        # boundary. The schema types runsc as an object when present, so a
        # declared null is a schema-invalid shape and is rejected (it is never
        # silently treated as "no gVisor policy").
        if "runsc" in runner:
            if runner["runsc"] is None:
                errors.append(
                    ManifestError(
                        "manifest.runner.runsc must be an object when present (explicit null is "
                        "rejected; schema parity)"
                    )
                )
            else:
                errors.append(
                    ManifestError("manifest.runner.runsc is only valid when container_runtime is 'runsc'")
                )
        if runtime_name == RUNTIME_RUNC:
            pass
        elif isinstance(runtime_name, str):
            # S06: value-free diagnostic (the rejected runtime_name is withheld).
            errors.append(
                ManifestError(
                    "manifest.runner.runtime_name requires container_runtime 'runsc' (the registered "
                    "runtime name must agree with the declared container runtime)"
                )
            )

    # D10: the immutable runtime closure. The registered runtime's
    # executable/bundle bytes and its EXACT registration (path + arguments)
    # are pinned here and live under the base-vm verity root (bound to the
    # checksum manifest). Same-name wrong-binary or wrong-arguments
    # registrations are rejectable against this closure.
    closure = runner.get("runtime_closure")
    if not _check_type(closure, dict, "manifest.runner.runtime_closure", errors):
        return
    _object_keys(closure, {"components"}, "manifest.runner.runtime_closure", errors)
    components = closure.get("components")
    if not _check_type(components, list, "manifest.runner.runtime_closure.components", errors):
        return
    if not 1 <= len(components) <= 8:
        errors.append(ManifestError("manifest.runner.runtime_closure.components must hold 1..8 entries"))
        return
    by_name = {}
    for i, component in enumerate(components):
        cpath = "manifest.runner.runtime_closure.components[%d]" % i
        if not _check_type(component, dict, cpath, errors):
            continue
        _object_keys(component, {"name", "path", "sha256", "registration_args"}, cpath, errors)
        name = component.get("name")
        if not (isinstance(name, str) and NAME_RE.match(name)):
            errors.append(ManifestError("%s.name must be a valid component name" % cpath))
            continue
        if name in by_name:
            errors.append(ManifestError("%s duplicates component name %s" % (cpath, name)))
        by_name[name] = component
        path = component.get("path")
        if not (isinstance(path, str) and CONTAINER_PATH_RE.match(path)):
            errors.append(ManifestError("%s.path must be an absolute guest path" % cpath))
        digest = component.get("sha256")
        if not (isinstance(digest, str) and HEX64_RE.match(digest)):
            errors.append(ManifestError("%s.sha256 must be a 64-hex pin of the executable/bundle bytes" % cpath))
        args = component.get("registration_args")
        if not (isinstance(args, list) and len(args) <= MAX_REGISTRATION_ARGS and all(isinstance(a, str) for a in args)):
            errors.append(
                ManifestError(
                    "%s.registration_args must be a list of at most %d strings (the EXACT registered "
                    "arguments the supervisor must verify)" % (cpath, MAX_REGISTRATION_ARGS)
                )
            )
        else:
            # E06: registration arguments are enforced against the declared
            # runtime/platform/network policy. A registration can otherwise
            # faithfully match its pins while contradicting the policy.
            _validate_registration_args(name, args, runner, cpath, errors)
    # D10: optional host toolchain policy (linux-test requested/admitted
    # comparison target). R06: one absent/empty policy across schemas and
    # validators -- a DECLARED policy must carry a non-empty bounded
    # components array (schema minItems 1); an empty one would silently
    # disable the observed-component comparison in receipts.
    # S05: absence and explicit null are distinct. The schema types
    # host_toolchain_policy as an object when present; a declared null is
    # rejected here so it can never be treated as "no policy" by the
    # receipt comparison.
    policy = runner.get("host_toolchain_policy")
    if policy is None and "host_toolchain_policy" in runner:
        errors.append(
            ManifestError(
                "manifest.runner.host_toolchain_policy must be an object when present (explicit null "
                "is rejected; schema parity; a declared-null policy is not 'no policy')"
            )
        )
    elif policy is not None:
        if not _check_type(policy, dict, "manifest.runner.host_toolchain_policy", errors):
            return
        _object_keys(policy, {"components"}, "manifest.runner.host_toolchain_policy", errors)
        pc = policy.get("components")
        if not _check_type(pc, list, "manifest.runner.host_toolchain_policy.components", errors):
            return
        if not pc or len(pc) > 64:
            errors.append(
                ManifestError(
                    "manifest.runner.host_toolchain_policy.components must be a non-empty bounded "
                    "array (1..64) when the policy is declared; an empty declared policy is rejected "
                    "because it would disable the observed-component comparison"
                )
            )
            return
        for i, component in enumerate(pc):
            cpath = "manifest.runner.host_toolchain_policy.components[%d]" % i
            if not _check_type(component, dict, cpath, errors):
                continue
            _object_keys(component, {"name", "sha256"}, cpath, errors)
            if not (isinstance(component.get("name"), str) and component["name"]):
                errors.append(ManifestError("%s.name must be a non-empty string" % cpath))
            if not (isinstance(component.get("sha256"), str) and HEX64_RE.match(component["sha256"])):
                errors.append(ManifestError("%s.sha256 must be 64-hex" % cpath))
    # The requested runtime's component must be pinned (D10).
    component_name = RUNTIME_COMPONENT.get(runtime_name) if isinstance(runtime_name, str) else None
    if component_name is not None and component_name not in by_name:
        errors.append(
            ManifestError(
                "manifest.runner.runtime_closure must pin a component named %r for the requested "
                "registered runtime %r (prelaunch verifies the executable bytes and the exact "
                "registration against this closure)" % (component_name, runtime_name)
            )
        )


#: E06: supported registration-argument vocabulary per closure component.
#: runsc's docker registration carries exactly the platform + network flags;
#: the runc component registers with no extra arguments. Anything else
#: (unknown flags, duplicates, contradictions) is rejected.
RUNSC_REGISTRATION_SUPPORTED = ("--platform=systrap", "--network=netstack", "--network=host")


def _validate_registration_args(component_name, args, runner, cpath, errors):
    """E06: enforce supported registration arguments against runtime policy."""
    if component_name == RUNTIME_COMPONENT.get(RUNTIME_RUNC):
        if args:
            errors.append(
                ManifestError(
                    "%s: the runc component registers with NO extra arguments (an empty "
                    "registration_args is required); unknown registration flags are rejected" % cpath
                )
            )
        return
    if component_name == RUNTIME_COMPONENT.get(RUNTIME_RUNSC):
        if len(args) != len(set(args)):
            errors.append(ManifestError("%s.registration_args has duplicate flags" % cpath))
            return
        unknown = [a for a in args if a not in RUNSC_REGISTRATION_SUPPORTED]
        if unknown:
            errors.append(
                ManifestError(
                    "%s.registration_args contains %d unsupported flag(s) (flag text withheld); the "
                    "supported runsc registration vocabulary is %s"
                    % (cpath, len(unknown), list(RUNSC_REGISTRATION_SUPPORTED))
                )
            )
            return
        platforms = [a for a in args if a.startswith("--platform=")]
        networks = [a for a in args if a.startswith("--network=")]
        if len(platforms) != 1 or platforms != ["--platform=systrap"]:
            errors.append(
                ManifestError(
                    "%s.registration_args must carry exactly '--platform=systrap' (the supported "
                    "in-VM platform) exactly once" % cpath
                )
            )
        if len(networks) != 1:
            errors.append(
                ManifestError(
                    "%s.registration_args must carry exactly one of '--network=netstack' or "
                    "'--network=host'" % cpath
                )
            )
        elif isinstance(runner, dict):
            runsc_network = runner.get("runsc", {}).get("network") if isinstance(runner.get("runsc"), dict) else None
            runtime_name = runner.get("runtime_name")
            # S06: runsc_network may itself be an already-rejected invalid
            # value; the dependent diagnostics below are value-free.
            valid_network = runsc_network in ("netstack", "host")
            expected = "--network=%s" % runsc_network if valid_network else None
            expected_name = RUNTIME_RUNSC_HOSTNET if runsc_network == "host" else RUNTIME_RUNSC
            if expected is not None and networks != [expected]:
                errors.append(
                    ManifestError(
                        "%s.registration_args network flag contradicts the declared runsc.network "
                        "policy (the flag must be exactly %s)" % (cpath, expected)
                    )
                )
            if expected is not None and runtime_name != expected_name:
                # S06: value-free diagnostic (the rejected runtime_name is withheld).
                errors.append(
                    ManifestError(
                        "%s.registration_args network flag does not agree with runtime_name "
                        "(expected the registered runtime name %s matching the declared network "
                        "policy)" % (cpath, expected_name)
                    )
                )


def _validate_base_vm(vm, errors):
    if not _check_type(vm, dict, "manifest.base_vm", errors):
        return
    _object_keys(
        vm,
        {
            "architecture",
            "os_image_hash",
            "metadata_sha256",
            "kernel_sha256",
            "initrd_sha256",
            "rootfs_sha256",
            "verity_root_hash",
            "cmdline",
            "vcpus",
            "memory_mb",
        },
        "manifest.base_vm",
        errors,
    )
    if vm.get("architecture") not in ("x86_64", "aarch64"):
        errors.append(ManifestError("manifest.base_vm.architecture must be 'x86_64' or 'aarch64'"))
    # D01/E01: the identity anchors over the DELIVERED dstack bundle layout.
    # os_image_hash is SHA256 over the EXACT serialized checksum manifest bytes
    # (Image/initramfs.cpio.gz/metadata.json/rootfs.squashfs.verity);
    # metadata_sha256 covers the metadata document whose cmdline is the boot
    # cmdline. The delivered bundle has ONE rootfs artifact -- the combined
    # verity image rootfs.squashfs.verity (data region + merkle tree +
    # superblock) pinned by rootfs_sha256; the v4.0 separate system.img role
    # (image_sha256) no longer exists and was removed. Component pins and
    # anchors are bound together, along with the metadata bytes, cmdline,
    # verity root and architecture, by image_admission.verify_base_vm_identity
    # before any boot.
    for field in (
        "os_image_hash",
        "metadata_sha256",
        "kernel_sha256",
        "initrd_sha256",
        "rootfs_sha256",
        "verity_root_hash",
    ):
        value = vm.get(field)
        if not (isinstance(value, str) and HEX64_RE.match(value)):
            errors.append(
                ManifestError(
                    "manifest.base_vm.%s must be a 64-hex sha256 pin (image identity follows the "
                    "serialized checksum manifest: os_image_hash + components + verity root + metadata)" % field
                )
            )
    cmdline = vm.get("cmdline")
    if not (isinstance(cmdline, str) and CMDLINE_RE.match(cmdline)):
        errors.append(
            ManifestError(
                "manifest.base_vm.cmdline must be the EXACT kernel command line (bounded printable "
                "ASCII, no '$'); it is bound into receipts and evidence and must equal the image "
                "metadata's declared command line"
            )
        )
    vcpus = vm.get("vcpus")
    if not (_is_int(vcpus) and 1 <= vcpus <= MAX_VCPUS):
        errors.append(ManifestError("manifest.base_vm.vcpus must be an integer in [1, %d]" % MAX_VCPUS))
    memory = vm.get("memory_mb")
    if not (_is_int(memory) and MIN_MEMORY_MB <= memory <= MAX_MEMORY_MB):
        errors.append(
            ManifestError("manifest.base_vm.memory_mb must be an integer in [%d, %d]" % (MIN_MEMORY_MB, MAX_MEMORY_MB))
        )


def _validate_harness(harness, errors):
    if not _check_type(harness, dict, "manifest.harness", errors):
        return
    _object_keys(harness, {"name", "version", "sha256", "path", "auxiliary_services"}, "manifest.harness", errors)
    if not (isinstance(harness.get("name"), str) and NAME_RE.match(harness["name"])):
        errors.append(ManifestError("manifest.harness.name is required and must be valid"))
    if not (isinstance(harness.get("version"), str) and RELEASE_RE.match(harness["version"])):
        errors.append(ManifestError("manifest.harness.version must be a pinned release identity"))
    if not (isinstance(harness.get("sha256"), str) and HEX64_RE.match(harness["sha256"])):
        errors.append(ManifestError("manifest.harness.sha256 must be a 64-hex pin of the actual harness bytes"))
    # D08: the harness is an IMAGE-CONTAINED component with a defined
    # verification path: `path` is its absolute in-image location; the runner
    # extracts those bytes from the pinned workload image and verifies them
    # against harness.sha256 before launch (workload-image identity comes
    # from the digest-pinned compose image refs).
    path = harness.get("path")
    if not (isinstance(path, str) and CONTAINER_PATH_RE.match(path)):
        errors.append(
            ManifestError(
                "manifest.harness.path must be an absolute in-image path (the image-contained harness "
                "model: the runner verifies the bytes at this path against harness.sha256)"
            )
        )
    # E05: mount-shadow rejection. The executed harness must resolve to
    # VERIFIED IMMUTABLE image content; a harness path beneath any mount
    # target (/workspace/inputs, /workspace/state, /workspace/artifacts,
    # /workspace/shared, a slot target or the user_config target) would be
    # shadowed by delivered/writable bytes, hiding the verified image bytes
    # behind different delivered content. Symlink policy: the runner resolves
    # harness.path within the image WITHOUT following symlinks out of the
    # image content -- any symlinked component is a launch rejection (runner
    # duty, interfaces/compose-runner-interface.md).
    if isinstance(path, str) and path is not None:
        # R05: the mount-shadow rejection operates on CANONICAL paths. The
        # accepted grammar permits dot segments and repeated slashes, so a
        # lexical prefix check alone is bypassable (e.g.
        # /usr/../workspace/state/h resolves into writable mounted state).
        # Noncanonical absolute paths are rejected outright and the shadow
        # comparison uses the canonical form.
        segments = path.split("/")
        if (
            not path.startswith("/")
            or path.endswith("/")
            or "//" in path
            or any(seg in (".", "..") for seg in segments)
        ):
            errors.append(
                ManifestError(
                    "manifest.harness.path must be a CANONICAL absolute path (no '.' or '..' "
                    "segments, no repeated or trailing slashes); a noncanonical harness path cannot "
                    "be matched against mount targets or verified after mount planning"
                )
            )
        else:
            shadow_prefixes = (INPUTS_ROOT + "/", STATE_ROOT + "/", ARTIFACTS_ROOT + "/", SHARED_ROOT + "/")
            if path.startswith(shadow_prefixes) or path in (INPUTS_ROOT, STATE_ROOT, ARTIFACTS_ROOT, SHARED_ROOT):
                errors.append(
                    ManifestError(
                        "manifest.harness.path must not live under a mount target (/workspace/inputs, "
                        "/workspace/state, /workspace/artifacts, /workspace/shared); a mount-shadowed "
                        "harness path can hide the verified image bytes behind delivered or writable bytes"
                    )
                )
    # E05: explicit auxiliary-service designation. Every declared service
    # either invokes the pinned harness (entrypoint[0] == harness.path) or is
    # DECLARED here as auxiliary (e.g. a producer/sidecar); an absent
    # entrypoint with no designation never falls back to the image default.
    auxiliary = harness.get("auxiliary_services", [])
    if auxiliary != [] and not (
        isinstance(auxiliary, list)
        and auxiliary
        and all(isinstance(s, str) for s in auxiliary)
        and len(auxiliary) == len(set(auxiliary))
    ):
        errors.append(
            ManifestError(
                "manifest.harness.auxiliary_services must be a unique non-empty list of declared "
                "service names (services that do NOT invoke the pinned harness); an absent entrypoint "
                "is otherwise rejected -- the image default is never silently executed"
            )
        )


def _declared_auxiliary(harness):
    """R06: the auxiliary set ONLY when every entry is a valid string.

    A shape-failed auxiliary_services value (e.g. [[]]) must never reach
    set()/membership processing; the shape error was already recorded, and
    dependent processing stops here by returning an empty set.
    """
    auxiliary = harness.get("auxiliary_services", []) if isinstance(harness, dict) else []
    if not isinstance(auxiliary, list) or not all(isinstance(s, str) for s in auxiliary):
        return set()
    return set(auxiliary)


def _validate_harness_entrypoint_binding(harness, compose_doc, completion_service, errors):
    """D08/E05 + R05: the DESIGNATED completion service always invokes the
    pinned harness; every other service invokes it or is declared auxiliary;
    the image default is never silently executed. R07: undeclared auxiliary
    names are never echoed into diagnostics."""
    if not isinstance(harness, dict) or not isinstance(harness.get("path"), str) or not isinstance(compose_doc, dict):
        return
    services = compose_doc.get("services")
    if not isinstance(services, dict):
        return
    auxiliary = _declared_auxiliary(harness)
    declared = [name for name in services if isinstance(name, str)]
    for _name in auxiliary:
        if _name not in declared:
            errors.append(
                ManifestError(
                    "manifest.harness.auxiliary_services names a service that is not declared in the "
                    "compose document (name withheld)"
                )
            )
    # R05: the auxiliary exemption never extends to the designated completion
    # service -- the verified-harness claim must be exercised by at least the
    # service that owns the run's exit evidence.
    if isinstance(completion_service, str) and completion_service in declared and completion_service in auxiliary:
        errors.append(
            ManifestError(
                "the designated completion service must invoke the pinned harness; it cannot be "
                "declared auxiliary (an unused harness claim would be unrelated to the executed "
                "program that owns the run's exit evidence)"
            )
        )
    for name, service in services.items():
        if not isinstance(service, dict):
            continue
        if name in auxiliary:
            continue
        entrypoint = service.get("entrypoint")
        if not (isinstance(entrypoint, list) and entrypoint and isinstance(entrypoint[0], str)):
            errors.append(
                ComposeSubsetError(
                    "compose.services.%s.entrypoint is REQUIRED and must be a non-empty array starting "
                    "with manifest.harness.path: an absent entrypoint would silently execute the image "
                    "default, whose bytes are not the pinned harness" % name
                )
            )
            continue
        if isinstance(harness.get("path"), str) and entrypoint[0] != harness["path"]:
            # S06: value-free diagnostic -- the comparison runs only when the
            # harness path itself is shape-valid; a malformed harness path was
            # already rejected by the harness validation and is not echoed.
            errors.append(
                ComposeSubsetError(
                    "compose.services.%s.entrypoint[0] does not equal manifest.harness.path (the "
                    "harness model is image-contained, and the invoked path must be exactly the path "
                    "whose bytes the runner verifies against harness.sha256; no separate host-supplied "
                    "executable is representable; auxiliary services must be declared in "
                    "manifest.harness.auxiliary_services)" % name
                )
            )


def _validate_platform(platform, base_vm, errors):
    if not _check_type(platform, dict, "manifest.image_platform", errors):
        return
    _object_keys(platform, {"os", "architecture", "variant"}, "manifest.image_platform", errors)
    if platform.get("os") != "linux":
        errors.append(ManifestError("manifest.image_platform.os must be 'linux' in v4"))
    arch = platform.get("architecture")
    # D05: membership check is type-guarded (a list architecture used to
    # reach dict indexing in _platform_string/consumers).
    if not isinstance(arch, str) or arch not in SUPPORTED_ARCHITECTURES:
        errors.append(
            ManifestError(
                "manifest.image_platform.architecture must be one of %s (bounded platform support)"
                % (SUPPORTED_ARCHITECTURES,)
            )
        )
    variant = platform.get("variant")
    if variant is not None and not (isinstance(variant, str) and WORKSPACE_SEGMENT_RE.match(variant)):
        errors.append(ManifestError("manifest.image_platform.variant must be a short identifier string"))
    # Base VM bytes are per-architecture; reject incompatible combinations.
    if (
        isinstance(arch, str)
        and arch in ARCH_COMPAT
        and isinstance(base_vm, dict)
        and base_vm.get("architecture") not in (None, ARCH_COMPAT[arch])
    ):
        errors.append(
            # S06: value-free diagnostic -- an invalid base_vm.architecture was
            # already rejected by its own validation and is never echoed here.
            ManifestError(
                "manifest.base_vm.architecture is incompatible with image_platform.architecture "
                "(expected %s); VM bytes are per-architecture" % ARCH_COMPAT[arch]
            )
        )


def _input_services_field(entry, compose_doc, path, errors):
    """Validate the optional per-input `services` audience list (D09, R06).

    Default (absent): the input reaches EVERY declared service. When the
    key is PRESENT it must be a unique non-empty list of DECLARED service
    names; an explicit null is rejected (schema parity), and dependent
    processing stops after a shape failure. R07: undeclared service names
    are never echoed into diagnostics.
    """
    if "services" not in entry:
        return None
    services = entry.get("services")
    declared = _service_names(compose_doc) if isinstance(compose_doc, dict) else []
    if not isinstance(services, list) or not services or not all(isinstance(s, str) for s in services):
        errors.append(ManifestError("%s.services must be a non-empty list of service names (explicit null is rejected)" % path))
        return None
    if len(services) != len(set(services)):
        errors.append(ManifestError("%s.services has duplicate entries" % path))
        return None
    for _name in services:
        if _name not in declared:
            errors.append(
                ManifestError(
                    "%s.services references a service that is not declared in the compose document "
                    "(name withheld)" % path
                )
            )
    return list(services)


def _validate_env_lists(allowed_envs, required_envs, manifest, compose_doc, errors):
    if not _check_type(allowed_envs, list, "manifest.allowed_envs", errors):
        allowed_envs = []
    if not _check_type(required_envs, list, "manifest.required_envs", errors):
        required_envs = []
    if len(allowed_envs) > MAX_ALLOWED_ENVS:
        errors.append(ManifestError("manifest.allowed_envs exceeds %d names" % MAX_ALLOWED_ENVS))
    if len(required_envs) > MAX_ALLOWED_ENVS:
        errors.append(ManifestError("manifest.required_envs exceeds %d names" % MAX_ALLOWED_ENVS))
    seen = {}
    for entry in allowed_envs:
        if not _check_type(entry, dict, "manifest.allowed_envs[]", errors):
            continue
        _object_keys(entry, {"name", "audience", "services"}, "manifest.allowed_envs[]", errors)
        name = entry.get("name")
        audience = entry.get("audience")
        if not (isinstance(name, str) and ENV_NAME_RE.match(name)):
            errors.append(ManifestError("manifest.allowed_envs has an entry whose name is not a valid env name"))
            continue
        if audience not in AUDIENCES:
            errors.append(
                ManifestError(
                    "manifest.allowed_envs[%s].audience must be 'workload' (workload appdata) or "
                    "'broker' (guest-root credential broker only)" % name
                )
            )
        _input_services_field(entry, compose_doc, "manifest.allowed_envs[%s]" % name, errors)
        if name in seen:
            errors.append(ManifestError("manifest.allowed_envs has duplicate %s" % name))
        seen[name] = audience
    required_seen = set()
    for name in required_envs:
        if not isinstance(name, str) or not ENV_NAME_RE.match(name):
            errors.append(ManifestError("manifest.required_envs has an entry that is not a valid env name"))
            continue
        if name in required_seen:
            errors.append(ManifestError("manifest.required_envs has duplicate %s" % name))
        required_seen.add(name)
        if name not in seen:
            errors.append(ManifestError("manifest.required_envs entry %s is not in allowed_envs" % name))

    reserved_used = {n for n, aud in seen.items() if aud == "workload" and _is_reserved_env(n)}
    env_policy = manifest.get("env_policy")
    if env_policy is not None:
        if not _check_type(env_policy, dict, "manifest.env_policy", errors):
            env_policy = {}
        _object_keys(env_policy, {"permit_reserved_envs"}, "manifest.env_policy", errors)
        if "permit_reserved_envs" not in env_policy:
            errors.append(
                ManifestError("manifest.env_policy.permit_reserved_envs is required (explicit, may be [])")
            )
    permit = env_policy.get("permit_reserved_envs", []) if isinstance(env_policy, dict) else []
    if not isinstance(permit, list) or not all(isinstance(p, str) for p in permit):
        errors.append(ManifestError("manifest.env_policy.permit_reserved_envs must be a list of strings"))
        permit = []
    for name in reserved_used:
        if name not in permit:
            errors.append(
                ManifestError(
                    "manifest.allowed_envs contains reserved workload name %s; it must be explicitly listed in "
                    "env_policy.permit_reserved_envs to be permitted" % name
                )
            )
    for name in permit:
        if not _is_reserved_env(name):
            # T05: a non-reserved entry is a REJECTED value (a permission-list
            # entry the contract refuses), never admitted metadata -- withheld.
            errors.append(
                ManifestError(
                    "manifest.env_policy.permit_reserved_envs has an entry that is not a "
                    "contract-reserved name (entry text withheld)"
                )
            )


def _validate_allowed_files(allowed_files, compose_doc, errors):
    if not _check_type(allowed_files, list, "manifest.allowed_files", errors):
        return
    if len(allowed_files) > MAX_FILE_SLOTS:
        errors.append(ManifestError("manifest.allowed_files exceeds %d slots" % MAX_FILE_SLOTS))
    slots = set()
    targets = set()
    segments = set()
    for entry in allowed_files:
        if not _check_type(entry, dict, "manifest.allowed_files[]", errors):
            continue
        _object_keys(entry, {"slot", "target", "max_bytes", "mode", "required", "audience", "services"}, "manifest.allowed_files[]", errors)
        slot = entry.get("slot")
        # C07/D05: hashable-guarded membership -- type check BEFORE any
        # set/dict membership so list-valued slots raise ContractError, not
        # TypeError.
        if not (isinstance(slot, str) and SLOT_RE.match(slot)):
            errors.append(ManifestError("manifest.allowed_files has an invalid slot name"))
            continue
        if slot in RESERVED_SLOT_NAMES:
            errors.append(ManifestError("manifest.allowed_files slot %s is a contract-reserved workspace slot" % slot))
            continue
        if slot in slots:
            errors.append(ManifestError("manifest.allowed_files has duplicate slot %s" % slot))
        slots.add(slot)
        _input_services_field(entry, compose_doc, "manifest.allowed_files[%s]" % slot, errors)
        target = entry.get("target")
        if isinstance(target, str):
            # Single path segment under /workspace/inputs/ -- no subdirectories,
            # no normalization aliases, no prefix overlaps between slots (F07).
            if not target.startswith(INPUTS_ROOT + "/") or not WORKSPACE_SEGMENT_RE.match(
                target[len(INPUTS_ROOT) + 1:]
            ):
                # T05: a rejected target is a rejected VALUE, not admitted
                # metadata -- its text is withheld (only shape-valid declared
                # targets are ever echoed, e.g. duplicate-target reports).
                errors.append(
                    ManifestError(
                        "manifest.allowed_files target must be %s/<single-segment> "
                        "(no subdirectories, no aliases); the rejected value is withheld" % INPUTS_ROOT
                    )
                )
            elif target in targets:
                errors.append(ManifestError("manifest.allowed_files has duplicate target %s" % target))
            else:
                segment = target[len(INPUTS_ROOT) + 1:]
                # D04: the segment IS the host source name; two slots sharing
                # a segment would share delivered bytes.
                if segment in segments:
                    errors.append(
                        ManifestError(
                            "manifest.allowed_files slot %s shares its target segment with another slot; "
                            "deliveries are keyed by target segment and must have distinct sources" % slot
                        )
                    )
                segments.add(segment)
            targets.add(target)
        else:
            errors.append(ManifestError("manifest.allowed_files target must be a string"))
        max_bytes = entry.get("max_bytes")
        if not (_is_int(max_bytes) and 1 <= max_bytes <= MAX_SLOT_BYTES):
            errors.append(ManifestError("manifest.allowed_files max_bytes must be an integer in [1, 1GiB]"))
        if entry.get("mode") not in ("ro", "rw"):
            errors.append(ManifestError("manifest.allowed_files mode must be 'ro' or 'rw'"))
        audience = entry.get("audience")
        if audience not in AUDIENCES:
            errors.append(ManifestError("manifest.allowed_files[%s].audience must be 'workload' or 'broker'" % slot))
        required = entry.get("required", False)
        if not isinstance(required, bool):
            errors.append(ManifestError("manifest.allowed_files[%s].required must be a boolean" % slot))


def _validate_runtime_inputs_decl(decl, allowed_envs, required_envs, compose_doc, errors):
    if not _check_type(decl, dict, "manifest.runtime_inputs", errors):
        return
    _object_keys(decl, {"env", "stdin", "user_config"}, "manifest.runtime_inputs", errors)

    env = decl.get("env")
    if _check_type(env, dict, "manifest.runtime_inputs.env", errors):
        _object_keys(env, {"mode"}, "manifest.runtime_inputs.env", errors)
        if env.get("mode") not in ("none", "inject"):
            errors.append(ManifestError("manifest.runtime_inputs.env.mode must be 'none' or 'inject'"))
        elif env.get("mode") == "none" and (allowed_envs or required_envs):
            errors.append(
                ManifestError(
                    "manifest.runtime_inputs.env.mode is 'none' but allowed_envs/required_envs are declared"
                )
            )

    for field, expected in (("stdin", ("none", "pipe")), ("user_config", ("none", "opaque-file"))):
        node = decl.get(field)
        if not _check_type(node, dict, "manifest.runtime_inputs.%s" % field, errors):
            continue
        allowed_keys = {"mode", "max_bytes"} if field == "stdin" else {"mode", "max_bytes", "target"}
        _object_keys(node, allowed_keys, "manifest.runtime_inputs.%s" % field, errors)
        mode = node.get("mode")
        if mode not in expected:
            errors.append(ManifestError("manifest.runtime_inputs.%s.mode must be one of %s" % (field, expected)))
            continue
        max_bytes = node.get("max_bytes")
        # T04 + U01: presence, type and value are enforced SEPARATELY, and an
        # absent bound is never compared numerically. An explicit null or a
        # boolean is a TYPE error (the schema says type:integer -- null is not
        # omission and false never compares equal to 0); value rules apply
        # only to validated integers. U01: an ACTIVE mode (stdin pipe /
        # user_config opaque-file) REQUIRES an explicitly declared bounded
        # max_bytes -- the input bound is a DECLARED limit, never an implicit
        # default -- so omission is a contract error there; mode 'none' keeps
        # the T04 rule (absence accepted, present value must be 0).
        max_bytes_typed = True
        if "max_bytes" in node and not _is_int(max_bytes):
            errors.append(
                ManifestError(
                    "manifest.runtime_inputs.%s.max_bytes must be an integer when present "
                    "(an explicit null is a type error, not omission; booleans are not integers)" % field
                )
            )
            max_bytes_typed = False
        if mode == "none":
            if max_bytes_typed and max_bytes not in (None, 0):
                errors.append(
                    ManifestError(
                        "manifest.runtime_inputs.%s.max_bytes must be 0 or omitted when mode is 'none'" % field
                    )
                )
            if field == "user_config" and "target" in node and node["target"] != DEFAULT_USER_CONFIG_TARGET:
                errors.append(
                    ManifestError(
                        "manifest.runtime_inputs.user_config.target must be %s when mode is 'none'"
                        % DEFAULT_USER_CONFIG_TARGET
                    )
                )
        elif "max_bytes" not in node:
            errors.append(
                ManifestError(
                    "manifest.runtime_inputs.%s.max_bytes is REQUIRED when mode is %r "
                    "(the input bound is an explicitly declared limit, never an implicit default)" % (field, mode)
                )
            )
        elif max_bytes_typed:
            if not (0 <= max_bytes <= MAX_STREAM_INPUT_BYTES):
                errors.append(
                    ManifestError(
                        "manifest.runtime_inputs.%s.max_bytes must be an integer in [0, 16MiB] "
                        "when mode is %r (0 delivers nothing)" % (field, mode)
                    )
                )
            if field == "user_config":
                target = node.get("target", DEFAULT_USER_CONFIG_TARGET)
                if not isinstance(target, str) or not target.startswith(INPUTS_ROOT + "/") or not WORKSPACE_SEGMENT_RE.match(
                    target[len(INPUTS_ROOT) + 1:]
                ):
                    errors.append(
                        ManifestError(
                            "manifest.runtime_inputs.user_config.target must be %s/<single-segment> "
                            "(opaque unmeasured bytes delivered verbatim into the inputs namespace)"
                            % INPUTS_ROOT
                        )
                    )


def _validate_network(network, runner, errors):
    if not _check_type(network, dict, "manifest.network", errors):
        return
    _object_keys(network, {"mode", "listen_ports"}, "manifest.network", errors)
    mode = network.get("mode")
    if mode not in ("none", "nat", "hostnet"):
        errors.append(ManifestError("manifest.network.mode must be 'none', 'nat' or 'hostnet'"))
    runtime = runner.get("container_runtime") if isinstance(runner, dict) else None
    runtime_name = runner.get("runtime_name") if isinstance(runner, dict) else None
    runsc_network = None
    if isinstance(runner, dict) and isinstance(runner.get("runsc"), dict):
        runsc_network = runner["runsc"].get("network")
    if mode == "hostnet":
        # hostnet is a DISTINCT network policy: the registered runsc-hostnet
        # runtime (gVisor network syscalls reach the container netns). Docker
        # topology stays compose-managed; this is never Docker host networking
        # (astra C04).
        if runtime != "runsc" or runsc_network != "host" or runtime_name != RUNTIME_RUNSC_HOSTNET:
            errors.append(
                ManifestError(
                    "manifest.network.mode 'hostnet' requires runner.container_runtime 'runsc' with "
                    "runner.runsc.network 'host' and runner.runtime_name 'runsc-hostnet' (it is not a "
                    "general mode and never enables Docker host networking)"
                )
            )
    elif runsc_network == "host" or runtime_name == RUNTIME_RUNSC_HOSTNET:
        errors.append(
            ManifestError(
                "manifest.runner.runsc.network 'host' (runtime runsc-hostnet) requires "
                "manifest.network.mode 'hostnet'"
            )
        )
    ports = network.get("listen_ports")
    if not _check_type(ports, list, "manifest.network.listen_ports", errors):
        return
    if len(ports) > MAX_LISTEN_PORTS:
        errors.append(ManifestError("manifest.network.listen_ports exceeds %d ports" % MAX_LISTEN_PORTS))
    seen = set()
    for port in ports:
        # D05: hashable-guarded membership.
        if not (_is_int(port) and 1 <= port <= 65535):
            errors.append(ManifestError("manifest.network.listen_ports has an entry that is not a TCP port"))
            continue
        if port in seen:
            errors.append(ManifestError("manifest.network.listen_ports has duplicate %d" % port))
        seen.add(port)
    if mode == "none" and ports:
        errors.append(ManifestError("manifest.network.mode 'none' forbids listen_ports"))
    if mode == "hostnet" and ports:
        errors.append(
            ManifestError(
                "manifest.network.mode 'hostnet' forbids listen_ports (the container's network syscalls "
                "use the container netns with gVisor mediating; compose-managed publishing does not apply)"
            )
        )


def _validate_outputs(outputs, compose_doc, errors):
    if not _check_type(outputs, dict, "manifest.outputs", errors):
        return
    _object_keys(outputs, {"capture", "artifacts", "completion_service"}, "manifest.outputs", errors)
    declared_services = _service_names(compose_doc) if isinstance(compose_doc, dict) else []
    completion = outputs.get("completion_service")
    completion_present = "completion_service" in outputs
    completion_ok = True
    # T04: presence, type and value are enforced SEPARATELY. Absence is the
    # only way to omit the completion service; an explicit null is a type
    # error (the schema says type:string), never "as if omitted".
    if completion_present and not isinstance(completion, str):
        errors.append(
            ManifestError(
                "manifest.outputs.completion_service must be a string naming a declared service "
                "when present (absence, not null, means undeclared; REQUIRED for multi-service "
                "manifests)"
            )
        )
        completion = None
        completion_ok = False
    if completion is not None:
        if not isinstance(completion, str) or completion not in declared_services:
            errors.append(
                ManifestError(
                    "manifest.outputs.completion_service must name a service declared in the compose "
                    "document (D09: multi-service completion behavior is explicit)"
                )
            )
    elif len(declared_services) > 1 and completion_ok:
        errors.append(
            ManifestError(
                "manifest.outputs.completion_service is REQUIRED for multi-service manifests (D09: the "
                "completion service's exit is the run's exit; first-exit races are resolved explicitly, "
                "not by accident)"
            )
        )
    capture = outputs.get("capture")
    if not _check_type(capture, list, "manifest.outputs.capture", errors):
        capture = []
    if (
        not all(isinstance(c, str) for c in capture)
        or len(capture) != len(set(capture))
        or any(c not in ("stdout", "stderr") for c in capture)
    ):
        errors.append(ManifestError("manifest.outputs.capture must be a subset of ['stdout','stderr']"))
    artifacts = outputs.get("artifacts")
    if not _check_type(artifacts, list, "manifest.outputs.artifacts", errors):
        return
    if len(artifacts) > MAX_ARTIFACTS:
        errors.append(ManifestError("manifest.outputs.artifacts exceeds %d entries" % MAX_ARTIFACTS))
    names = set()
    paths = set()
    for artifact in artifacts:
        if not _check_type(artifact, dict, "manifest.outputs.artifacts[]", errors):
            continue
        _object_keys(artifact, {"name", "path"}, "manifest.outputs.artifacts[]", errors)
        name = artifact.get("name")
        if not (isinstance(name, str) and NAME_RE.match(name)):
            errors.append(ManifestError("manifest.outputs.artifacts has an entry with an invalid name"))
            continue
        if name in names:
            errors.append(ManifestError("manifest.outputs.artifacts has duplicate name %s" % name))
        names.add(name)
        path = artifact.get("path")
        if isinstance(path, str):
            # Outputs may ONLY live in the artifacts output area (F07): runtime
            # inputs live under /workspace/inputs/ and can never be exported.
            if not path.startswith(ARTIFACTS_ROOT + "/") or not WORKSPACE_SEGMENT_RE.match(
                path[len(ARTIFACTS_ROOT) + 1:]
            ):
                # T05: a rejected artifact path is a rejected VALUE, not
                # admitted metadata -- its text is withheld (only shape-valid
                # declared paths are ever echoed, e.g. duplicate-path reports).
                errors.append(
                    ManifestError(
                        "manifest.outputs.artifacts path must be %s/<single-segment> (declared outputs "
                        "live only in the output area, never at runtime-input or state paths); "
                        "the rejected value is withheld" % ARTIFACTS_ROOT
                    )
                )
            elif path in paths:
                errors.append(ManifestError("manifest.outputs.artifacts has duplicate path %s" % path))
            paths.add(path)
        else:
            errors.append(ManifestError("manifest.outputs.artifacts path must be a string"))


def _validate_credentials(credentials, allowed_envs, allowed_files, errors):
    if credentials is None:
        return
    if not _check_type(credentials, dict, "manifest.credentials", errors):
        return
    _object_keys(
        credentials,
        {"required", "via", "adapter"},
        "manifest.credentials",
        errors,
    )
    if not isinstance(credentials.get("required"), bool):
        errors.append(ManifestError("manifest.credentials.required must be a boolean"))
    if credentials.get("via") != "runtime-input-broker":
        errors.append(
            ManifestError(
                "manifest.credentials.via must be 'runtime-input-broker' (credential import is an adapter "
                "over the general runtime-input API feeding the guest-root credential broker; there is no "
                "workload-visible credential channel)"
            )
        )
    adapter = credentials.get("adapter")
    if not _check_type(adapter, dict, "manifest.credentials.adapter", errors):
        return
    _object_keys(adapter, {"profile", "accepted_fields", "source", "provider_route"}, "manifest.credentials.adapter", errors)
    # E10: provider_route is a REQUIRED key (present but null for the
    # files-only profile). Omission used to be tolerated by the library while
    # the lowering indexed the absent key; now the field is explicit.
    if "provider_route" not in adapter:
        errors.append(
            ManifestError(
                "manifest.credentials.adapter.provider_route is REQUIRED (the exact measured route for "
                "an env-transport profile, literal null for the files-only profile); omission is rejected"
            )
        )
    # E10: broker-input service audiences must be CONSISTENT -- the sentinel
    # capability is injected into exactly the broker audience, so mixed
    # audiences across broker inputs would either leak the capability wider
    # than an input allows or starve a declared consumer. All broker-audience
    # entries must carry the same `services` list (or all leave it absent).
    # R06: a shape-failed services value (e.g. [[]] -- error recorded by the
    # audience validator) must never reach the tuple/set comparison; it maps
    # to the same "absent" key and dependent processing stops.
    def _audience_key(entry):
        services = entry.get("services")
        if services is None:
            return None
        if not isinstance(services, list) or not all(isinstance(s, str) for s in services):
            return "!invalid"
        return tuple(services)

    broker_entries = [
        e
        for e in (allowed_envs if isinstance(allowed_envs, list) else [])
        if isinstance(e, dict) and e.get("audience") == "broker"
    ] + [
        e
        for e in (allowed_files if isinstance(allowed_files, list) else [])
        if isinstance(e, dict) and e.get("audience") == "broker"
    ]
    broker_audiences = {_audience_key(e) for e in broker_entries}
    if len(broker_audiences) > 1:
        errors.append(
            ManifestError(
                "broker-audience inputs declare inconsistent services audiences; every broker-audience "
                "env/file entry must carry the same services list (or omit it), because the per-run "
                "sentinel capability is injected into exactly that audience"
            )
        )
    profile_name = adapter.get("profile")
    # D05: type-guard BEFORE dict membership (a list profile used to reach
    # unhashable dict membership and crash with TypeError).
    if not isinstance(profile_name, str) or profile_name not in ADAPTER_PROFILES:
        errors.append(
            ManifestError(
                "manifest.credentials.adapter.profile must be one of %s (frozen versioned adapter "
                "vocabularies; arbitrary field names are rejected)" % (sorted(ADAPTER_PROFILES),)
            )
        )
        return
    profile = ADAPTER_PROFILES[profile_name]
    fields = adapter.get("accepted_fields")
    if fields != list(profile["accepted_fields"]):
        errors.append(
            ManifestError(
                "manifest.credentials.adapter.accepted_fields must be exactly %s for adapter profile %s "
                "(the frozen field vocabulary; settings/hooks/MCP/provider overrides are rejected by policy)"
                % (list(profile["accepted_fields"]), profile_name)
            )
        )
    if profile_name in ("claude-api-key/1", "claude-subscription/1"):
        if adapter.get("source") != "explicit-caller-stdin-or-file":
            errors.append(
                ManifestError(
                    "manifest.credentials.adapter.source must be 'explicit-caller-stdin-or-file' (no discovery, "
                    "no reuse of developer/worker auth)"
                )
            )
        route = adapter.get("provider_route")
        if route != profile["provider_route"]:
            errors.append(
                ManifestError(
                    "manifest.credentials.adapter.provider_route must be the exact measured %s for adapter "
                    "profile %s (never an unmeasured runtime override)" % (profile["provider_route"], profile_name)
                )
            )
    else:
        # generic-broker-file/1: files only; no provider route, no env names.
        if adapter.get("source") != "explicit-caller-file":
            errors.append(
                ManifestError(
                    "manifest.credentials.adapter.source must be 'explicit-caller-file' for adapter "
                    "profile %s (broker files come from an explicit caller-owned file source only)" % profile_name
                )
            )
        if adapter.get("provider_route") is not None:
            errors.append(
                ManifestError(
                    "manifest.credentials.adapter.provider_route must be null for adapter profile %s "
                    "(the generic broker-file profile has no measured provider route; route policy is a "
                    "workload concern)" % profile_name
                )
            )
    # A credentials block implies broker-audience inputs; broker inputs imply
    # the block (so execution always knows a broker is required). Both env and
    # FILE broker inputs count (astra C03).
    broker_names = _broker_input_names(allowed_envs, allowed_files)
    if broker_names and credentials.get("required") is not True:
        errors.append(
            ManifestError(
                "manifest declares %d broker-audience input(s) but credentials.required is not true"
                % len(broker_names)
            )
        )
    if credentials.get("required") and not broker_names:
        errors.append(
            ManifestError(
                "manifest.credentials.required is true but no broker-audience names are declared in "
                "allowed_envs/allowed_files"
            )
        )
    # D07: profile/transport compatibility. claude-api-key/1 defines ONLY the
    # api_key -> ANTHROPIC_API_KEY env mapping and NO credential-file format:
    # broker-audience FILE slots are rejected under it (use
    # generic-broker-file/1, which is files-only).
    # claude-subscription/1 (proposed delta) is likewise ENV-ONLY
    # (claudeAiOauth -> CLAUDE_SUBSCRIPTION_OAUTH): the same env-only rule.
    if profile_name in ("claude-api-key/1", "claude-subscription/1"):
        broker_files = [
            entry.get("slot")
            for entry in (allowed_files if isinstance(allowed_files, list) else [])
            if isinstance(entry, dict) and entry.get("audience") == "broker" and isinstance(entry.get("slot"), str)
        ]
        if broker_files:
            errors.append(
                ManifestError(
                    "adapter profile %s defines only %s-to-%s env "
                    "transport and no credential-file format or conflict rules; %d broker-audience file "
                    "slot(s) are declared. Use adapter profile generic-broker-file/1 for credential FILES"
                    % (
                        profile_name,
                        profile["accepted_fields"][0],
                        profile["broker_env_names"][0],
                        len(broker_files),
                    )
                )
            )
        declared_broker_env = {
            entry.get("name")
            for entry in (allowed_envs if isinstance(allowed_envs, list) else [])
            if isinstance(entry, dict) and entry.get("audience") == "broker" and isinstance(entry.get("name"), str)
        }
        if credentials.get("required") and declared_broker_env and declared_broker_env != set(profile["broker_env_names"]):
            errors.append(
                ManifestError(
                    "broker-audience env names must be exactly %s for adapter profile %s"
                    % (list(profile["broker_env_names"]), profile_name)
                )
            )
    else:
        declared_broker_env = [
            entry.get("name")
            for entry in (allowed_envs if isinstance(allowed_envs, list) else [])
            if isinstance(entry, dict) and entry.get("audience") == "broker" and isinstance(entry.get("name"), str)
        ]
        if declared_broker_env:
            errors.append(
                ManifestError(
                    "adapter profile %s is files-only; %d broker-audience env name(s) are declared (use "
                    "claude-api-key/1 for env credential transport)" % (profile_name, len(declared_broker_env))
                )
            )


def _validate_limits(limits, errors):
    if limits is None:
        return
    if not _check_type(limits, dict, "manifest.limits", errors):
        return
    _object_keys(limits, {"timeout_s", "workspace_max_bytes", "output_max_bytes"}, "manifest.limits", errors)
    timeout = limits.get("timeout_s")
    # E07: explicit nulls are REJECTED, never treated as absent (one
    # consistent absent/null policy; a null limit used to pass validation and
    # later participate in a numeric comparison).
    if "timeout_s" in limits and timeout is None:
        errors.append(ManifestError("manifest.limits.timeout_s must be an integer when present (explicit null is rejected)"))
    elif timeout is not None and not (_is_int(timeout) and 1 <= timeout <= MAX_TIMEOUT_S):
        errors.append(ManifestError("manifest.limits.timeout_s must be an integer in [1, %d]" % MAX_TIMEOUT_S))
    for field, low in (("workspace_max_bytes", MIN_WORKSPACE_BYTES), ("output_max_bytes", MIN_WORKSPACE_BYTES)):
        value = limits.get(field)
        if field in limits and value is None:
            errors.append(ManifestError("manifest.limits.%s must be an integer when present (explicit null is rejected)" % field))
        elif value is not None and not (_is_int(value) and low <= value <= MAX_WORKSPACE_BYTES):
            errors.append(
                ManifestError("manifest.limits.%s must be an integer in [%d, %d]" % (field, low, MAX_WORKSPACE_BYTES))
            )
