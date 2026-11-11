"""Deterministic lowering from a validated manifest to Docker Compose (v4).

The measured manifest is the ONLY input that shapes execution. This module
is a PURE function: manifest (+ explicit operational arguments) ->
deterministic execution configuration. It performs NO I/O and never talks
to Docker; it defines exactly what the implementing runner must do. The
generated configuration uses REAL, pinned-Docker-Compose-valid syntax and
is validated against the actual `docker compose config` parser in tests
(astra C02).

v4 changes (contract3-review):

  D04 - every file/user_config mount source is keyed by the TARGET SEGMENT
        (the single host source file under <workspace>/inputs/), so the
        mounted source and the materialized bytes are always the same file;
        omitted OPTIONAL slots and omitted user_config have explicit
        materialize-empty entries.
  D09 - the bounded multi-service subset lowers per service: every service
        carries the runtime key, user, read_only root, its audience-filtered
        mounts and env; state/artifacts/shared are shared rw directory
        binds; the completion service's exit is the run's exit, observed by
        DETACHED startup (`compose up --detach --quiet-pull`) plus the
        bounded `ps --all` completion wait (see _compose_argv/_lifecycle).
        stdin pipe remains a single-service form (validated upstream).
  D06 - generated configuration privacy is explicit: rendered env VALUES
        live only in the per-run private workspace and are destroyed at
        cleanup (see CONTRACT.json semantics.privacy_private_outputs).

Frozen rules unchanged from v3: explicit daemon endpoint (the ONLY
selection mechanism), allowlist-only control environment with isolated
per-run dirs, long-syntax volumes with create_host_path:false,
long-syntax loopback ports, network_mode none only for network 'none',
hostnet NEVER Docker host networking, fixed nonroot user, array-only
argv, '$'-free generated configuration (caller values escaped '$$').
"""

import ipaddress

from .canonical import canonical_bytes, load_json_bytes
from .errors import LoweringError
from .manifest import (
    ARTIFACTS_ROOT,
    DSTACK_SOCK_VOLUME,
    DSMACK_RUNTIME_VOLUMES,
    DEFAULT_USER_CONFIG_TARGET,
    INPUTS_ROOT,
    RUN_ID_RE,
    SHARED_ROOT,
    STATE_ROOT,
    _platform_string,
)

CONTROL_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
WORKLOAD_UID = 1000
WORKLOAD_GID = 1000
AGENT_SOCKET_DIR = "/run/dsmack-agent"
# The supervisor writes the guest resolver here. Docker's embedded DNS (127.0.0.11) needs xt DNAT/SNAT,
# which the guest kernel lacks (CONFIG_NETFILTER_XT_NAT unset), so networked containers use it directly.
GUEST_RESOLV_CONF = "/run/resolv-guest.conf"


def _target_segment(target):
    prefix = INPUTS_ROOT + "/"
    if isinstance(target, str) and target.startswith(prefix):
        return target[len(prefix):]
    raise LoweringError("internal: input target is not under %s" % INPUTS_ROOT)


def lower(
    manifest,
    manifest_sha256,
    *,
    daemon_endpoint=None,
    run_id=None,
    workspace_host_dir=None,
    runtime_available=("runc",),
):
    """Lower a validated manifest dict + exact manifest digest to the
    deterministic execution configuration. Raises LoweringError on any
    fail-closed condition."""
    if not isinstance(daemon_endpoint, str) or not daemon_endpoint:
        raise LoweringError(
            "daemon_endpoint is REQUIRED and explicit; lowering never discovers or defaults a Docker "
            "endpoint (no ambient host configuration, no contexts)"
        )
    if not isinstance(run_id, str) or not RUN_ID_RE.match(run_id):
        raise LoweringError(
            "run_id is REQUIRED (matching ^[a-z0-9][a-z0-9-]{0,62}$): the per-run identifier keeps "
            "project names and workspaces isolated across repeated or concurrent runs"
        )

    project_name = "dsmack-%s-%s-%s" % (manifest["name"], run_id, manifest_sha256[:12])
    if workspace_host_dir is None:
        workspace_host_dir = "/var/lib/dsmack/workspaces/%s-%s" % (run_id, manifest_sha256[:12])

    runtime_name = manifest["runner"]["runtime_name"]
    if runtime_name not in runtime_available:
        raise LoweringError(
            "registered runtime %r was requested by the measured manifest but is not available; the "
            "contract REQUIRES failing closed -- no silent fallback to another runtime" % runtime_name
        )

    compose_doc = _compose_doc(manifest)
    service_names = [name for name in compose_doc["services"] if isinstance(name, str)]
    completion_service = manifest["outputs"].get("completion_service") or (service_names[0] if service_names else None)
    # D09: per-service mounts (audience- and service-filtered, keyed by the
    # target segment so source bytes and mounted file are the same file).
    services_lowered = {}
    for service_name in service_names:
        mounts = _service_mounts(manifest, service_name, workspace_host_dir)
        services_lowered[service_name] = {"mounts": mounts}

    from .security import require_selection
    security_profiles = {}
    for service_name in service_names:
        try:
            security_profiles[service_name] = require_selection(compose_doc["services"][service_name], manifest)
        except (ValueError, OSError) as exc:
            raise LoweringError("security profile refused: %s" % exc) from None
    network_mode, ports = _lower_network(manifest)
    compose_argv = _compose_argv(manifest, project_name, completion_service)
    lifecycle = _lifecycle(manifest, completion_service)

    uc = manifest["runtime_inputs"]["user_config"]
    uc_target = uc.get("target", DEFAULT_USER_CONFIG_TARGET)

    return {
        "security_profiles": security_profiles,
        "argv_by_service": _lower_argv_by_service(manifest),
        "compose_argv": compose_argv,
        "completion_service": completion_service,
        "lifecycle": lifecycle,
        "control_env": {
            "COMPOSE_PROJECT_DIRECTORY": "{isolated_project_dir}",
            "DOCKER_CONFIG": "{isolated_docker_config_dir}",
            "DOCKER_HOST": daemon_endpoint,
            "PATH": CONTROL_PATH,
        },
        "control_env_policy": (
            "allowlist-only: the compose control process receives EXACTLY control_env and nothing "
            "from the ambient environment; DOCKER_CONFIG and the compose project directory are "
            "isolated EMPTY per-run directories (no .env, no override files, no contexts)"
        ),
        "daemon_endpoint": daemon_endpoint,
        "generated_config_privacy": (
            "PRIVATE: the rendered compose file contains runtime env VALUES and lives only in the "
            "per-run private workspace (mode 0600/0700); it is never written to public logs, receipts "
            "or evidence; parser diagnostics that may embed it are captured privately; it is destroyed "
            "with the workspace at cleanup. Public export is an explicit separate action."
        ),
        "input_delivery": {
            "env": "workload-audience env values are merged into the generated compose environment by "
            "render_compose_file per the entry's service audience",
            "files": "each declared workload slot is a SINGLE-FILE bind <workspace>/inputs/<target-segment> "
            "-> target, keyed by the TARGET segment so mounted source and delivered bytes are the same "
            "file; bytes are materialized before start and never rewritten; omitted OPTIONAL slots are "
            "materialized as EMPTY regular files (delivery_plan marks materialize_empty); broker-audience "
            "slots are never materialized",
            "stdin": "mode none: compose up attaches no stdin (closed). mode pipe (single-service only): "
            "compose run -i -T; the runner writes at most the validated max_bytes then CLOSES stdin (EOF); "
            "larger envelopes are rejected at validation, never truncated",
            "user_config": "user_config bytes are delivered verbatim (opaque, unparsed) to %s via a "
            "single-file bind keyed by its target segment; an omitted opaque user_config is materialized "
            "as an EMPTY regular file (explicit delivery_plan entry)" % uc_target
            if uc.get("mode") == "opaque-file"
            else "user_config mode is 'none'",
            "lifetime": "all workload inputs exist only inside the private per-run workspace and are "
            "destroyed at cleanup (lstat walk, no symlink following); no input is exported by default",
        },
        "mounts_by_service": services_lowered,
        "network_mode": network_mode,
        "egress_nftables": render_egress_rules(manifest),
        "platform": _platform_string(manifest["image_platform"]),
        "ports": ports,
        "project_name": project_name,
        "read_only_rootfs": True,
        "requires_runtime": runtime_name,
        "runtime_closure_duty": (
            "prelaunch (in-guest supervisor, before dockerd): verify the executable/bundle bytes at "
            "runner.runtime_closure components' paths against their pinned sha256, verify the runtime "
            "registration path and EXACT arguments against registration_args, then verify live daemon "
            "state; mismatched bytes or arguments fail closed (same-name wrong-binary/wrong-args is a "
            "rejection, D10)"
        ),
        "run_id": run_id,
        # R05: harness verification happens AFTER mount planning, against the
        # RESOLVED executable -- canonical-path manifest rejection alone does
        # not bind the executed bytes.
        "harness_resolution_duty": (
            "after mount planning and BEFORE launch: resolve manifest.harness.path within the "
            "image rootfs; EVERY path component must be image-contained (no symlink may point into "
            "or through any mount target, and any symlinked component at all is a launch "
            "rejection); the resolved final regular file's sha256 must equal harness.sha256; a "
            "path that resolves into /workspace/inputs, /workspace/state, /workspace/artifacts or "
            "/workspace/shared (or any declared slot/user_config target) fails closed. The "
            "designated completion service must be the one launched with these verified bytes"
        ),
        "workspace_host_dir": workspace_host_dir,
        "workspace_ownership": "private per-run directory of the runner's unprivileged workload uid "
        "(%d:%d); enforced in the generated config via the service user key; cleanup walks it without "
        "following symlinks (lstat-based), then removes it" % (WORKLOAD_UID, WORKLOAD_GID),
        "workload_uid_gid": [WORKLOAD_UID, WORKLOAD_GID],
    }


def _input_reaches(entry, service_name, service_names):
    """D09 audience filter: an input reaches a service per its `services`
    list; absent/empty means every declared service."""
    targets = entry.get("services")
    if not targets:
        return True
    return service_name in targets


def _service_mounts(manifest, service_name, workspace_host_dir):
    """Per-service mount list (D04: keyed by target segment; D09: filtered)."""
    service_names = list(_compose_doc(manifest)["services"])
    mounts = []
    for entry in manifest["allowed_files"]:
        if entry.get("audience") == "broker":
            # C03: broker materialization is SEPARATE; never a workload mount.
            continue
        if not _input_reaches(entry, service_name, service_names):
            continue
        segment = _target_segment(entry["target"])
        mounts.append(_file_mount(segment, entry["target"], workspace_host_dir, entry["mode"] == "ro"))
    uc = manifest["runtime_inputs"]["user_config"]
    if uc.get("mode") == "opaque-file":
        uc_target = uc.get("target", DEFAULT_USER_CONFIG_TARGET)
        mounts.append(_file_mount(_target_segment(uc_target), uc_target, workspace_host_dir, True))
    # Shared ABI directories: state (workload-owned per-run state), artifacts
    # (the single output area) and, for multi-service manifests, a controlled
    # shared directory mounted into every service (D09 shared-storage example
    # support; bounded by the workspace cap).
    mounts.append(
        {"create_host_path": False, "mode": "rw", "slot": "state", "source": "%s/state" % workspace_host_dir, "target": STATE_ROOT, "type": "bind"}
    )
    mounts.append(
        {"create_host_path": False, "mode": "rw", "slot": "artifacts", "source": "%s/artifacts" % workspace_host_dir, "target": ARTIFACTS_ROOT, "type": "bind"}
    )
    if len(service_names) > 1:
        mounts.append(
            {"create_host_path": False, "mode": "rw", "slot": "shared", "source": "%s/shared" % workspace_host_dir, "target": SHARED_ROOT, "type": "bind"}
        )
    if DSTACK_SOCK_VOLUME in _compose_doc(manifest)["services"][service_name].get("volumes", []):
        from .security import AGENT_PROFILE, AGENT_SOCKET_TARGET
        profile = _compose_doc(manifest)["services"][service_name].get("security_profile")
        mounts.append(
            {"create_host_path": False, "mode": "ro", "slot": "dstack", "source": "%s/%s.sock" % (AGENT_SOCKET_DIR, service_name), "target": AGENT_SOCKET_TARGET if profile == AGENT_PROFILE else "/var/run/dstack.sock", "type": "bind"}
        )
    for volume in _compose_doc(manifest)["services"][service_name].get("volumes", []):
        if volume in DSMACK_RUNTIME_VOLUMES:
            mounts.append(
                {"create_host_path": False, "mode": volume.rsplit(":", 1)[1], "slot": "runtime",
                 "source": "/run/dsmack", "target": "/run/dsmack", "type": "bind"}
            )
    if manifest["network"]["mode"] != "none":
        mounts.append(
            {"create_host_path": False, "mode": "ro", "slot": "resolv", "source": GUEST_RESOLV_CONF, "target": "/etc/resolv.conf", "type": "bind"}
        )
    return mounts


def _file_mount(segment, target, workspace_host_dir, read_only):
    """Single-file bind mount entry (C05: file slots are byte files, one
    unambiguous form; C03: workload-audience slots only -- callers filter).
    The source is keyed by the TARGET segment (D04)."""
    return {
        "kind": "file",
        "mode": "ro" if read_only else "rw",
        "segment": segment,
        "source": "%s/inputs/%s" % (workspace_host_dir, segment),
        "target": target,
        "type": "bind",
    }


LOCAL_REGISTRY = "127.0.0.1:5005"


def local_image_ref(image):
    """Where the guest pulls a pinned image: its loopback publisher, whatever registry the
    compose names. The pull is by digest, so the repository name carries no trust, and a
    compose naming ``ghcr.io/x@sha256:D`` runs unchanged on dstack and here."""
    host, _, rest = image.partition("/")
    if rest and ("." in host or ":" in host or host == "localhost"):
        image = rest
    return LOCAL_REGISTRY + "/" + image


SERVICE_BRIDGE = "dsmack0"
SERVICE_SUBNET = ipaddress.ip_network("10.213.0.0/24")


def service_networks(manifest):
    """With network.service_egress, every service joins an internal bridge (dsmack0) at a fixed
    address, and a service whose egress (its service_egress entry, else network.egress) is non-empty
    also gets its own bridge dsme<i>, its only default route. None without service_egress."""
    per_service = manifest["network"].get("service_egress")
    if per_service is None:
        return None
    services = sorted(_compose_doc(manifest)["services"])
    out = {}
    for i, name in enumerate(services):
        egress = per_service.get(name, manifest["network"].get("egress", []))
        out[name] = {"address": str(SERVICE_SUBNET[10 + i]), "bridge": "dsme%d" % i if egress else None, "egress": egress}
    return out


def _accept_rules(egress, match=""):
    rules = []
    for entry in egress:
        net = ipaddress.ip_network(entry["destination"], strict=True)
        rules.append("  %s%s daddr %s %s dport %d counter accept" % (
            match, "ip" if net.version == 4 else "ip6", net, entry["protocol"], entry["port"]))
    return rules


def render_egress_rules(manifest):
    """Guest-wide policy, installed atomically before any workload starts.

    Guest processes match network.egress. Forwarded container
    packets match network.egress too, or, with network.service_egress, only the
    tuples of the service whose bridge they enter on, plus service-to-service
    traffic on the internal bridge. Input accepts only loopback and replies,
    which also bypass those tuples. An inet table also denies IPv6.
    """
    services = service_networks(manifest)
    rules = [
        "add table inet dsmack_egress",
        "delete table inet dsmack_egress",
        "table inet dsmack_egress {",
    ]
    for hook in ("input", "output", "forward"):
        rules += [
            " chain %s {" % hook,
            "  type filter hook %s priority -10; policy drop;" % hook,
        ]
        if hook != "forward":
            rules.append('  %sifname "lo" accept' % hook[0])
        rules.append("  ct direction reply ct state established,related accept")
        if hook == "output" or (hook == "forward" and services is None):
            rules += _accept_rules(manifest["network"].get("egress", []))
        elif hook == "forward":
            rules.append('  iifname "%s" oifname "%s" accept' % (SERVICE_BRIDGE, SERVICE_BRIDGE))
            for s in services.values():
                if s["bridge"]:
                    rules += _accept_rules(s["egress"], 'iifname "%s" ' % s["bridge"])
        rules += ["  counter drop", " }"]
    return "\n".join(rules + ["}", ""])


def _lower_network(manifest):
    mode = manifest["network"]["mode"]
    ports = manifest["network"]["listen_ports"]
    if mode == "none":
        return "none", []
    # nat AND hostnet: compose-managed default bridge topology (C04: hostnet
    # is a gVisor runtime policy, never Docker host networking).
    if mode == "hostnet":
        return None, []
    return None, [
        {"host_ip": "127.0.0.1", "protocol": "tcp", "published": p, "target": p} for p in ports
    ]


def _compose_argv(manifest, project_name, completion_service):
    """The TWO frozen compose start forms (C05), race-free lifecycle (E04).

    stdin mode pipe (single-service only, validated upstream) uses
    `compose run -i -T`; every other manifest starts ALL services DETACHED
    (`compose up --detach --quiet-pull`). The runsc-qualification first-exit
    race is closed structurally: nothing aborts on a producer's exit. The
    runner then follows the frozen lifecycle in `lifecycle` -- wait for the
    DESIGNATED completion service only, stop remaining writers, inspect every
    service BEFORE removal, collect stable outputs, then down. The run's exit
    is the completion service's exit code; an auxiliary service that exits
    nonzero first is RECORDED (observed.services[].exit_code), never aborts
    the completion service, and never masks its exit.
    """
    doc = _compose_doc(manifest)
    service_name = next(iter(doc["services"]))
    base = [
        "docker",
        "compose",
        "--project-name",
        project_name,
        "--project-directory",
        "{isolated_project_dir}",
        "-f",
        "{generated_compose_file}",
    ]
    if manifest["runtime_inputs"]["stdin"]["mode"] == "pipe":
        return base + [
            "run",
            "--quiet-pull",
            "-i",
            "-T",
            "--name",
            "%s-main" % project_name,
            service_name,
        ]
    return base + ["up", "--detach", "--quiet-pull"]


def _lifecycle(manifest, completion_service):
    """E04: the bounded multi-service/execution lifecycle (frozen duties).

    Writers are stopped and every container is inspected BEFORE removal, so
    receipt observations and artifact collection see stable state; streams
    are attributed per service (the completion service owns the run's
    stdout/stderr capture; auxiliary streams are runner-private).
    """
    doc = _compose_doc(manifest)
    multi = len(doc["services"]) > 1
    return {
        "start": "docker compose up --detach --quiet-pull (all services; stdin pipe single-service uses compose run instead)",
        "wait": (
            "bounded wait on the DESIGNATED completion service %s only, bounded by limits.timeout_s "
            "(expiry is cancel reason 'timeout'): poll `docker compose ps --all --format json -- %s` "
            "-- --all is REQUIRED (the pinned Compose v2.35.1 ps defaults to running-only, so an "
            "exited container would VANISH from the default listing and the wait would never "
            "observe it). Each poll parses the container's State: status 'exited' ends the wait; a "
            "MISSING container is 'starting' until first seen and a container that is never created "
            "within the bound fails closed; status 'dead' (or a start error) fails closed "
            "immediately. NO --abort-on-container-exit: an auxiliary/producer exiting first "
            "(success or failure) never stops the completion service" % (completion_service, completion_service)
        )
        if multi
        else (
            "wait for the single service's exit, bounded by limits.timeout_s (cancel reason 'timeout'); "
            "observe the stopped container through `docker compose ps --all --format json` (never the "
            "running-only default) or `docker container wait`"
        ),
        "auxiliary_failure": (
            "record every auxiliary service's ACTUAL exit in observed.services[].exit_code (each "
            "container is inspected after the wait; a missing exit observation is a receipt "
            "rejection); do NOT abort the completion service and do NOT mask its exit code; the "
            "run's status follows the completion service only"
        )
        if multi
        else None,
        "stop_writers": "docker compose stop (stop every remaining writer; containers are preserved)",
        "inspect": (
            "docker inspect EVERY service container BEFORE removal: State.Status, State.ExitCode, "
            "State.OOMKilled -- the receipt's per-service observations come from this stable state"
        ),
        "collect": "collect declared artifacts and captured streams AFTER stop (no writer can mutate them mid-collection); outputs.stdout/stderr are the COMPLETION service's streams (stream ownership); auxiliary service streams stay runner-private and are never receipt-recorded",
        "teardown": "docker compose down only AFTER inspect+collect; then workspace cleanup (lstat walk)",
    }


def _lower_argv_by_service(manifest):
    """Per-service exact argv: entrypoint + command concatenation (C02)."""
    doc = _compose_doc(manifest)
    out = {}
    for name, service in doc["services"].items():
        if isinstance(service, dict):
            out[name] = list(service.get("entrypoint", [])) + list(service.get("command", []))
    return out


def _compose_doc(manifest):
    return load_json_bytes(manifest["docker_compose_file"].encode("utf-8"), "compose")


def render_compose_file(manifest, lowered, workload_env=None):
    """Render the generated compose file text (deterministic JSON).

    workload_env: ONLY validated WORKLOAD-audience env name/value pairs.
    Broker-audience names are refused here (they must never reach the
    workload). Values reach a service per the entry's service audience (D09).

    Literal-dollar handling: the manifest subset contains no '$' anywhere
    (rejected at validation), but RUNTIME env values are unmeasured caller
    data and may contain '$'. Compose would interpolate such values against
    the control environment, so every caller-supplied value is ESCAPED
    ('$' -> '$$') when rendered; compose treats '$$' as a literal dollar.
    The final safety assertion strips '$$' escapes and requires no bare '$'
    to remain -- interpolation is impossible by construction.
    """
    doc = _compose_doc(manifest)
    allowed_workload = {
        entry["name"]: entry.get("services")
        for entry in manifest["allowed_envs"]
        if isinstance(entry, dict) and entry.get("audience") == "workload"
    }
    all_services = list(doc["services"])

    gen_services = {}
    for service_name in all_services:
        service = doc["services"][service_name]
        env = dict(service.get("environment", {}))
        static_names = set(env)
        for name, value in sorted((workload_env or {}).items()):
            audiences = allowed_workload.get(name, set())
            if not audiences or service_name in audiences:
                if name not in allowed_workload:
                    raise LoweringError(
                        "refusing to render env (name withheld): not a workload-audience name in "
                        "allowed_envs (broker-audience values never reach a workload, undeclared "
                        "names are rejected)"
                    )
                if name in static_names:
                    raise LoweringError(
                        "refusing to render env (name withheld): collides with the compose static "
                        "environment"
                    )
                if not isinstance(value, str):
                    raise LoweringError("refusing to render env (name withheld): value must be a string")
                env[name] = value.replace("$", "$$")  # literal-dollar escape

        volumes_out = []
        for mount in lowered["mounts_by_service"][service_name]["mounts"]:
            volumes_out.append(
                {
                    "bind": {"create_host_path": False, "propagation": "rprivate"},
                    "read_only": mount["mode"] == "ro",
                    "source": mount["source"],
                    "target": mount["target"],
                    "type": "bind",
                }
            )

        gen_service = {
            "environment": env,
            "image": local_image_ref(service["image"]),
            "read_only": True,
            "runtime": lowered["requires_runtime"],
            "user": "%d:%d" % (WORKLOAD_UID, WORKLOAD_GID),
            "volumes": volumes_out,
        }
        if lowered.get("security_profiles", {}).get(service_name):
            from .security import preset_fields
            try:
                gen_service.update(preset_fields(lowered["security_profiles"][service_name]))
            except (ValueError, OSError) as exc:
                raise LoweringError("browser policy refused: %s" % exc) from None
        if lowered["network_mode"] is not None:
            gen_service["network_mode"] = lowered["network_mode"]
        if lowered["platform"]:
            gen_service["platform"] = lowered["platform"]
        if "working_dir" in service:
            gen_service["working_dir"] = service["working_dir"]
        if "entrypoint" in service:
            gen_service["entrypoint"] = service["entrypoint"]
        if "command" in service:
            gen_service["command"] = service["command"]
        if "deploy" in service:
            gen_service["deploy"] = service["deploy"]
        if lowered["ports"]:
            gen_service["ports"] = lowered["ports"]
        gen_services[service_name] = gen_service

    generated = {"services": gen_services}
    networks = service_networks(manifest)
    if networks is not None:
        generated["networks"] = {"default": {"internal": True, "driver_opts": {"com.docker.network.bridge.name": SERVICE_BRIDGE},
                                             "ipam": {"config": [{"subnet": str(SERVICE_SUBNET)}]}}}
        hosts = ["%s:%s" % (name, s["address"]) for name, s in networks.items()]
        for name, s in networks.items():
            gen_services[name]["extra_hosts"] = hosts
            gen_services[name]["networks"] = {"default": {"ipv4_address": s["address"]}}
            if s["bridge"]:
                gen_services[name]["networks"][s["bridge"]] = {}
                generated["networks"][s["bridge"]] = {"driver_opts": {"com.docker.network.bridge.name": s["bridge"]}}
    text_bytes = canonical_bytes(generated)
    if b"$" in text_bytes.replace(b"$$", b""):
        raise LoweringError(
            "generated compose configuration contains an unescaped '$'; interpolation must be "
            "impossible by construction"
        )
    return text_bytes.decode("utf-8")
