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
  D07 - the sentinel ABI is a per-run lifecycle: a fresh per-run bearer
        token path, readiness gating, measured-route-only restriction,
        credential binding to the run, and teardown; the lifecycle contract
        is emitted in the lowered config for the runner to implement. The
        manifest subset already rejects broker + network 'none'.
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
SENTINEL_ENV_NAME = "DSMACK_SENTINEL_ENDPOINT"
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
    broker=None,
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

    requires_broker = bool(manifest.get("credentials", {}).get("required"))
    if requires_broker and not (isinstance(broker, dict) and isinstance(broker.get("endpoint"), str) and broker["endpoint"]):
        raise LoweringError(
            "manifest.credentials.required is true but no credential broker endpoint is available; "
            "execution fails closed (broker-audience inputs are never handed to the workload directly)"
        )
    # E10: the adapter dict is validated to carry provider_route EXPLICITLY
    # (required key; null for the files-only profile) so lowering never
    # indexes an absent key.
    adapter_route = None
    if requires_broker:
        adapter = manifest.get("credentials", {}).get("adapter", {})
        if "provider_route" not in adapter:
            raise LoweringError("manifest.credentials.adapter.provider_route is REQUIRED (validated upstream; fail closed)")
        adapter_route = adapter["provider_route"]

    compose_doc = _compose_doc(manifest)
    service_names = [name for name in compose_doc["services"] if isinstance(name, str)]
    completion_service = manifest["outputs"].get("completion_service") or (service_names[0] if service_names else None)
    # E10: the sentinel capability is injected ONLY into the broker audience
    # (the consistent services list every broker-audience input declares; all
    # services when none declares one).
    broker_capability_services = _broker_capability_services(manifest, service_names)

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
        "broker": None
        if not requires_broker
        else {
            "endpoint": broker["endpoint"],
            "provider_route": adapter_route,
        },
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
            "render_compose_file per the entry's service audience; broker-audience values go ONLY to "
            "the credential broker",
            "files": "each declared workload slot is a SINGLE-FILE bind <workspace>/inputs/<target-segment> "
            "-> target, keyed by the TARGET segment so mounted source and delivered bytes are the same "
            "file; bytes are materialized before start and never rewritten; omitted OPTIONAL slots are "
            "materialized as EMPTY regular files (delivery_plan marks materialize_empty); broker-audience "
            "slots are materialized only into the broker's own store, never under the workload workspace",
            "stdin": "mode none: compose up attaches no stdin (closed). mode pipe (single-service only): "
            "compose run -i -T; the runner writes at most the validated max_bytes then CLOSES stdin (EOF); "
            "larger envelopes are rejected at validation, never truncated",
            "user_config": "user_config bytes are delivered verbatim (opaque, unparsed) to %s via a "
            "single-file bind keyed by its target segment; an omitted opaque user_config is materialized "
            "as an EMPTY regular file (explicit delivery_plan entry)" % uc_target
            if uc.get("mode") == "opaque-file"
            else "user_config mode is 'none'",
            "lifetime": "all workload inputs exist only inside the private per-run workspace and are "
            "destroyed at cleanup (lstat walk, no symlink following); broker inputs are destroyed with "
            "the broker's per-run store; no input is exported by default",
        },
        "mounts_by_service": services_lowered,
        "network_mode": network_mode,
        "egress_nftables": render_egress_rules(manifest),
        "platform": _platform_string(manifest["image_platform"]),
        "ports": ports,
        "project_name": project_name,
        "read_only_rootfs": True,
        "requires_broker": requires_broker,
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
        "sentinel": None
        if not requires_broker
        else {
            "env_name": SENTINEL_ENV_NAME,
            "upstream_provider_route": adapter_route,
            "capability_services": broker_capability_services,
            "lifecycle": {
                "creation": "per-run: the broker creates a fresh listener on the compose bridge gateway "
                "bound to this run_id, with a FRESH per-run bearer token embedded in the endpoint path; "
                "tokens from previous runs are invalid by construction",
                "readiness": "the runner polls readiness BEFORE start and fails closed on timeout; the "
                "sentinel env is injected only after readiness, ONLY into capability_services",
                "authorization": "every request must carry this run's bearer token; the broker binds the "
                "run's credential to run_id and rejects unknown/stale/expired tokens (cross-run access "
                "rejected; negative test duty)",
                "route_restrictions": (
                    "provider-proxy form (env-transport profiles): the ONLY upstream ORIGIN is the "
                    "measured provider_route (client paths map to it per endpoint_construction); "
                    "any other host is refused and only '/v1/<path>' client paths are accepted; TLS "
                    "verification toward the provider stays ON. Files-only form (generic-broker-file/1, "
                    "provider_route null): NO provider route is proxied at all -- the ONLY route class "
                    "is the bounded broker-file disclosure route (see disclosure_policy), and a "
                    "service may fetch only slots whose declared audience includes it"
                ),
                # R09: exact, frozen endpoint construction per profile. The
                # bearer token is path segment 1; the per-profile route space
                # is fixed and unambiguous.
                "endpoint_construction": {
                    "token_form": "the fresh per-run bearer token is the FIRST path segment: http://<gateway-ip>:<port>/<token>...",
                    # T03: the endpoint ends AT THE TOKEN -- the pinned client
                    # (Anthropic SDK / Claude Code) appends '/v1/<path>' to its
                    # base URL, so a base ending in '/v1' would double the
                    # prefix ('/v1/v1/...' upstream). Gateway authentication is
                    # the run-local token capability, never the provider key.
                    # S07: a CONCRETE client-path -> upstream-path mapping.
                    # provider_route (e.g. https://api.anthropic.com) is the
                    # MEASURED UPSTREAM ORIGIN -- never a path appended to the
                    # endpoint. The upstream request URL is the upstream
                    # origin + the client path after the token segment,
                    # verbatim.
                    "env_transport_profiles": (
                        "endpoint = http://<gateway-ip>:<port>/<token> (ends AT the token; NO /v1 "
                        "suffix). PINNED CLIENT CONFIGURATION (Anthropic SDK / Claude Code): the "
                        "workload process is started with ANTHROPIC_BASE_URL = this endpoint and "
                        "ANTHROPIC_API_KEY = this run's token (path segment 1) -- a RUN-LOCAL "
                        "capability, never the provider key; the client then requests "
                        "<endpoint>/v1/<path> per the pinned client's own URL construction. "
                        "CONCRETE PROXY MAPPING: upstream_url = provider_route + <client path after "
                        "'/<token>'>. The client path after the token segment is forwarded VERBATIM "
                        "to the measured upstream ORIGIN. Examples: client POST "
                        "http://10.0.2.15:8100/tok-abc/v1/messages -> upstream POST "
                        "https://api.anthropic.com/v1/messages ; client GET "
                        "http://10.0.2.15:8100/tok-abc/v1/models -> upstream GET "
                        "https://api.anthropic.com/v1/models. GATEWAY AUTHENTICATION: the token "
                        "(path segment 1) is the per-run capability the broker resolves to this "
                        "run; the token itself is REMOVED from the forwarded path (never upstream), "
                        "and the proxy REPLACES every client credential header (x-api-key, "
                        "Authorization) upstream-side with the run's own broker-held credential -- "
                        "client headers are never forwarded and the provider key never exists "
                        "workload-side. provider_route "
                        "(https://api.anthropic.com) is the measured upstream ORIGIN only -- it is "
                        "never appended to the endpoint, and client request paths are never embedded "
                        "in it. Allowed client paths after the token under env-transport are "
                        "exactly '/v1/<path>' (any method); any other path shape is 404"
                    ),
                    "files_only_profile": (
                        "endpoint = http://<gateway-ip>:<port>/<token> (NO /v1); the ONLY request form "
                        "is GET http://<gateway-ip>:<port>/<token>/broker-file/<slot> returning that "
                        "slot's caller-supplied bytes bounded by the slot max_bytes; any other path or "
                        "method is 404/405"
                    ),
                    "authorization": (
                        "every request must carry this run's bearer token as path segment 1; the "
                        "broker resolves the token to the run and enforces the slot audience "
                        "(files-only) or the measured route (env-transport); unknown/stale/expired "
                        "tokens are refused"
                    ),
                },
                # R09: the files-only profile is a DISTINCT MEASURED
                # DISCLOSURE/transport policy, named as such: broker-audience
                # FILE slot bytes are readable by the declared audience
                # services through this bounded route. It is not a secrecy
                # waiver for anything else: claude-api-key/1 credentials stay
                # env/proxy-only and never reach workloads; non-audience
                # services never see broker bytes; sources stay explicitly
                # caller-owned with no discovery/reuse.
                "disclosure_policy": (
                    "dsmack.broker-file-disclosure/1 (generic-broker-file/1 only): the declared "
                    "audience services of a broker-audience FILE slot retrieve that slot's EXACT "
                    "caller-supplied bytes via the frozen GET <endpoint>/broker-file/<slot> route, "
                    "bounded by the slot max_bytes, per-run token-bound, GET-only, teardown-bound. "
                    "This is a measured, audience-scoped transport for declared caller files -- NOT "
                    "credential discovery or reuse, and NOT applicable to claude-api-key/1 (whose "
                    "credentials never reach workloads). Any secrecy claim outside this named "
                    "policy (workload-env secrecy, provider secrecy, cross-audience secrecy) is "
                    "unchanged"
                ),
                # S07: the credential-binding rule is explicitly
                # PROFILE-SPECIFIC -- a blanket "never exposed to the
                # workload" contradicts the files-only profile's measured
                # file-disclosure route.
                "credential_binding": (
                    "PROFILE-SPECIFIC. env-transport profiles (claude-api-key/1): the run's provider "
                    "credential lives ONLY in the broker's per-run store bound to this run_id and is "
                    "NEVER exposed to the workload directly -- workloads reach the provider only "
                    "through the token-bound proxy above, the broker injects the credential "
                    "upstream-side, and no workload-readable copy exists. files-only profile "
                    "(generic-broker-file/1): broker-audience FILE slot bytes ARE disclosed to their "
                    "DECLARED AUDIENCE services, but ONLY through the measured "
                    "dsmack.broker-file-disclosure/1 route (see disclosure_policy) -- never through "
                    "any other path, never to non-audience services, never across runs. ALL "
                    "profiles: broker-audience inputs are associated with this run_id only, and "
                    "credential sourcing stays explicitly caller-owned (no discovery, no reuse)"
                ),
                "teardown": "after workload exit (any status): listener closed, per-run store and tokens "
                "destroyed, then workspace cleanup; post-teardown requests fail closed",
            },
            "transport": (
                "workload-reachable TCP endpoint on the compose bridge gateway; the runner resolves "
                "the gateway after network creation and passes the concrete URL to "
                "render_compose_file; resolution failure fails closed. Endpoint construction is "
                "FROZEN per profile in endpoint_construction (env-transport: "
                "http://<gateway-ip>:<port>/<token> -- ending AT the token; the pinned client appends "
                "/v1/<path> -- with the concrete client-path-to-upstream "
                "mapping and run-local token authentication; files-only: http://<gateway-ip>:<port>/<token> "
                "with the single GET <token>/broker-file/<slot> route). This endpoint is DISTINCT "
                "from the root-only control/credential socket and exposes only the route class "
                "allowed by the adapter profile"
            ),
        },
        "workspace_host_dir": workspace_host_dir,
        "workspace_ownership": "private per-run directory of the runner's unprivileged workload uid "
        "(%d:%d); enforced in the generated config via the service user key; cleanup walks it without "
        "following symlinks (lstat-based), then removes it" % (WORKLOAD_UID, WORKLOAD_GID),
        "workload_uid_gid": [WORKLOAD_UID, WORKLOAD_GID],
    }


def _broker_capability_services(manifest, service_names):
    """E10: the services that receive the sentinel capability.

    Exactly the broker audience: the (validated-consistent) `services` list
    every broker-audience input declares, defaulting to every declared
    service when no broker input restricts its audience. R06: a shape-failed
    services value (e.g. [[]]; the validation error was already recorded)
    must never reach the set intersection -- it is treated as unrestricted
    here and validation never reaches lowering.
    """
    audiences = set()
    for entry in manifest.get("allowed_envs", []) if isinstance(manifest.get("allowed_envs"), list) else []:
        if isinstance(entry, dict) and entry.get("audience") == "broker":
            services = entry.get("services")
            audiences.update(services if isinstance(services, list) and all(isinstance(s, str) for s in services) else service_names)
    for entry in manifest.get("allowed_files", []) if isinstance(manifest.get("allowed_files"), list) else []:
        if isinstance(entry, dict) and entry.get("audience") == "broker":
            services = entry.get("services")
            audiences.update(services if isinstance(services, list) and all(isinstance(s, str) for s in services) else service_names)
    return sorted(audiences & set(service_names))


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
        mounts.append(
            {"create_host_path": False, "mode": "ro", "slot": "dstack", "source": "%s/%s.sock" % (AGENT_SOCKET_DIR, service_name), "target": "/var/run/dstack.sock", "type": "bind"}
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


def render_egress_rules(manifest):
    """Guest-wide policy, installed atomically before any workload starts.

    Both forwarded container packets and guest processes (including brokers)
    must match the measured destination tuples. Only loopback and replies to
    inbound connections bypass those tuples. An inet table also denies IPv6.
    """
    rules = [
        "add table inet dsmack_egress",
        "delete table inet dsmack_egress",
        "table inet dsmack_egress {",
    ]
    for hook in ("output", "forward"):
        rules += [
            " chain %s {" % hook,
            "  type filter hook %s priority -10; policy drop;" % hook,
        ]
        if hook == "output":
            rules.append('  oifname "lo" accept')
        rules.append("  ct direction reply ct state established,related accept")
        for entry in manifest["network"].get("egress", []):
            net = ipaddress.ip_network(entry["destination"], strict=True)
            rules.append("  %s daddr %s %s dport %d counter accept" % (
                "ip" if net.version == 4 else "ip6", net, entry["protocol"], entry["port"]))
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
        "teardown": "docker compose down only AFTER inspect+collect; then workspace cleanup (lstat walk) and sentinel teardown per the sentinel lifecycle",
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


def render_compose_file(manifest, lowered, workload_env=None, sentinel_endpoint=None):
    """Render the generated compose file text (deterministic JSON).

    workload_env: ONLY validated WORKLOAD-audience env name/value pairs.
    Broker-audience names are refused here (they must never reach the
    workload). Values reach a service per the entry's service audience (D09).

    sentinel_endpoint: REQUIRED when the lowered config requires a broker:
    the concrete workload-reachable per-run sentinel URL resolved by the
    runner from the bridge gateway after readiness, built exactly per the
    frozen endpoint_construction for the profile -- BOTH profile forms end AT
    the token: http://<gateway-ip>:<port>/<token> (env-transport: the pinned
    client appends /v1/<path> to this base URL; files-only: the broker-file
    disclosure route appends /broker-file/<slot>). It is injected as the
    runner-owned sentinel env ONLY into the broker capability audience
    (lowered["sentinel"]["capability_services"], E10); no other service
    sees it and no other sentinel path exists.

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

    if lowered["sentinel"] is not None:
        if not isinstance(sentinel_endpoint, str) or not sentinel_endpoint or "$" in sentinel_endpoint:
            raise LoweringError(
                "sentinel_endpoint is REQUIRED when the manifest requires a credential broker: the "
                "runner-resolved workload-reachable per-run sentinel URL (resolution failure fails closed)"
            )

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
                        "allowed_envs (broker-audience values go to the credential broker, undeclared "
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

        if lowered["sentinel"] is not None:
            # E10: the sentinel capability reaches ONLY the broker audience.
            if service_name in lowered["sentinel"]["capability_services"]:
                sentinel_name = lowered["sentinel"]["env_name"]
                if sentinel_name in static_names:
                    raise LoweringError("refusing to render the sentinel env: collides with the compose static environment")
                env[sentinel_name] = sentinel_endpoint

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
                gen_service.update(preset_fields())
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
    text_bytes = canonical_bytes(generated)
    if b"$" in text_bytes.replace(b"$$", b""):
        raise LoweringError(
            "generated compose configuration contains an unescaped '$'; interpolation must be "
            "impossible by construction"
        )
    return text_bytes.decode("utf-8")
