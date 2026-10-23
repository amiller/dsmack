#!/usr/bin/env python3
"""Generate the EXTERNAL guest inputs for the in-guest runner runs -- bound to
the REBUILT bundle identity (S02), with the exact delivery channels the packed
workload disk carries (S01/S03).

Modes:
  --mode engineering (default): the two engineering app-compose manifests
    (greet-sh + pycompute, credential-free), their envelopes, and the external
    admission document, all bound to the --artifacts bundle identity.
  --mode product: the two REGENERATED product manifests (api + subscription;
    from --product-manifests, already rendered by render_product_manifests.py
    against the same --artifacts bundle) plus the per-manifest BROKER CHANNEL
    (broker/<name>/broker-config.json binding listen_port/workload_host/
    provider_route/ca_bundle/auth_mode -- derived from the manifest itself;
    NEVER a token, NEVER a credential: S03 requires the capability token to be
    freshly generated in-guest and the credential to be staged per-run by the
    demo harness, outside any artifact source or checksum inventory).

Both modes emit the channel directories the workload packer
(launch_vm_dstack_arm64.build_workload_disk) includes verbatim:
  manifests/ envelopes/ admission/ base-bundle/ images/ broker/

Manifest deltas vs the approved compose-runner lane's manifests are unchanged
from the prior freeze (guest compose/runc versions, no-limits variant option).
Every output is validated with the ACTUAL frozen contract library before this
script exits 0. Run AFTER promote_and_verify.sh.

Usage (run by BUILD.sh on the host with PYTHONPATH -> candidate contract lib):
  python3 make_guest_inputs.py --artifacts DIR --out DIR --candidate DIR \
      [--mode engineering|product] [--product-manifests DIR] [--no-limits] \
      [--render-out DIR]
"""
import argparse
import hashlib
import json
import os
import shutil
import sys

from dsmack_compose_contract import (
    compute_commitment,
    validate_manifest_bytes,
    validate_runtime_inputs_bytes,
)

GUEST_RUNC_SHA256 = "6a8bd8a019e7b10a8d30a9fa85656f795d5957ab7269e5579f438a065b753332"
GUEST_RUNC_VERSION = "1.1.15+ds1"
GUEST_COMPOSE_VERSION = "2.26.1-4"
MEASURED_GUEST_CA = "/etc/ssl/certs/ca-certificates.crt"
DEFAULT_BROKER_PORT = 5100
WORKLOAD_HOST = "172.17.0.1"  # guest dockerd default bridge gateway (workload-reachable)
# GIO09: the in-guest publisher serves the OCI layout read-only on this
# loopback endpoint (reconciled for BOTH Zed and Mini; NOT 10.0.2.2:5005).
OCI_LOOPBACK_PORT = 5005
# GIO09 (repair3): the CANONICAL harness repository name. The retained,
# independently-verified ARM64 OCI layout carries ``org.opencontainers.image.
# ref.name = "2.1.187-arm64"`` in its index, but the rendered product manifests,
# the built-artifacts lock (harness_image_ref_guest) and the ARM64 harness lock
# (portable_guest_reference) all require ``127.0.0.1:5005/dsmack-claude-harness
# @<D>``. The supervisor pre-pulls the repository the staged annotation names and
# the runner resolves the repository the manifests name; a mismatch makes
# identity.ensure_image fail closed (image-mismatch/image-unresolvable) even
# though the content digest D is identical. We NORMALIZE the staged index
# annotation to this one repository so the staged delivery, the supervisor
# pre-pull, the rendered product references and the runner resolution share the
# IDENTICAL repository-plus-digest identity -- WITHOUT changing the content
# digest D (only the top-level index annotation string changes; no blob is
# touched). This is the single source of truth shared with BUILD.sh HARNESS_NAME,
# verify_built_artifacts.HARNESS_IMAGE_NAME and render_product_manifests.
HARNESS_REPO_NAME = "dsmack-claude-harness"

# GIO09: use the MEASURED guest publisher's own verifier to validate a staged
# OCI layout, so the host never stages bytes the in-guest publisher would
# refuse (one source of truth for the layout admission).
_RC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "runner-content")
if _RC not in sys.path:
    sys.path.insert(0, _RC)
from dsmack_guest_io import closure, oci_publish  # noqa: E402


def stage_oci_layout(out, src_dir, repo_name=HARNESS_REPO_NAME):
    """GIO09: stage a CONTENT-ADDRESSED OCI image layout (index.json +
    blobs/sha256/<hex>) into the measured public ``oci-layout/`` channel, VERIFY
    it with the measured in-guest publisher's own verifier (real digest
    verification -- every manifest/config/layer blob must hash to its digest),
    and render the loopback DELIVERY refs the guest pulls BY DIGEST.

    GIO09 (repair3): the staged index annotation is NORMALIZED to the single
    canonical repository ``repo_name`` (dsmack-claude-harness) so the staged
    delivery, the supervisor pre-pull (DSMACK_OCI_REF), the rendered product
    manifests, the built-artifacts lock and the runner's ensure_image all use
    the IDENTICAL repository-plus-digest identity. ONLY the top-level index
    annotation string changes -- every blob (manifest/config/layers) is copied
    byte-for-byte and re-hashed, so the content digest D is preserved EXACTLY
    (fail closed if it ever changes). Returns the delivery dict."""
    dst = os.path.join(out, "oci-layout")
    os.makedirs(os.path.join(dst, "blobs", "sha256"), exist_ok=True)
    src_index = os.path.join(src_dir, "index.json")
    if not os.path.isfile(src_index):
        raise SystemExit("--oci-layout-src %s has no index.json" % src_dir)
    blobs_src = os.path.join(src_dir, "blobs", "sha256")
    if not os.path.isdir(blobs_src):
        raise SystemExit("--oci-layout-src %s has no blobs/sha256 dir" % src_dir)
    for fn in sorted(os.listdir(blobs_src)):
        sp = os.path.join(blobs_src, fn)
        if os.path.isfile(sp):
            shutil.copy(sp, os.path.join(dst, "blobs", "sha256", fn))

    # Normalize the index annotation to the canonical repository WITHOUT touching
    # any blob. The retained harness layout carries exactly one image manifest;
    # we rename ONLY its ref.name annotation and keep its digest/size/mediaType/
    # platform. Multiple differently-named manifests are ambiguous for a single
    # canonical repository and are rejected (fail closed) rather than guessed.
    with open(src_index, "rb") as fh:
        index = json.loads(fh.read())
    entries = index.get("manifests") or []
    if len(entries) != 1:
        raise SystemExit(
            "--oci-layout-src %s index has %d manifests; GIO09 canonical-name "
            "normalization requires exactly one harness manifest" % (src_dir, len(entries)))
    src_digest = entries[0].get("digest")
    annotations = dict(entries[0].get("annotations") or {})
    original_ref_name = annotations.get("org.opencontainers.image.ref.name")
    annotations["org.opencontainers.image.ref.name"] = repo_name
    entries[0]["annotations"] = annotations
    with open(os.path.join(dst, "index.json"), "w") as fh:
        json.dump(index, fh, separators=(",", ":"), sort_keys=True)

    # Real digest verification of the STAGED bytes (fail closed on any mismatch).
    model = oci_publish.verify_layout(dst)
    # The content digest D MUST be unchanged by the rename (only the index
    # annotation differs); the staged repository MUST be exactly the canonical
    # one. Both are hard invariants, not best-effort.
    if src_digest not in model["manifests"]:
        raise SystemExit("GIO09: annotation normalization changed the content digest "
                         "(staged manifests=%r, expected %s)" % (list(model["manifests"]), src_digest))
    if set(model["names"]) != {repo_name} or model["names"].get(repo_name) != src_digest:
        raise SystemExit("GIO09: staged layout does not resolve to the single canonical "
                         "repository %r@%s (got names=%r)" % (repo_name, src_digest, model["names"]))
    refs = {name: "127.0.0.1:%d/%s@%s" % (OCI_LOOPBACK_PORT, name, digest)
            for name, digest in sorted(model["names"].items())}
    delivery = {
        "schema": "dsmack.oci-delivery/1",
        "endpoint": "127.0.0.1:%d" % OCI_LOOPBACK_PORT,
        "verified_manifests": len(model["manifests"]),
        "verified_blobs": len(model["blobs"]),
        "refs": refs,
        "harness_repository": repo_name,
        "normalized_from_ref_name": original_ref_name,
        "content_digest_preserved": src_digest,
        "note": ("Served read-only by the MEASURED in-guest publisher "
                 "(dsmack_guest_io.oci_publish); the supervisor serves it BEFORE and "
                 "THROUGHOUT the runner phase (publisher kept alive until the runner "
                 "resolves), pre-pulls this exact repository@digest, and the guest pulls "
                 "BY DIGEST so RepoDigest D is preserved on both Zed and Mini. The index "
                 "annotation was normalized to the canonical repository without changing "
                 "the content digest D. docker-load (images/*.tar) is a transitional "
                 "fallback only, NOT portable delivery."),
    }
    write_json(os.path.join(dst, "DELIVERY.json"), delivery)
    print("oci-layout staged + VERIFIED: %d manifest(s), %d blob(s); repo=%s (from ref.name=%r); refs=%s"
          % (len(model["manifests"]), len(model["blobs"]), repo_name, original_ref_name, sorted(refs.values())))
    return delivery


def sha256f(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def bundle_facts(art):
    digest = open(os.path.join(art, "digest.txt")).read().strip()
    md = json.loads(open(os.path.join(art, "metadata.json"), "rb").read())
    entries = {}
    for line in open(os.path.join(art, "sha256sum.txt")).read().splitlines():
        h, name = line.split("  ", 1)
        entries[name] = h
    am = json.load(open(os.path.join(art, "artifact-manifest.json")))
    return {
        "os_image_hash": digest,
        "cmdline": md["cmdline"],
        "kernel_sha256": entries["Image"],
        "initrd_sha256": entries["initramfs.cpio.gz"],
        "rootfs_sha256": entries["rootfs.squashfs.verity"],
        "metadata_sha256": sha256f(os.path.join(art, "metadata.json")),
        "verity_root_hash": am["verity"]["root_hash"],
    }


def new_manifest(prior_path, facts, no_limits=False):
    doc = json.load(open(prior_path))
    if no_limits:
        # The guest dstack kernel has no swap cgroup accounting: a memory limit
        # makes dockerd set MemorySwap and runc create then fails on the absent
        # memory.swap.max (measured try3). Re-issued external workload WITHOUT
        # deploy.resources limits (the contract subset makes deploy optional).
        inner = json.loads(doc["docker_compose_file"])
        for svc in inner["services"].values():
            svc.pop("deploy", None)
        doc["docker_compose_file"] = json.dumps(inner, sort_keys=True, separators=(",", ":"))
    doc["base_vm"] = {
        "architecture": "aarch64",
        "cmdline": facts["cmdline"],
        "initrd_sha256": facts["initrd_sha256"],
        "kernel_sha256": facts["kernel_sha256"],
        "memory_mb": 4096,
        "metadata_sha256": facts["metadata_sha256"],
        "os_image_hash": facts["os_image_hash"],
        "rootfs_sha256": facts["rootfs_sha256"],
        "vcpus": 1,
        "verity_root_hash": facts["verity_root_hash"],
    }
    doc["runner"]["compose_tool"]["version"] = GUEST_COMPOSE_VERSION
    doc["runner"]["runtime_version"] = GUEST_RUNC_VERSION
    for comp in doc["runner"]["runtime_closure"]["components"]:
        if comp["name"] == "runc":
            comp["sha256"] = GUEST_RUNC_SHA256
            comp["path"] = "/usr/bin/runc"
    return doc


def write_json(path, doc):
    with open(path, "w") as f:
        json.dump(doc, f, indent=1, sort_keys=True)
        f.write("\n")


#: I/O-continuity schema id for a published commitment declaration (the frozen
#: v4 commitment object/scope only -- NO raw private values).
COMMITMENT_DECLARATION_SCHEMA = "dsmack.runtime-input-commitment-declaration/1"


def emit_commitment_declaration(out, name, env, manifest_sha256):
    """Publish a SELECTED commitment declaration onto the measured vdc.

    This carries ONLY the frozen v4 commitment object (alg + normalized scope +
    inputs_sha256) that the caller DELIBERATELY committed to, plus the bound
    manifest_sha256. It does NOT carry env/files/stdin/user_config VALUES; those
    stay in the envelope on the UNMEASURED vde. Uncommitted envelopes publish
    NOTHING here (no content hash, no cache id)."""
    commitments = env.get("commitments")
    if not commitments:
        return None
    declaration = {
        "schema": COMMITMENT_DECLARATION_SCHEMA,
        "manifest_sha256": manifest_sha256,
        "commitment": {
            "alg": commitments["alg"],
            "scope": commitments.get("scope"),
            "inputs_sha256": commitments["inputs_sha256"],
        },
    }
    path = os.path.join(out, "commitments", "%s.commitment.json" % name)
    write_json(path, declaration)
    print("commitment declaration %s: alg=%s inputs_sha256=%s (public; no raw values)"
          % (name, commitments["alg"], commitments["inputs_sha256"]))
    return path


def emit_common(out, art, facts, workload_id, oci_layout_src=None):
    # PUBLIC (vdc) channels + PRIVATE (vde) channels. The packer routes
    # envelopes/ and broker/ to the UNMEASURED vde; everything else to vdc.
    for sub in ("manifests", "envelopes", "admission", "base-bundle", "images",
                "broker", "commitments", "oci-layout"):
        os.makedirs(os.path.join(out, sub), exist_ok=True)
    for name in ("Image", "initramfs.cpio.gz", "metadata.json", "rootfs.squashfs.verity", "sha256sum.txt"):
        shutil.copy(os.path.join(art, name), os.path.join(out, "base-bundle", name))
    write_json(os.path.join(out, "admission", "base-admission.json"), {
        "admission_version": 1,
        "allowed_os_image_hashes": [facts["os_image_hash"]],
    })
    with open(os.path.join(out, "WORKLOAD"), "w") as f:
        f.write(workload_id + "\n")
    with open(os.path.join(out, "images", "README"), "w") as f:
        f.write("TRANSITIONAL docker-load channel ONLY (supervisor loads *.tar before the runner).\n"
                "GIO09: docker load does NOT establish a RepoDigest, so this path cannot satisfy\n"
                "real pull-by-digest / RepoDigest verification. It is a fallback for the current\n"
                "Zed path only and is NOT the product delivery.\n")
    # GIO09: the PORTABLE OFFLINE, DIGEST-PRESERVING OCI delivery. The harness
    # image travels as a content-addressed OCI image layout under oci-layout/
    # (index.json + blobs/sha256/<hex>) on the measured vdc. In-guest, the
    # MEASURED publisher (dsmack_guest_io.oci_publish, invoked by the supervisor)
    # verifies it under bounds and serves it read-only on loopback, and the
    # guest dockerd pulls BY DIGEST so the RepoDigest is preserved. The endpoint
    # is reconciled for BOTH Zed and Mini: 127.0.0.1:<port> served by the
    # measured guest publisher -- NOT the Zed-specific 10.0.2.2:5005 registry and
    # NOT any public upload. The real content-addressed blobs + the exact child
    # digests are produced by the later REAL build and dropped in here; this lane
    # stages the channel and wires the publisher lifecycle.
    if oci_layout_src:
        # GIO09: stage + VERIFY the real content-addressed OCI layout and render
        # the loopback delivery refs (connected staging -> repository mapping).
        stage_oci_layout(out, oci_layout_src)
    else:
        with open(os.path.join(out, "oci-layout", "README"), "w") as f:
            f.write("Portable offline digest-preserving OCI layout channel (GIO09).\n"
                    "Stage a verified layout with make_guest_inputs.py --oci-layout-src DIR:\n"
                    "  oci-layout/index.json\n"
                    "  oci-layout/blobs/sha256/<hex>   (manifests, config, layers)\n"
                    "  oci-layout/DELIVERY.json        (rendered 127.0.0.1:5005/<name>@<D> refs)\n"
                    "The measured in-guest publisher serves this read-only on 127.0.0.1:5005 and the\n"
                    "guest pulls 127.0.0.1:5005/<name>@sha256:<D>, preserving RepoDigest D on\n"
                    "BOTH Zed and Mini. docker load (images/*.tar) is a transitional fallback only.\n")


def emit_engineering(args, facts):
    cand_runner = os.path.join(args.candidate, "compose_runner")
    manifest_paths = {}
    for name in ("greet-sh", "pycompute"):
        doc = new_manifest(os.path.join(cand_runner, "manifests", "%s.app-compose.json" % name),
                           facts, args.no_limits)
        out_path = os.path.join(args.out, "manifests", "%s.app-compose.json" % name)
        write_json(out_path, doc)
        raw = open(out_path, "rb").read()
        manifest, summary = validate_manifest_bytes(raw)  # fail-closed pre-gate
        manifest_paths[name] = out_path
        print("manifest %s: sha256=%s (validated by the frozen contract library)"
              % (name, summary["manifest_sha256"]))

        env_src = os.path.join(cand_runner, "envelopes")
        env_name = "%s.envelope.json" % name
        cand_env = os.path.join(env_src, env_name)
        if not os.path.isfile(cand_env):
            cand_env = os.path.join(env_src, "pycompute.committed.envelope.json")
        env = json.load(open(cand_env))
        env["manifest_sha256"] = summary["manifest_sha256"]
        if "commitments" in env:
            digest = compute_commitment(env, manifest)
            env["commitments"]["inputs_sha256"] = digest
        env_out = os.path.join(args.out, "envelopes", env_name)
        write_json(env_out, env)
        validate_runtime_inputs_bytes(raw, open(env_out, "rb").read())  # fail-closed
        print("envelope %s: validated against new manifest bytes (commitment recomputed)" % env_name)
        # I/O-continuity: the envelope itself is PRIVATE (vde); if it carries a
        # commitment the caller opted into, publish the commitment DECLARATION
        # (object/scope only) on the measured vdc.
        emit_commitment_declaration(args.out, name, env, summary["manifest_sha256"])
    return manifest_paths


def emit_product(args, facts):
    """S01/S03: product manifests + the broker CHANNEL (config only -- the
    credential and the capability token are NEVER artifacts)."""
    if not args.product_manifests:
        raise SystemExit("--mode product requires --product-manifests (the regenerated dir)")
    manifest_paths = {}
    port = DEFAULT_BROKER_PORT
    for fn in sorted(os.listdir(args.product_manifests)):
        if not fn.endswith(".app-compose.json"):
            continue
        src = os.path.join(args.product_manifests, fn)
        raw = open(src, "rb").read()
        manifest, summary = validate_manifest_bytes(raw)  # fail-closed
        bv = manifest.get("base_vm") or {}
        if bv.get("os_image_hash") != facts["os_image_hash"]:
            raise SystemExit("product manifest %s is not bound to the rebuilt bundle %s; run "
                             "render_product_manifests.py against the same --artifacts first"
                             % (fn, facts["os_image_hash"]))
        name = fn[:-len(".app-compose.json")]
        dst = os.path.join(args.out, "manifests", fn)
        shutil.copy(src, dst)
        manifest_paths[name] = dst
        print("product manifest %s: sha256=%s" % (name, summary["manifest_sha256"]))
        creds = manifest.get("credentials") or {}
        if creds.get("required"):
            adapter = creds.get("adapter") or {}
            profile = adapter.get("profile", "")
            mode = {"claude-subscription/1": "claude-subscription",
                    "claude-api-key/1": "api-key"}.get(profile)
            if mode is None:
                raise SystemExit("product manifest %s requires an unsupported credential profile %r"
                                 % (fn, profile))
            bdir = os.path.join(args.out, "broker", name)
            os.makedirs(bdir, exist_ok=True)
            write_json(os.path.join(bdir, "broker-config.json"), {
                "listen_port": port,
                "workload_host": WORKLOAD_HOST,
                "provider_route": adapter.get("provider_route"),
                "ca_bundle": MEASURED_GUEST_CA,
                "auth_mode": mode,
            })
            with open(os.path.join(bdir, "README"), "w") as f:
                f.write("Stage the per-run credential as %s/credential (0600) IMMEDIATELY before\n"
                        "launch. It is intentionally absent from this artifact source and from the\n"
                        "packed SHA256SUMS inventory (S03); the per-run capability token is generated\n"
                        "in-guest by the supervisor, never staged.\n" % bdir)
            port += 1
            print("broker channel %s: port=%d route=%s mode=%s (config only, no secret)"
                  % (name, port - 1, adapter.get("provider_route"), mode))
    return manifest_paths


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifacts", required=True, help="REBUILT promoted bundle dir")
    ap.add_argument("--out", required=True, help="runner-inputs output dir")
    ap.add_argument("--candidate", required=True,
                    help="frozen contract10-candidate dir (prior manifests/envelopes)")
    ap.add_argument("--mode", choices=("engineering", "product"), default="engineering")
    ap.add_argument("--product-manifests", default=None,
                    help="dir of manifests regenerated by render_product_manifests.py")
    ap.add_argument("--no-limits", action="store_true")
    ap.add_argument("--render-out", default=None,
                    help="also render the lowered compose files (host-side parser qualification)")
    ap.add_argument("--workload-id", default=None)
    ap.add_argument("--oci-layout-src", default=None,
                    help="GIO09: a verified content-addressed OCI image layout dir (index.json + "
                         "blobs/sha256/<hex>) to stage into the measured oci-layout/ channel and "
                         "render loopback 127.0.0.1:5005 delivery refs; e.g. the approved arm64 "
                         "harness layout (arm64-harness-critical/oci-layout-v1)")
    context_mode = ap.add_mutually_exclusive_group(required=True)
    context_mode.add_argument("--closure-context", help="Exact externally pinned caller context JSON; preserved byte for byte")
    context_mode.add_argument("--template-only", action="store_true", help="Build-time template only: no attempt context; cannot pass guest closure admission")
    args = ap.parse_args()
    context_raw = None
    if args.closure_context:
        # Read exact caller bytes once, bounded and without any alias traversal.
        parts = os.path.abspath(args.closure_context).split(os.sep)
        fd = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in parts[1:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            source = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            with os.fdopen(source, 'rb') as stream:
                import stat
                st = os.fstat(stream.fileno())
                if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > 8192:
                    raise SystemExit("closure context type/size/alias refused")
                context_raw = stream.read(8193)
                if len(context_raw) != st.st_size or stream.read(1):
                    raise SystemExit("closure context changed while reading")
        finally:
            os.close(fd)

    facts = bundle_facts(args.artifacts)
    print("bundle: os_image_hash=%s verity_root=%s" % (facts["os_image_hash"], facts["verity_root_hash"]))
    workload_id = args.workload_id or (
        "runner-join-two-manifests-plainrunc" if args.mode == "engineering"
        else "product-claude-coding-task")
    emit_common(args.out, args.artifacts, facts, workload_id, oci_layout_src=args.oci_layout_src)
    if args.mode == "engineering":
        manifest_paths = emit_engineering(args, facts)
    else:
        manifest_paths = emit_product(args, facts)

    if context_raw is not None:
        # Validate against FINAL emitted manifests before publishing or packing.
        # Never generate a different attempt_id or reserialize caller bytes.
        closure.context_bytes(context_raw, os.path.join(args.out, "manifests"))
        context_dir = os.path.join(args.out, "closure-context")
        os.mkdir(context_dir, 0o700)
        with open(os.path.join(context_dir, "context.json"), "xb") as stream:
            stream.write(context_raw)
            stream.flush()
            os.fsync(stream.fileno())
    else:
        print("TEMPLATE ONLY: no caller context; guest closure admission will refuse launch")

    if args.render_out:
        from dsmack_compose_contract import lower, render_compose_file
        os.makedirs(args.render_out, exist_ok=True)
        for name, path in manifest_paths.items():
            raw = open(path, "rb").read()
            manifest, summary = validate_manifest_bytes(raw)
            lowered = lower(
                manifest, summary["manifest_sha256"],
                daemon_endpoint="unix:///run/rootcontrol/docker.sock",
                run_id="parsertest",
                workspace_host_dir="/run/dsmack-runs/parsertest",
                runtime_available=("io.containerd.runc.v2", "runc"),
                broker=({"endpoint": "http://%s:%d/t" % (WORKLOAD_HOST, DEFAULT_BROKER_PORT)}
                        if (manifest.get("credentials") or {}).get("required") else None),
            )
            workload_env = {}
            env_path = os.path.join(args.out, "envelopes", "%s.envelope.json" % name)
            if os.path.isfile(env_path):
                env = json.load(open(env_path))
                workload_env = {k: v for k, v in (env.get("env") or {}).items()}
            text = render_compose_file(manifest, lowered, workload_env=workload_env)
            data = text if isinstance(text, bytes) else text.encode("utf-8")
            with open(os.path.join(args.render_out, "%s.compose.json" % name), "wb") as f:
                f.write(data)
            print("rendered compose for %s -> %s (%d bytes)" % (name, args.render_out, len(data)))

    print("guest inputs written to", args.out)


if __name__ == "__main__":
    main()
