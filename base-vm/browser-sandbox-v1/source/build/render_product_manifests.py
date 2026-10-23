#!/usr/bin/env python3
"""GATED build helper (S01/S02): regenerate the product app-compose manifests
from the REBUILT artifacts -- the full identity chain, not only wrapper/image
strings.

frozen-review-repair2 S02 rejected the previous version of this tool because it
changed wrapper/image references only: the manifests' base_vm block (and hence
every receipt's admitted identity) still named the stale 46c4bcc9… bundle. This
version, run in the GATED build (BUILD.sh) after the two-leg rebuild has minted
the new bundle and the harness image digest, rewrites each product manifest so
that:

  * base_vm is REGENERATED from the rebuilt bundle facts (os_image_hash,
    verbatim metadata cmdline, kernel/initrd/rootfs/metadata sha256s, verity
    root hash, declared 1 vCPU / 4096 MiB) -- receipts produced under these
    manifests can only ever admit the REBUILT bundle;
  * every service image reference `127.0.0.1:5005/dsmack-claude-harness@sha256:…`
    is rewritten to the GUEST-REACHABLE digest reference
    `127.0.0.1:5005/dsmack-claude-harness@sha256:<D'>`. Delivery design
    (GIO09, reconciled across the CROSS-LANE-VERIFIED-FINDINGS single endpoint):
    the measured ARM64 OCI layout travels INTO the guest as the public
    `oci-layout/` channel, and the in-guest supervisor serves it read-only on
    the loopback publisher `127.0.0.1:5005` BEFORE the runner (bounded
    readiness). The guest daemon (docker.io, classic image store) populates
    RepoDigests ONLY on a registry pull, so `ensure_image`'s fail-closed
    RepoDigests check is satisfied by an exact-digest pull from that in-guest
    loopback publisher. The pull is BY DIGEST, which dockerd verifies
    cryptographically; the required explicit policy change
    ("insecure-registries": ["127.0.0.1:5005"]) lives in the MEASURED profile
    input docker-daemon.json baked into the rootfs. No slirp 10.0.2.2:5005, no
    host Docker; the digest check is never weakened -- the pin IS the digest;
  * harness.sha256 becomes the REPAIRED wrapper's sha256 (api vs subscription
    chosen by the manifest's harness binary name).

Each output is validated with validate_manifest_bytes + lower() (fail closed on
any schema/lowering error). This tool performs NO build, NO boot, NO credential
access; it is a deterministic byte transform of the frozen templates plus the
measured rebuilt-bundle facts.
"""
import argparse
import hashlib
import json
import os
import re
import sys

_THIS = os.path.dirname(os.path.abspath(__file__))
# candidate/dstack-runner-join/source/build/ -> candidate/
_CANDIDATE = os.path.dirname(os.path.dirname(os.path.dirname(_THIS)))
sys.path.insert(0, os.path.join(_CANDIDATE, "contract10-candidate", "lib"))

from dsmack_compose_contract import lower, validate_manifest_bytes  # noqa: E402

PRODUCT_FILES = (
    "claude-coding-task-dstack.app-compose.json",
    "claude-coding-task-subscription-dstack.app-compose.json",
)
IMAGE_RE = re.compile(r"127\.0\.0\.1:5005/dsmack-claude-harness@sha256:[0-9a-f]{64}")
GUEST_REGISTRY = "127.0.0.1:5005"  # in-guest loopback OCI publisher (GIO09); see module doc
STALE_OS_IMAGE_HASH = "46c4bcc91ee1979b6a57cdf349cf63a9df583cc01cedc2fcf4514d366b7b73b2"
DECLARED_VCPUS = 1
DECLARED_MEM_MIB = 4096


def sha256f(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def bundle_facts(artifacts_dir):
    """Measured facts of the REBUILT bundle (same derivation as
    make_guest_inputs.py): the identity chain the manifests must carry."""
    digest = open(os.path.join(artifacts_dir, "digest.txt")).read().strip()
    md = json.load(open(os.path.join(artifacts_dir, "metadata.json")))
    entries = {}
    for line in open(os.path.join(artifacts_dir, "sha256sum.txt")).read().splitlines():
        h, name = line.split("  ", 1)
        entries[name] = h
    am = json.load(open(os.path.join(artifacts_dir, "artifact-manifest.json")))
    return {
        "os_image_hash": digest,
        "cmdline": md["cmdline"],
        "kernel_sha256": entries["Image"],
        "initrd_sha256": entries["initramfs.cpio.gz"],
        "rootfs_sha256": entries["rootfs.squashfs.verity"],
        "metadata_sha256": sha256f(os.path.join(artifacts_dir, "metadata.json")),
        "verity_root_hash": am["verity"]["root_hash"],
    }


def rewrite(manifest_bytes, facts, harness_image_digest, api_sha, sub_sha,
            registry=GUEST_REGISTRY):
    manifest = json.loads(manifest_bytes.decode("utf-8"))
    guest_ref = "%s/dsmack-claude-harness@%s" % (registry, harness_image_digest)
    # 1. the embedded compose doc: replace the unreachable host-loopback pin
    #    with the guest-reachable registry digest reference.
    dcf = manifest["docker_compose_file"]
    dcf_new, n = IMAGE_RE.subn(guest_ref, dcf)
    if n == 0:
        raise SystemExit("no 127.0.0.1:5005 harness reference found; template already changed?")
    manifest["docker_compose_file"] = dcf_new
    # 2. S02: REGENERATE base_vm from the rebuilt bundle facts -- the full
    #    resource/cmdline/identity tuple, so admission and receipts bind to
    #    the artifacts actually being booted.
    manifest["base_vm"] = {
        "architecture": "aarch64",
        "cmdline": facts["cmdline"],
        "initrd_sha256": facts["initrd_sha256"],
        "kernel_sha256": facts["kernel_sha256"],
        "memory_mb": DECLARED_MEM_MIB,
        "metadata_sha256": facts["metadata_sha256"],
        "os_image_hash": facts["os_image_hash"],
        "rootfs_sha256": facts["rootfs_sha256"],
        "vcpus": DECLARED_VCPUS,
        "verity_root_hash": facts["verity_root_hash"],
    }
    # 3. harness.sha256: repaired wrapper (api vs subscription by binary name).
    harness = manifest.get("harness", {})
    name = harness.get("name", "")
    harness["sha256"] = sub_sha if "subscription" in name else api_sha
    manifest["harness"] = harness
    out = json.dumps(manifest, indent=1, sort_keys=True).encode("utf-8") + b"\n"
    # 4. fail-closed validation + lowering.
    parsed, summary = validate_manifest_bytes(out)
    lower(parsed, summary["manifest_sha256"],
          daemon_endpoint="unix:///run/rootcontrol/docker.sock",
          run_id="render-check",
          workspace_host_dir="/run/dsmack-runs/render-check",
          runtime_available=("runc", "io.containerd.runc.v2"),
          broker={"endpoint": "http://10.0.2.2:5000/t"})
    return out, summary["manifest_sha256"]


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifacts", required=True,
                    help="REBUILT bundle artifacts dir (digest.txt/metadata.json/sha256sum.txt/"
                         "artifact-manifest.json); source of the regenerated base_vm facts")
    ap.add_argument("--harness-image-digest", required=True, help="sha256:… of the rebuilt harness image")
    ap.add_argument("--api-wrapper-sha256", required=True)
    ap.add_argument("--subscription-wrapper-sha256", required=True)
    ap.add_argument("--registry", default=GUEST_REGISTRY,
                    help="guest-reachable registry host:port (default %(default)s; the slirp "
                         "alias of host loopback)")
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args(argv)
    if not args.harness_image_digest.startswith("sha256:"):
        raise SystemExit("--harness-image-digest must be sha256:<hex>")
    facts = bundle_facts(args.artifacts)
    if facts["os_image_hash"] == STALE_OS_IMAGE_HASH:
        raise SystemExit("artifacts dir still carries the STALE 46c4bcc9… bundle; refusing to "
                         "render product manifests against the unrepaired image")
    for fn in PRODUCT_FILES:
        path = os.path.join(args.out_dir, fn)
        with open(path, "rb") as fh:
            src = fh.read()
        out, msha = rewrite(src, facts, args.harness_image_digest,
                            args.api_wrapper_sha256, args.subscription_wrapper_sha256,
                            registry=args.registry)
        with open(path, "wb") as fh:
            fh.write(out)
        print("regenerated %s manifest_sha256=%s base_vm=%s" % (fn, msha, facts["os_image_hash"]))


if __name__ == "__main__":
    main()
