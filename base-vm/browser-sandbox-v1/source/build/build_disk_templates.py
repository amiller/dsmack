#!/usr/bin/env python3
"""Build deterministic BLANK ext4 scratch/result templates as IMAGE ASSETS
(guest-io-integration).

WHY: the runtime fresh RW disks (vdb scratch, vdd result) must be initialized
on the native Mac path where there is NO mkfs available in the signed app.  The
native backend therefore takes a FRESH COPY of an admitted BLANK ext4 template
that ships inside the measured image bundle (NATIVE-V3-ABI: "vdb fresh RW
initialized from admitted scratch template, vdd fresh RW result initialized
from admitted template"; "fresh-copy templates must not hardlink/mutate base
assets").  So the template bytes are pinned IMAGE IDENTITY: their sha256 must
be part of the image checksums/metadata/admission, exactly like the kernel and
rootfs.

DETERMINISM: mke2fs output is byte-reproducible when every nondeterministic
input is pinned -- a fixed UUID, a fixed directory hash seed, no lazy init,
no journal (a blank ephemeral disk needs none), a fixed volume label, and
SOURCE_DATE_EPOCH for the superblock timestamps.  Two builds of the same
(size,label) produce byte-identical templates (proved by the determinism
fixture; see tests/test_disk_templates.py).

SCOPE: this uses the installed mke2fs on a plain regular file as the invoking
user -- NO mount, NO root, NO Docker, NO loop device (R04-authorized bounded
subprocess for OWN trusted fixture images).  It does NOT build the real guest
image; it produces the template assets + a pinned manifest that the gated final
build embeds.  Sizes default to the production disk sizes but are overridable
so the determinism fixture can run cheaply.

Usage:
  build_disk_templates.py --out DIR [--scratch-bytes N] [--result-bytes N]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys

SOURCE_DATE_EPOCH = "1784592000"          # matches the rootfs build
# Fixed, documented identities (not secrets; they make the bytes reproducible).
SCRATCH_UUID = "d5ac0000-0000-4000-8000-000000000001"
RESULT_UUID = "d5ac0000-0000-4000-8000-000000000002"
HASH_SEED = "d5ac0000-7eed-4000-8000-00000000f5ed"
BLOCK_SIZE = 4096

# GIO07: the ONE agreed template byte ceiling, reconciled across the guest
# Independent scratch/result ceilings; source/profile authorization remains external.
TEMPLATE_BYTES_MAX = 1 * 1024 * 1024 * 1024  # existing RESULT ceiling/legacy field
SCRATCH_TEMPLATE_BYTES_MAX = 4 * 1024 * 1024 * 1024
TEMPLATE_ALIGN = 512
TEMPLATE_CAPS = {"scratch": SCRATCH_TEMPLATE_BYTES_MAX, "result": TEMPLATE_BYTES_MAX}

# Keep old defaults. A reviewed profile explicitly selects a larger scratch.
PROD_SCRATCH_BYTES = 1 * 1024 * 1024 * 1024     # 1 GiB (was 8 GiB; GIO07)
PROD_RESULT_BYTES = 256 * 1024 * 1024           # 256 MiB

TEMPLATE_MANIFEST_SCHEMA = "dsmack.disk-templates/1"
TEMPLATE_ADMISSION_SCHEMA = "dsmack.disk-template-admission/1"


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _clean_mkfs_env() -> dict:
    """GIO08: a CLEAN, pinned environment -- NOT the inherited host environment.

    Only the variables that make mke2fs output deterministic are set:
      * SOURCE_DATE_EPOCH -- superblock mkfs/last-write timestamps;
      * E2FSPROGS_FAKE_TIME -- the e2fsprogs internal clock (the inspected
        libext2fs honours it), so the output is independent of wall-clock time;
      * TZ=UTC, LC_ALL=C -- no locale/timezone drift;
      * MKE2FS_CONFIG -- pinned to /dev/null so the host /etc/mke2fs.conf
        defaults are NOT silently mixed in (every parameter is on the argv).
      * a minimal PATH so the pinned mkfs.ext4 is found deterministically.
    """
    return {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH,
        "E2FSPROGS_FAKE_TIME": SOURCE_DATE_EPOCH,
        "TZ": "UTC",
        "LC_ALL": "C",
        "MKE2FS_CONFIG": "/dev/null",
    }


def _mke2fs_version() -> str:
    """Pin the formatter identity: record `mke2fs -V` output (version + build
    date line) so the gated final build can verify the exact e2fsprogs used."""
    proc = subprocess.run(["mkfs.ext4", "-V"], env=_clean_mkfs_env(),
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
    return proc.stdout.decode("utf-8", "replace").strip().splitlines()[0] if proc.stdout else "unknown"


def validate_capacity(role: str, size_bytes: int) -> int:
    if role not in TEMPLATE_CAPS:
        raise SystemExit("unknown template capacity role")
    cap = TEMPLATE_CAPS[role]
    if type(size_bytes) is not int or not (0 < size_bytes <= cap) or size_bytes % TEMPLATE_ALIGN != 0:
        raise SystemExit("template violates role-specific capacity/alignment")
    return cap


def build_template(out_path: str, size_bytes: int, uuid: str, label: str, *, role: str) -> dict:
    """Create ONE deterministic blank ext4 template at out_path.  Returns the
    pinned descriptor {name,size_bytes,sha256,uuid,label,block_size,
    mkfs_features,...}. mke2fs runs unprivileged on a regular file (no mount)
    under a CLEAN pinned environment with explicit clock control (GIO08)."""
    cap = validate_capacity(role, size_bytes)
    if os.path.lexists(out_path):
        raise SystemExit("refusing existing template output")
    if size_bytes % BLOCK_SIZE != 0:
        raise SystemExit("size %d is not a multiple of block size %d" % (size_bytes, BLOCK_SIZE))
    with open(out_path, "xb") as handle:
        handle.truncate(size_bytes)
    features = "^has_journal"
    extended = "hash_seed=%s,lazy_itable_init=0,lazy_journal_init=0" % HASH_SEED
    env = _clean_mkfs_env()
    cmd = ["mkfs.ext4", "-q", "-F", "-b", str(BLOCK_SIZE), "-O", features,
           "-U", uuid, "-E", extended, "-L", label, out_path]
    proc = subprocess.run(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        raise SystemExit("mkfs.ext4 failed for %s (rc=%d)" % (out_path, proc.returncode))
    return {
        "name": os.path.basename(out_path),
        "size_bytes": size_bytes,
        "sha256": _sha256_file(out_path),
        "uuid": uuid,
        "label": label,
        "block_size": BLOCK_SIZE,
        "mkfs_features": features,
        "mkfs_extended": extended,
        "source_date_epoch": int(SOURCE_DATE_EPOCH),
        "fake_time": int(SOURCE_DATE_EPOCH),
        "template_bytes_max": cap,
        "capacity_role": role,
    }


def build_all(out_dir: str, scratch_bytes: int, result_bytes: int, expected_mke2fs_version=None) -> dict:
    validate_capacity("scratch", scratch_bytes)
    validate_capacity("result", result_bytes)
    for name in ("scratch-template.ext4", "result-template.ext4", "disk-templates.json"):
        if os.path.lexists(os.path.join(out_dir,name)):
            raise SystemExit("refusing existing template bundle output")
    actual_version = _mke2fs_version()
    if expected_mke2fs_version is not None and actual_version != expected_mke2fs_version:
        raise SystemExit("mke2fs version mismatch: %r != %r" % (actual_version, expected_mke2fs_version))
    os.makedirs(out_dir, exist_ok=True)
    scratch = build_template(os.path.join(out_dir, "scratch-template.ext4"),
                             scratch_bytes, SCRATCH_UUID, "dsmack-scratch", role="scratch")
    result = build_template(os.path.join(out_dir, "result-template.ext4"),
                            result_bytes, RESULT_UUID, "dsmack-export", role="result")
    manifest = {
        "schema": TEMPLATE_MANIFEST_SCHEMA,
        "mke2fs_version": actual_version,
        "mke2fs_version_pin": expected_mke2fs_version,
        "template_bytes_max": TEMPLATE_BYTES_MAX,
        "template_role_bytes_max": TEMPLATE_CAPS,
        "templates": {
            "scratch": {"role": "vdb-scratch", **scratch},
            "result": {"role": "vdd-result", **result},
        },
        # GIO08: a reviewed ADDITIVE admission binding for BOTH templates. The
        # final build MUST bind these digests into the authenticated image
        # identity and admission, and MUST verify the built template bytes
        # against them (postbuild). Until the gated build promotes them, this
        # stanza is the explicit, reviewed binding record -- not a silent
        # opt-in. The guest builder never raises os_image_hash itself (that is
        # an authenticated metadata key-set change owned by the final gate).
        "admission_binding": {
            "schema": TEMPLATE_ADMISSION_SCHEMA,
            "bytes_max": TEMPLATE_BYTES_MAX,
            "role_bytes_max": TEMPLATE_CAPS,
            "mke2fs_version": actual_version,
            "align": TEMPLATE_ALIGN,
            "native_cap_source": "backend-v3 disks_v3.rs role-specific template_bytes_max / spec_v3.rs check_template",
            "descriptors": [
                {"role": "vdb-scratch", "name": scratch["name"],
                 "sha256": scratch["sha256"], "size_bytes": scratch["size_bytes"]},
                {"role": "vdd-result", "name": result["name"],
                 "sha256": result["sha256"], "size_bytes": result["size_bytes"]},
            ],
            "final_build_verification": "MANDATORY: verify built template bytes == these digests "
                                        "and bind both into authenticated metadata + admission",
        },
    }
    manifest_path = os.path.join(out_dir, "disk-templates.json")
    with open(manifest_path, "w") as handle:
        json.dump(manifest, handle, indent=1, sort_keys=True)
        handle.write("\n")
    return manifest


def merge_into_artifact_manifest(artifact_manifest_path: str, templates_manifest: dict) -> dict:
    """ADDITIVE, bounded metadata wiring: record the pinned disk-template
    descriptors inside the image's artifact-manifest.json under a new
    ``disk_templates`` key, WITHOUT touching the base-bundle sha256sum.txt
    4-component layout (which the in-guest admission authenticates and would
    reject a foreign name in).  Returns the updated artifact-manifest dict.

    NOTE (handoff): binding the template digests into os_image_hash itself
    requires a contract-level change to the authenticated metadata key set
    (image_admission.parse_metadata enforces an EXACT key set); that belongs to
    the final integrator + the io-contract reconciliation, not this bounded
    guest-source lane.  Until then the templates are pinned in the image
    artifact-manifest and this disk-templates.json, and MUST be promoted into
    the authenticated identity at the gated final build."""
    with open(artifact_manifest_path, "rb") as handle:
        am = json.loads(handle.read())
    am["disk_templates"] = {
        "schema": templates_manifest["schema"],
        "template_bytes_max": templates_manifest.get("template_bytes_max", TEMPLATE_BYTES_MAX),
        "template_role_bytes_max": templates_manifest["template_role_bytes_max"],
        "mke2fs_version": templates_manifest.get("mke2fs_version"),
        "templates": templates_manifest["templates"],
        "admission_binding": templates_manifest.get("admission_binding"),
        "binding_note": "pinned image asset; final build MUST promote these digests into the "
                        "authenticated image identity (metadata key-set extension) and admission, "
                        "and MUST verify built template bytes against admission_binding.descriptors",
    }
    with open(artifact_manifest_path, "w") as handle:
        json.dump(am, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return am


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, help="output dir for the template assets + manifest")
    ap.add_argument("--scratch-bytes", type=int, default=PROD_SCRATCH_BYTES)
    ap.add_argument("--result-bytes", type=int, default=PROD_RESULT_BYTES)
    ap.add_argument("--expected-mke2fs-version", default=None)
    ap.add_argument("--merge-artifact-manifest", default=None,
                    help="also record the template digests into this artifact-manifest.json (additive)")
    args = ap.parse_args(argv)
    manifest = build_all(args.out, args.scratch_bytes, args.result_bytes, args.expected_mke2fs_version)
    if args.merge_artifact_manifest:
        merge_into_artifact_manifest(args.merge_artifact_manifest, manifest)
        print("recorded disk-template digests into", args.merge_artifact_manifest)
    for role, t in sorted(manifest["templates"].items()):
        print("template %-8s %-22s size=%d sha256=%s"
              % (role, t["name"], t["size_bytes"], t["sha256"]))
    print("disk-templates manifest:", os.path.join(args.out, "disk-templates.json"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
