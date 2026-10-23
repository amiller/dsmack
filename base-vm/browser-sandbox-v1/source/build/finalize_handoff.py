#!/usr/bin/env python3
"""Assemble the lane HANDOFF.json from collected evidence (run at finalize)."""
import hashlib
import json
import os

LANE = "/data/amiller/dsmack/attested-runner-20261020/dstack-runner-join"
BATCH = "/home/amiller/dsmack-sprints/attested-runner-20261019/joined-sprint/app-compose-20261020"


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def load(path):
    p = os.path.join(LANE, path)
    if os.path.isfile(p):
        return json.load(open(p))
    return None


def main(boot_name, runner_verify_path):
    art = os.path.join(LANE, "build", "artifacts")
    im = load("build/IMAGE-MANIFEST.json") or {}
    repro = load("evidence/repro.json") or {}
    boot = load(f"evidence/boot-{boot_name}-summary.json") or {}
    rverify = json.load(open(runner_verify_path)) if os.path.isfile(runner_verify_path) else {}

    names = ["Image", "config-6.18.40-dstack", "rootfs.squashfs.verity", "initramfs.cpio.gz",
             "metadata.json", "sha256sum.txt", "digest.txt", "artifact-manifest.json"]
    artifacts = {n: {"sha256": sha(os.path.join(art, n)), "bytes": os.path.getsize(os.path.join(art, n))}
                 for n in names if os.path.isfile(os.path.join(art, n))}
    digest = open(os.path.join(art, "digest.txt")).read().strip() if os.path.isfile(os.path.join(art, "digest.txt")) else None

    runner_files = {}
    rd = os.path.join(LANE, "source", "runner-content")
    for root, _, fs in os.walk(rd):
        for f in sorted(fs):
            p = os.path.join(root, f)
            rel = os.path.relpath(p, rd)
            if "__pycache__" in rel:
                continue
            runner_files[rel] = sha(p)

    handoff = {
        "schema": "dsmack-lane-handoff/1",
        "lane": "dstack-runner-join",
        "batch": BATCH,
        "status": None,  # filled by caller
        "image_bundle": {
            "path": os.path.join(art),
            "os_image_hash": digest,
            "os_image_hash_definition": "sha256(sha256sum.txt)",
            "image_version": (im.get("image") or {}).get("version"),
            "verity": im.get("verity"),
            "artifacts": artifacts,
            "full_manifest": "build/IMAGE-MANIFEST.json",
            "reproducibility": {
                "evidence": "evidence/repro.json",
                "reproducible": repro.get("reproducible"),
                "method": repro.get("method"),
                "kernel_by_reference": "Image 415e59cc… + config byte-identical from the PROVEN ec83a3fc bundle (hash-pinned in build_leg_rootfs.sh before build); module store extracted per leg from the proven verity rootfs",
            },
            "admission": {"evidence": "evidence/admission.log", "result": "ADMIT + tamper-rejected (this lane's bundle)"},
            "supersedes": {
                "os_image_hash": "ec83a3fcc72dda79b74747460b886971ffee34185e6061c1844549502cc44d08",
                "path": "/data/amiller/dsmack/attested-runner-20261020/dstack-smoke-finish/build/artifacts",
                "state": "prior lane read-only; kernel bytes reused by reference (provenance preserved); identity NOT relabeled — the new bundle records its own sha256(sha256sum.txt)",
            },
            "join_deltas": [
                "guest packages += python3 (same pinned trixie snapshot)",
                "approved compose_runner package + frozen contract library installed at /usr/local/lib/dsmack/compose-runner (+ installed-form CLI wrapper /usr/local/bin/dsmack-compose-runner, sys.path delta only)",
                "supervisor deltas: export disk vdd, slirp static network, RUNNER PHASE over external manifests, digest-pinned boundary probe",
                "IMAGE_VERSION 0.6.2.nft -> 0.6.3.runner",
            ],
        },
        "runner": {
            "approval": "contract10-review/astra-gate.json approved_for_implementation=true; contract_sha256 b0e8349910511ca29034f7585b6e9ae7e6cf7599e5a160ae5f2898cf14d80a45",
            "copy_integrity": "evidence/runner-content-copy-verify.txt (11/11 frozen files byte-identical; lib diff IDENTICAL)",
            "source_tree": "source/runner-content (owned verified copy; prior candidate untouched)",
            "files_sha256": runner_files,
        },
        "guest_runtime_pins": {
            "runc": {"path": "/usr/bin/runc (symlink -> /usr/sbin/runc)", "version": "1.1.15+ds1",
                     "sha256": "6a8bd8a019e7b10a8d30a9fa85656f795d5957ab7269e5579f438a065b753332",
                     "method": "measured from the exact guest bytes via qemu-aarch64 before pinning; the runner fail-closes live in-guest (registration + bytes + --version)"},
            "compose_tool": {"name": "docker-compose", "version": "2.26.1-4",
                             "path": "/usr/libexec/docker/cli-plugins/docker-compose",
                             "method": "guest `docker compose version --short` measured on the guest bytes; parser round-trip qualified on the guest bytes (logs/parser/parser-roundtrip-2.26.1.log)"},
            "docker_engine": "26.1.5+dfsg1 (Debian trixie snapshot 20260721T000000Z) — differs from the compose-runner lane's host pin (28.1.1); disclosed, not forged",
            "delta_review_note": "host->guest re-pin deltas (compose 2.35.1 -> 2.26.1-4, runc 1.2.5 -> 1.1.15+ds1) are exactly the changes the compose-runner HANDOFF required for guest execution; recorded for integration review",
        },
        "guest_runs": {
            "manifests": ["greet-sh", "pycompute"],
            "inputs": "build/runner-inputs (external, delivered on the workload disk; never baked into the image)",
            "admission_doc": "external admission bytes allowing THIS bundle's os_image_hash only",
            "boot": boot,
            "receipt_verification": rverify,
        },
        "failures_and_repairs": [
            {"attempt": "runnerjoin-try1", "bundle": "70fc3f9e9d5a14bddd5799b1ec4ce087c3111c567a9f54375ceecfce859f4ed7",
             "outcome": "guest_fail_closed, supervisor fail 8 (export disk mount), 10 s, clean poweroff",
             "root_cause": "the export mountpoint /export did not exist and cannot be created on the read-only squashfs root; the supervisor mkdir silently failed",
             "repair": "export disk mounts at /run/export (writable tmpfs mountpoint); image rebuilt (identity a1c866c5…)",
             "evidence": "evidence/boot-runnerjoin-try1-summary.json, evidence/boot-runnerjoin-try1.log"},
            {"attempt": "runnerjoin-try2", "bundle": "a1c866c5375f1ec158a8041560feff21d580ba859b85258045a11c9f355158c8",
             "outcome": "boot+dockerd+workload gate+both manifest validations PASS (runner validate + validate-inputs rc=0 in-guest); BOTH runs failed closed runner-error start-failed at compose up; clean poweroff 308 s; bundle unchanged",
             "root_cause": "INITIAL hypothesis (supervisor cgroup.subtree_control empty) was tested and DISPROVEN by try3; the surviving root-cause evidence: the guest dstack kernel has no swap cgroup accounting — dockerd logs 'Your kernel does not support swap limit capabilities' at create time, and a memory limit makes dockerd set MemorySwap so runc create fails on the absent memory.swap.max. Unlimited containers (the smoke's) never exercised this. The host reproduction of the byte-identical rendered config started and exited 0, isolating the cause to the guest kernel/daemon.",
             "repair": "supervisor R5 (controller enablement, fail-closed) + dockerd debug carried into the final image; the workload was re-issued WITHOUT deploy.resources limits (deploy is optional in the contract subset) — external inputs, not an image/runner change",
             "evidence": "evidence/boot-runnerjoin-try2-summary.json, evidence/runnerjoin-try2-export/ (run.err + RESULT-dockerd.console)"},
            {"attempt": "runnerjoin-try3", "bundle": "46c4bcc91ee1979b6a57cdf349cf63a9df583cc01cedc2fcf4514d366b7b73b2",
             "outcome": "controllers verified enabled in-guest (DSMACK_CGROUP_INFO subtree_enabled=cpuset cpu io memory hugetlb pids); boot+dockerd+workload+validations PASS; BOTH runs still failed closed at compose up (runner-error start-failed); clean poweroff 295 s; bundle unchanged",
             "root_cause": "same as try2 — the cgroup-controller hypothesis was disproven (controllers were on); the swap-accounting signature in the dockerd create-time logs remains the root-cause diagnosis",
             "repair": "external workloads re-issued without deploy.resources limits (try4); image unchanged (46c4bcc9…)",
             "evidence": "evidence/boot-runnerjoin-try3-summary.json, evidence/runnerjoin-try3-export/"},
        ],
        "residual_gaps": [
            "UNATTESTED throughout: receipts are linux-test, boot=null in the receipt (the receipt's base_vm_launch.boot is a VM-boot observation field the runner fills only via an authenticated-evidence hook no verifier ships); the VM boot itself is proven by the launcher console + bundle immutability snapshots",
            "first smoke is plainrunc only; runsc/ARM is a separate lane (not attempted here, not a blocker)",
            "TCG emulation on x86 host: not native ARM, not KVM, not TEE",
            "negative/abuse gates were exercised on the SAME runner bytes by the compose-runner lane's 13 host-Docker tests; this lane's boots cover the positive path plus the contract validate gate in-guest",
            "guest outbound is QEMU slirp with static 10.0.2.x config; DNS/TLS worked for the digest pulls (see boot console)",
            "no KMS/gateway/key-provider/dstack-agent (separate milestones)",
        ],
    }
    print(json.dumps(handoff, indent=1))


if __name__ == "__main__":
    import sys
    main(sys.argv[1], sys.argv[2])
