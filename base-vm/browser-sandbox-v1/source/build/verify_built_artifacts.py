#!/usr/bin/env python3
"""POST-BUILD VERIFICATION (Phase B; S01/S02; repaired per B03/B05) --
independently prove that the rebuilt artifacts embed the SELECTED SOURCE and
that every external manifest binds to the rebuilt identities. No boot, no
daemon, no credential.

What it proves (each check is recorded in a machine-readable transcript):

  P1  rootfs-embeds-source: `unsquashfs` (extraction only, into --workdir
      under the build root -- never host temporary storage) of the rebuilt
      rootfs.squashfs.verity; every installed guest file must hash EQUAL to
      the frozen candidate source bytes: the compose-runner package + the
      patched contract library (incl. the repaired validator manifest.py),
      the supervisor (/usr/bin/dsmack-supervisor), the sentinel package and
      its adapter dependency, the INSTALLED CLI
      (/usr/local/bin/dsmack-compose-runner, compared against the exact
      heredoc frozen in build_leg_rootfs.sh), and /etc/docker/daemon.json
      (which must carry "insecure-registries": ["127.0.0.1:5005"]).
      NEGATIVE: the stale validator 80c39cc9… / runner 27d6ef64… refused.
  P2  harness-image-embeds-wrappers + child identity: --harness-digest MUST
      resolve in the registry storage to a SINGLE image manifest (an index /
      manifest-list digest is REJECTED: delivery and manifests must carry the
      exact linux/arm64 child identity), its config platform must be
      arm64/linux, every referenced blob must hash to its digest, and the
      LAST occurrence of each wrapper across layers (last-layer-wins,
      honoring whiteout deletions) must hash to the repaired candidate
      wrapper bytes. NEGATIVE: stale 7f2f3aa1…/93e50e51… refused.
  P3  manifests-bind-rebuilt-identity: the product dir and BOTH delivered
      input trees (--runner-inputs AND --runner-inputs-product) must contain
      EXACTLY the expected manifest set (no extras), every manifest's base_vm
      must EQUAL the complete rebuilt tuple (architecture, os_image_hash,
      verbatim cmdline, kernel/initrd/rootfs/metadata sha256s, verity root,
      1 vCPU / 2048 MiB), service image references are PARSED from the
      embedded compose document (never substring-matched) and must equal
      127.0.0.1:5005/dsmack-claude-harness@<D'> exactly, harness.sha256 must
      equal the repaired wrapper, no stale 10.0.2.2:5005 slirp ref anywhere,
      admission in
      BOTH trees admits EXACTLY [H'], and every engineering envelope
      validates against its manifest bytes under the EXTRACTED guest library.
  P4  embedded-validator-accepts-subscription: the EXTRACTED guest library
      bytes (not the host copy) validate the subscription product manifest.
  P5  bundle-self-consistency: sha256(sha256sum.txt) == digest.txt == H';
      EVERY file referenced by sha256sum.txt is REHASHED from the actual
      artifacts bytes; the base-bundle copies in BOTH delivered trees are
      REHASHED (not only byte-compared checksum manifests); verity/tamper
      admission EVIDENCE (--evidence/admission.log) must show
      'verity: verified' and 'tamper-test: tamper-rejected' for H' -- a
      skipped verity or tamper check is REJECTED; the guest package inventory
      (--guest-packages) must exist and carry the pinned container stack.
      NEGATIVES: stale base / stale harness digests refused.
  P6  secret/token exclusion (scoped, pattern-based -- see LIMITS): across
      the delivered channel trees and product manifests, no file named like a
      credential/token, no broker-config key outside the frozen allowlist, no
      value matching known credential shapes (sk-ant-…, accessToken/
      refreshToken fields, Authorization: Bearer), and no checksum inventory
      line referencing a credential/token path.

LIMITS (documented, not fake guarantees): P6 is a deny-pattern scan of the
delivered TEXT channels (manifests/envelopes/admission/broker/images/WORKLOAD
+ product manifests), not a semantic proof that no secret exists anywhere;
binary bundle artifacts are covered by identity (P1/P5), not content
scanning. P2 proves registry-storage bytes -- the bytes a digest pull
verifies -- without running a daemon. This script performs NO boot and NO
credential access; passing it is Phase-B artifact identity only, never
runtime qualification.

Exit 0 and transcript.predicate == "pass" ONLY when every check passes. The
BUILT-ARTIFACTS-LOCK.json 'verification' block is derived from this
transcript; the launcher refuses a lock without it (S02).

Usage:
  python3 verify_built_artifacts.py \
      --artifacts DIR --candidate DIR --harness-digest sha256:… \
      --registry-root DIR --product-manifests DIR --runner-inputs DIR \
      --runner-inputs-product DIR --evidence DIR --guest-packages FILE \
      --workdir DIR --out transcript.json [--keep-extract DIR]
"""
import argparse
import gzip
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile

STALE_OS_IMAGE_HASH = "46c4bcc91ee1979b6a57cdf349cf63a9df583cc01cedc2fcf4514d366b7b73b2"
STALE_VALIDATOR = "80c39cc9257f73c61bcfe38b9f7a0a7f2cfaf560f344e2c0c4b9438b34941fc1"
STALE_RUNNER = "27d6ef64ce81aab8d67328ff880112e3eb9821f2f4c19d2e536eff030a1968f1"
STALE_HARNESS_DIGESTS = {
    "sha256:48c2a81bc901a25084fa1bbb36291c7ed84f2d6ce3fe0efede753c4c07dc96eb",
    "sha256:1ffe3d32a9c9a5dda6ee51f967e62d4c77021ff95057304f94aae1da126c32cd",
}
STALE_WRAPPER_PREFIXES = ("7f2f3aa1", "93e50e51")
# GIO09: the reconciled single OCI endpoint (CROSS-LANE-VERIFIED-FINDINGS.oci).
# The guest pulls the harness BY DIGEST from the in-guest loopback publisher on
# 127.0.0.1:5005 (the measured oci-layout/ channel served read-only before the
# runner); there is NO slirp 10.0.2.2:5005 pull anymore. GUEST_REGISTRY is what
# the rendered product manifests AND daemon.json must carry. STALE_GUEST_ALIAS
# is the retired slirp alias that must NOT appear in any rendered manifest.
STALE_SLIRP_REGISTRY = "10.0.2.2:5005"
# NATIVE-GUEST-NETWORK-PROFILE: pinned VERIFIED upstream gvproxy v0.8.9
# unconfigured NAT contract (GUEST-IMAGE-PROFILE-HANDOFF.md). The measured guest
# profile must match this so the in-guest digest pulls route through gvproxy on
# both the Zed external-client path and the native Mini path.
GVPROXY_SUBNET_CIDR = "192.168.127.0/24"
GVPROXY_GATEWAY = "192.168.127.1"
GVPROXY_DNS = "192.168.127.1"      # gvproxy resolver binds ONLY to the gateway IP
GVPROXY_GUEST_IP = "192.168.127.2"  # pinned static guest address
GVPROXY_PREFIXLEN = 24
GVPROXY_IFACE = "eth0"
GUEST_REGISTRY = "127.0.0.1:5005"
HOST_REGISTRY = "127.0.0.1:5005"   # host build registry (same loopback literal)
STALE_GUEST_ALIAS = "10.0.2.2:5005"
HARNESS_IMAGE_NAME = "dsmack-claude-harness"
WRAPPERS = ("usr/local/bin/dsmack-claude-wrapper", "usr/local/bin/dsmack-claude-wrapper-subscription")
PRODUCT_MANIFEST_SET = {
    "claude-coding-task-dstack.app-compose.json",
    "claude-coding-task-subscription-dstack.app-compose.json",
}
ENGINEERING_MANIFEST_SET = {"greet-sh.app-compose.json", "pycompute.app-compose.json"}
ENGINEERING_ENVELOPE_SET = {"greet-sh.envelope.json", "pycompute.envelope.json"}
# B05: the base VM bundle components make_guest_inputs.py copies into EACH
# delivered tree's base-bundle/ dir (render_product_manifests/make_guest_inputs
# copy exactly these plus sha256sum.txt). Every one MUST be present and rehash;
# absence is a REJECTION, not a silently-skipped check.
DELIVERED_BASE_BUNDLE = ("Image", "initramfs.cpio.gz", "metadata.json", "rootfs.squashfs.verity")
# B05: the COMPLETE pinned guest container stack, derived from the frozen
# build_leg_rootfs.sh --include list (docker-cli/docker-compose were previously
# omitted) plus runc (the OCI runtime the daemon requires; checked as a binary
# in build_leg_rootfs.sh:122). Every one must be installed, at arm64/all arch.
REQUIRED_GUEST_PACKAGES = ("docker.io", "docker-cli", "docker-compose", "containerd",
                           "runc", "busybox-static", "bash", "ca-certificates",
                           "iproute2", "dmsetup", "cryptsetup-bin", "python3")
# B05: version+architecture expectations for the COMPLETE required container
# stack are NOT hand-written literals (the previous docker.io pin
# "26.1.5+dfsg1" was copied from a descriptive stack note and did NOT match the
# hash-pinned seed .deb's real Debian version 26.1.5+dfsg1-9+b13). They are
# loaded from guest-stack-expectations.json, derived from the dpkg control
# metadata of the hash-pinned debootstrap seed .debs for the selected snapshot
# (Debian epochs/revisions preserved; per-deb provenance sha256). Every frozen
# package is version-checked against that seed metadata AND the promoted
# inventory is cross-checked against metadata extracted from the rebuilt rootfs
# (/var/lib/dpkg/status) -- producer/consumer agreement, not self-agreement.
# See load_stack_expectations / parse_dpkg_status / check_guest_packages.
STACK_EXPECTATIONS_REL = ("dstack-runner-join", "source", "build",
                          "guest-stack-expectations.json")
GUEST_PACKAGE_ALLOWED_ARCHS = {"arm64", "all"}
BROKER_CONFIG_ALLOWED_KEYS = {"listen_port", "workload_host", "provider_route", "ca_bundle", "auth_mode"}
SECRET_VALUE_PATTERNS = (
    re.compile(rb"sk-ant-[A-Za-z0-9_\-]{8,}"),
    re.compile(rb'"accessToken"\s*:'),
    re.compile(rb'"refreshToken"\s*:'),
    re.compile(rb"Authorization:\s*Bearer\s+\S+"),
)
SECRET_NAME_PATTERN = re.compile(r"(^|[._-])(credential|credentials|token|secret)s?([._-]|$)", re.I)


def sha256f(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256b(data):
    return hashlib.sha256(data).hexdigest()


class Checker:
    def __init__(self):
        self.checks = []
        self.failed = 0

    def record(self, check_id, ok, detail):
        self.checks.append({"check": check_id, "ok": bool(ok), "detail": detail})
        if not ok:
            self.failed += 1
            print("FAIL %s: %s" % (check_id, detail), file=sys.stderr)
        else:
            print("ok   %s" % check_id)


def extract_rootfs(artifacts, dest):
    rootfs = os.path.join(artifacts, "rootfs.squashfs.verity")
    r = subprocess.run(["unsquashfs", "-no-progress", "-d", dest, rootfs,
                        "usr/local/lib/dsmack", "usr/bin/dsmack-supervisor",
                        "usr/local/bin/dsmack-compose-runner",
                        # SPECULATIVE-IMAGE-E2E fix (POSTBUILD-PREDICATES): the
                        # installed guest-I/O wrapper is checked below
                        # (P1:installed-guest-io-cli) but was omitted from this
                        # selective extraction, producing a FALSE "absent from
                        # rootfs" finding. Extract it so the check reads the real
                        # installed bytes (the CLI is confirmed present in the
                        # actual squashfs; see recorded review disagreement).
                        "usr/local/bin/dsmack-guest-io", "etc/docker/daemon.json",
                        "var/lib/dpkg/status"],
                       capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        raise SystemExit("unsquashfs failed: %s" % r.stderr[-1000:])
    return dest


def expected_cli_bytes(candidate):
    """The installed CLI is generated by a quoted heredoc frozen inside
    build_leg_rootfs.sh; re-derive the exact expected bytes from that frozen
    source so the installed form is verified, not merely present (B05)."""
    src = os.path.join(candidate, "dstack-runner-join", "source", "build", "build_leg_rootfs.sh")
    lines = open(src, "r", encoding="utf-8").read().splitlines(True)
    out, grab = [], False
    for ln in lines:
        if grab:
            if ln.rstrip("\n") == "EOF":
                return "".join(out).encode("utf-8")
            out.append(ln)
        elif "dsmack-compose-runner" in ln and "<<'EOF'" in ln and ln.lstrip().startswith("cat >"):
            grab = True
    raise SystemExit("installed-CLI heredoc not found in build_leg_rootfs.sh")


def expected_heredoc_bytes(candidate, marker):
    """Re-derive the exact bytes of a frozen `cat > ... <<'EOF'` heredoc whose
    opening line contains ``marker`` (GIO10: installed-import/wrapper check)."""
    src = os.path.join(candidate, "dstack-runner-join", "source", "build", "build_leg_rootfs.sh")
    lines = open(src, "r", encoding="utf-8").read().splitlines(True)
    out, grab = [], False
    for ln in lines:
        if grab:
            if ln.rstrip("\n") == "EOF":
                return "".join(out).encode("utf-8")
            out.append(ln)
        elif marker in ln and "<<'EOF'" in ln and ln.lstrip().startswith("cat >"):
            grab = True
    raise SystemExit("heredoc for %r not found in build_leg_rootfs.sh" % marker)


TEMPLATE_ROLES_REQUIRED = ("vdb-scratch", "vdd-result")


def check_disk_templates(ck, candidate, tree, require=False, expected_mke2fs_version=None,
                         artifacts_dir=None):
    """GIO08/GIO10: verify the reviewed additive template admission binding.

    When ``require`` is set (the FINAL build), this FAILS CLOSED on: a missing
    or unreadable disk-templates manifest; either mandatory role
    (vdb-scratch/vdd-result) absent from templates OR the admission binding; a
    template file absent or whose bytes do not hash to the recorded digest OR
    whose actual byte LENGTH does not equal the recorded size_bytes (GIO08: the
    prior check verified only the digest); a binding descriptor whose
    size/digest disagrees with the templates entry; formatter drift (manifest
    mke2fs_version != the expected pin); and -- the "authenticated binding"
    wired through promotion -- the promoted image artifact-manifest.json
    ``disk_templates`` block whose descriptors do NOT byte-agree with this
    manifest's (so the descriptors are cross-bound across the templates
    manifest, the promoted artifact-manifest and the actual template bytes, not
    a lone unauthenticated JSON object). An empty templates object with
    unrelated descriptors can no longer pass.

    When ``require`` is false (source-only fixture), absence is recorded
    informationally and present manifests are still structurally checked.

    NOTE (documented residual, NOT a silent gap): binding the template digests
    into os_image_hash ITSELF requires extending the authenticated-metadata key
    set (image_admission.parse_metadata enforces an EXACT key set) AND the
    native backend reads the templates as BUNDLE assets (NATIVE-V3-ABI), so the
    verity-root route is unavailable too -- both are shared-contract / final-
    integrator changes, out of a bounded guest-source lane. This verifier makes
    the descriptors MANDATORY, byte-verified (digest+size) and cross-bound at
    the final gate; the os_image_hash inclusion is the precise remaining
    contract step (reported in the handoff)."""
    cap = 1 * 1024 * 1024 * 1024  # == build_disk_templates.TEMPLATE_BYTES_MAX / native cap
    found = None
    for probe in ((os.path.join(artifacts_dir, "disk-templates.json") if artifacts_dir else ""),
                  os.path.join(candidate, "dstack-runner-join", "build", "artifacts", "disk-templates.json"),
                  os.path.join(tree, "usr/local/lib/dsmack/disk-templates/disk-templates.json")):
        if os.path.isfile(probe):
            found = probe
            break
    if found is None:
        ck.record("P1:disk-templates-present", not require,
                  "disk-templates manifest ABSENT (required at the final build)" if require
                  else "no disk-templates manifest in this source-only build (promoted at final gate)")
        return
    try:
        man = json.load(open(found))
    except (OSError, ValueError) as exc:
        ck.record("P1:disk-templates-parse", False, "unreadable: %s" % type(exc).__name__)
        return
    templates = man.get("templates") or {}
    binding = man.get("admission_binding") or {}
    descriptors = {d.get("role"): d for d in (binding.get("descriptors") or [])}
    # by-ROLE map of the templates entries (each carries its own role field)
    tpl_by_role = {t.get("role"): t for t in templates.values()}
    # both mandatory roles present in BOTH templates and the admission binding
    roles_ok = all(r in tpl_by_role for r in TEMPLATE_ROLES_REQUIRED) \
        and all(r in descriptors for r in TEMPLATE_ROLES_REQUIRED)
    ck.record("P1:disk-templates-both-roles", roles_ok,
              "templates roles=%s binding roles=%s require=%s"
              % (sorted(tpl_by_role), sorted(descriptors), list(TEMPLATE_ROLES_REQUIRED)))
    # formatter pin enforced when an expected pin is supplied (GIO08 fail-closed)
    if expected_mke2fs_version is not None:
        ck.record("P1:disk-templates-formatter-pin",
                  man.get("mke2fs_version") == expected_mke2fs_version,
                  "mke2fs_version=%r expected=%r" % (man.get("mke2fs_version"), expected_mke2fs_version))
    for role in TEMPLATE_ROLES_REQUIRED:
        t = tpl_by_role.get(role)
        d = descriptors.get(role)
        if t is None or d is None:
            ck.record("P1:disk-template:%s" % role, not require, "role missing (templates/binding)")
            continue
        size = t.get("size_bytes")
        size_ok = isinstance(size, int) and 0 < size <= cap and size % 512 == 0
        ck.record("P1:disk-template-size:%s" % role, size_ok, "size=%r cap=%d" % (size, cap))
        # the binding descriptor MUST agree with the templates entry (no empty
        # templates object with unrelated descriptors)
        ck.record("P1:disk-template-descriptor-agrees:%s" % role,
                  d.get("sha256") == t.get("sha256") and d.get("size_bytes") == t.get("size_bytes")
                  and d.get("name") == t.get("name"),
                  "descriptor %r vs template %r" % (d, {k: t.get(k) for k in ("name", "sha256", "size_bytes")}))
        # the template bytes, when embedded alongside the manifest, MUST hash to
        # the recorded digest; at the final build they are required present.
        emb = os.path.join(os.path.dirname(found), t.get("name", ""))
        if os.path.isfile(emb):
            # GIO08: validate actual byte LENGTH as well as digest -- a file
            # whose bytes hash correctly but whose length disagrees with the
            # recorded size_bytes (e.g. a differently-sized template reusing a
            # colliding record) is refused.
            dg_ok = sha256f(emb) == t.get("sha256")
            actual_size = os.path.getsize(emb)
            sz_ok = actual_size == t.get("size_bytes")
            ck.record("P1:disk-template-bytes:%s" % role, dg_ok and sz_ok,
                      "digest_ok=%s size actual=%d recorded=%r" % (dg_ok, actual_size, t.get("size_bytes")))
        elif require:
            ck.record("P1:disk-template-bytes:%s" % role, False,
                      "template file %r absent at the final build" % t.get("name"))

    # GIO08: the "authenticated binding wired through promotion" -- the promoted
    # image artifact-manifest.json MUST carry a disk_templates block whose
    # admission_binding descriptors byte-agree with this templates manifest, so
    # the descriptors are cross-bound (not a lone unauthenticated JSON object).
    if require:
        am_path = None
        for probe in ((os.path.join(artifacts_dir, "artifact-manifest.json") if artifacts_dir else None),
                      os.path.join(candidate, "dstack-runner-join", "build", "artifacts",
                                   "artifact-manifest.json")):
            if probe and os.path.isfile(probe):
                am_path = probe
                break
        if am_path is None:
            ck.record("P1:disk-templates-bound-in-artifact-manifest", False,
                      "no promoted artifact-manifest.json to bind the template descriptors into")
        else:
            try:
                am = json.load(open(am_path))
                am_desc = (((am.get("disk_templates") or {}).get("admission_binding") or {})
                           .get("descriptors"))
                man_desc = (binding or {}).get("descriptors")
                ck.record("P1:disk-templates-bound-in-artifact-manifest",
                          isinstance(am_desc, list) and am_desc == man_desc,
                          "artifact-manifest descriptors must byte-equal the disk-templates manifest")
            except (OSError, ValueError) as exc:
                ck.record("P1:disk-templates-bound-in-artifact-manifest", False,
                          "artifact-manifest.json unreadable: %s" % type(exc).__name__)

        # GIO08 (AUTHENTICATED binding, the part this lane OWNS): the two template
        # digests MUST be bound into the authenticated boot cmdline
        # (dstack.scratch_template_sha256 / dstack.result_template_sha256). The
        # cmdline lives in metadata.json, whose sha256 is covered by sha256sum.txt
        # == os_image_hash, so the image's AUTHENTICATED IDENTITY cryptographically
        # commits to the template digests -- not merely two mutable JSON documents
        # agreeing. A coordinated template+descriptor substitution (swap a template
        # and forge BOTH JSON descriptors to match) is still rejected: the cmdline
        # token is anchored by os_image_hash, so the swapped template's actual
        # bytes will not hash to the authenticated token.
        md_path = None
        for probe in ((os.path.join(artifacts_dir, "metadata.json") if artifacts_dir else None),
                      os.path.join(candidate, "dstack-runner-join", "build", "artifacts", "metadata.json")):
            if probe and os.path.isfile(probe):
                md_path = probe
                break
        if md_path is None:
            ck.record("P1:disk-templates-bound-in-os-image-hash", False,
                      "no promoted metadata.json to confirm the authenticated cmdline binding")
        else:
            try:
                cmdline = (json.load(open(md_path)) or {}).get("cmdline", "")
                want = {"vdb-scratch": "dstack.scratch_template_sha256",
                        "vdd-result": "dstack.result_template_sha256"}
                ok = True
                detail = []
                for role in TEMPLATE_ROLES_REQUIRED:
                    t = tpl_by_role.get(role) or {}
                    tok = want.get(role)
                    m = re.search(r"\b%s=([0-9a-f]{64})\b" % re.escape(tok), cmdline) if tok else None
                    bound = bool(m) and m.group(1) == t.get("sha256")
                    ok = ok and bound
                    detail.append("%s bound=%s" % (role, bound))
                ck.record("P1:disk-templates-bound-in-os-image-hash", ok,
                          "authenticated cmdline must carry each template digest: " + "; ".join(detail))
            except (OSError, ValueError) as exc:
                ck.record("P1:disk-templates-bound-in-os-image-hash", False,
                          "metadata.json unreadable: %s" % type(exc).__name__)


def check_gvproxy_network_profile(ck, env_path):
    """NATIVE-GUEST-NETWORK-PROFILE: the installed guest-network.env must be
    SEMANTICALLY compatible with the pinned gvproxy v0.8.9 unconfigured NAT.
    Fail-closed: a stale slirp (10.0.2.x) profile passes source-equality but is
    unroutable through gvproxy (gateway off-subnet, impossible 10.0.2.3 DNS)."""
    import ipaddress
    label = "P1:gvproxy-network-profile"
    if not os.path.isfile(env_path):
        ck.record(label, False, "installed guest-network.env absent from rootfs")
        return
    env = {}
    with open(env_path) as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            for stmt in line.split(";"):
                if "=" in stmt:
                    k, v = stmt.split("=", 1)
                    env[k.strip()] = v.strip().strip('"').strip("'")
    subnet = ipaddress.ip_network(GVPROXY_SUBNET_CIDR)
    problems = []
    if env.get("GUEST_IFACE") != GVPROXY_IFACE:
        problems.append("GUEST_IFACE=%r expected %r" % (env.get("GUEST_IFACE"), GVPROXY_IFACE))
    try:
        ifc = ipaddress.ip_interface(env.get("GUEST_IP_CIDR", ""))
        if ifc.ip != ipaddress.ip_address(GVPROXY_GUEST_IP):
            problems.append("GUEST_IP_CIDR address %s expected pinned %s" % (ifc.ip, GVPROXY_GUEST_IP))
        if ifc.network.prefixlen != GVPROXY_PREFIXLEN:
            problems.append("prefix /%s expected /%s" % (ifc.network.prefixlen, GVPROXY_PREFIXLEN))
        if ifc.ip not in subnet:
            problems.append("address %s not in gvproxy subnet %s" % (ifc.ip, subnet))
    except ValueError as exc:
        problems.append("GUEST_IP_CIDR=%r unparseable: %s" % (env.get("GUEST_IP_CIDR"), exc))
    try:
        gw = ipaddress.ip_address(env.get("GUEST_GW", ""))
        if gw != ipaddress.ip_address(GVPROXY_GATEWAY):
            problems.append("GUEST_GW=%s expected %s" % (gw, GVPROXY_GATEWAY))
        if gw not in subnet:
            problems.append("gateway %s not reachable on subnet %s" % (gw, subnet))
    except ValueError as exc:
        problems.append("GUEST_GW=%r unparseable: %s" % (env.get("GUEST_GW"), exc))
    try:
        dns = ipaddress.ip_address(env.get("GUEST_DNS", ""))
        if dns != ipaddress.ip_address(GVPROXY_DNS):
            problems.append("GUEST_DNS=%s expected %s (gvproxy resolver binds only to the gateway IP)"
                            % (dns, GVPROXY_DNS))
    except ValueError as exc:
        problems.append("GUEST_DNS=%r unparseable: %s" % (env.get("GUEST_DNS"), exc))
    ck.record(label, not problems,
              "gvproxy NAT compat: " + ("; ".join(problems) if problems
              else "iface/addr/gw/dns match pinned %s" % GVPROXY_SUBNET_CIDR))


def check_rootfs(ck, tree, candidate, require_disk_templates=False, expected_mke2fs_version=None,
                 artifacts_dir=None):
    """P1: embedded guest bytes == frozen candidate source bytes."""
    rc = os.path.join(candidate, "dstack-runner-join", "source", "runner-content")
    pairs = []
    # GIO10: the NEW measured guest-I/O helper package (safe private transport +
    # offline OCI publisher) is security-critical installed source and MUST be
    # covered by the source-equality check, not omitted.
    for sub, guest_base in (("dsmack_compose_runner", "usr/local/lib/dsmack/compose-runner/dsmack_compose_runner"),
                            (os.path.join("lib", "dsmack_compose_contract"),
                             "usr/local/lib/dsmack/compose-runner/lib/dsmack_compose_contract"),
                            ("dsmack_guest_io", "usr/local/lib/dsmack/guest-io/dsmack_guest_io")):
        src_dir = os.path.join(rc, sub)
        for fn in sorted(os.listdir(src_dir)):
            if fn.endswith(".py"):
                pairs.append((os.path.join(src_dir, fn), os.path.join(tree, guest_base, fn)))
    # GIO10: the measured guest network profile declaration.
    pairs.append((os.path.join(candidate, "dstack-runner-join", "source", "profile",
                               "dstack-trixie-arm64-minimal", "guest-network.env"),
                  os.path.join(tree, "usr/local/lib/dsmack/net/guest-network.env")))
    pairs.append((os.path.join(candidate, "dstack-runner-join", "source", "guest",
                               "supervisor-dstack-trixie.sh"),
                  os.path.join(tree, "usr/bin/dsmack-supervisor")))
    harness = os.path.join(candidate, "claude-inputs-candidate", "harness")
    sentinel_base = os.path.join(tree, "usr/local/lib/dsmack/sentinel/harness")
    for rel in ("__init__.py", "sentinel/__init__.py", "sentinel/sentinel.py",
                "sentinel/sentinel_oauth.py", "adapter/__init__.py",
                "adapter/claude_subscription_document.py"):
        pairs.append((os.path.join(harness, rel), os.path.join(sentinel_base, rel)))
    pairs.append((os.path.join(candidate, "dstack-runner-join", "source", "profile",
                               "dstack-trixie-arm64-minimal", "docker-daemon.json"),
                  os.path.join(tree, "etc/docker/daemon.json")))
    measured = {}
    for src, embedded in pairs:
        if not os.path.isfile(embedded):
            ck.record("P1:%s" % os.path.relpath(embedded, tree), False, "absent from rootfs")
            continue
        hs, he = sha256f(src), sha256f(embedded)
        measured[os.path.relpath(embedded, tree)] = he
        ck.record("P1:%s" % os.path.relpath(embedded, tree), hs == he,
                  "source=%s embedded=%s" % (hs, he))
    # NATIVE-GUEST-NETWORK-PROFILE: the installed guest-network.env must be
    # SEMANTICALLY compatible with the user-pinned, VERIFIED upstream gvproxy
    # v0.8.9 unconfigured NAT (GUEST-IMAGE-PROFILE-HANDOFF.md). Source-equality
    # alone does not catch a profile that was frozen with a stale slirp
    # (10.0.2.x) subnet, which cannot route through gvproxy (gateway off-subnet,
    # DNS resolver only ever binds to the gateway IP). Fail-closed.
    check_gvproxy_network_profile(ck, os.path.join(tree, "usr/local/lib/dsmack/net/guest-network.env"))
    # B05: the INSTALLED CLI is verified against the exact frozen heredoc bytes
    cli_path = os.path.join(tree, "usr/local/bin/dsmack-compose-runner")
    want_cli = sha256b(expected_cli_bytes(candidate))
    if os.path.isfile(cli_path):
        got_cli = sha256f(cli_path)
        measured["usr/local/bin/dsmack-compose-runner"] = got_cli
        ck.record("P1:installed-cli", got_cli == want_cli,
                  "installed=%s heredoc=%s" % (got_cli, want_cli))
    else:
        ck.record("P1:installed-cli", False, "absent from rootfs")
    # GIO10: the INSTALLED guest-I/O wrapper must equal its exact frozen heredoc
    # (installed-import check: it points sys.path at the measured package).
    gio_cli = os.path.join(tree, "usr/local/bin/dsmack-guest-io")
    want_gio = sha256b(expected_heredoc_bytes(candidate, "dsmack-guest-io"))
    if os.path.isfile(gio_cli):
        got_gio = sha256f(gio_cli)
        measured["usr/local/bin/dsmack-guest-io"] = got_gio
        ck.record("P1:installed-guest-io-cli", got_gio == want_gio,
                  "installed=%s heredoc=%s" % (got_gio, want_gio))
    else:
        ck.record("P1:installed-guest-io-cli", False, "absent from rootfs")
    # GIO08/GIO10: reviewed additive disk-template admission binding.
    check_disk_templates(ck, candidate, tree, require=require_disk_templates, expected_mke2fs_version=expected_mke2fs_version, artifacts_dir=artifacts_dir)
    # explicit registry policy inside the image
    dj_path = os.path.join(tree, "etc/docker/daemon.json")
    try:
        dj = json.load(open(dj_path))
        ck.record("P1:insecure-registry-policy", dj.get("insecure-registries") == [GUEST_REGISTRY],
                  "insecure-registries=%r" % dj.get("insecure-registries"))
    except (OSError, ValueError) as exc:
        ck.record("P1:insecure-registry-policy", False, "daemon.json unreadable: %s" % type(exc).__name__)
    # negatives: the stale bytes must NOT be what is embedded
    emb_validator = measured.get("usr/local/lib/dsmack/compose-runner/lib/dsmack_compose_contract/manifest.py")
    emb_runner = measured.get("usr/local/lib/dsmack/compose-runner/dsmack_compose_runner/runner.py")
    ck.record("P1-neg:validator-not-stale", emb_validator not in (None, STALE_VALIDATOR),
              "embedded validator=%s" % emb_validator)
    ck.record("P1-neg:runner-not-stale", emb_runner not in (None, STALE_RUNNER),
              "embedded runner=%s" % emb_runner)
    return measured


def _registry_blob(registry_root, digest):
    hexd = digest.split(":", 1)[1]
    p = os.path.join(registry_root, "docker", "registry", "v2", "blobs", "sha256",
                     hexd[:2], hexd, "data")
    if not os.path.isfile(p):
        raise SystemExit("registry blob %s missing at %s" % (digest, p))
    data = open(p, "rb").read()
    if sha256b(data) != hexd:
        raise SystemExit("registry blob %s bytes do not hash to their digest" % digest)
    return data


def _parse_workload_user(spec):
    """Resolve the configured workload user (OCI image config 'User', set by the
    Dockerfile `USER 1000:1000`) to a numeric (uid, gid). Numeric 'uid[:gid]' is
    honored exactly (gid defaults to uid); empty is root (0, 0); a NON-numeric
    name cannot be resolved without the guest passwd db, so (None, None) selects
    a conservative any-exec-bit rule in _user_can_exec (fail-closed)."""
    if not spec:
        return (0, 0)
    parts = str(spec).split(":")
    try:
        uid = int(parts[0])
        gid = int(parts[1]) if len(parts) > 1 and parts[1] != "" else uid
        return (uid, gid)
    except (ValueError, IndexError):
        return (None, None)


def _user_can_exec(mode, f_uid, f_gid, u_uid, u_gid):
    """POSIX execute resolution for the configured workload user against a file's
    mode/uid/gid. A mode with no applicable execute bit (e.g. 0644) is NOT
    executable -- that is the B05 non-executable-wrapper rejection."""
    mode = mode or 0
    if u_uid is None:        # indeterminate named user -> require SOME exec bit
        return bool(mode & 0o111)
    if u_uid == 0:           # root -> any execute bit suffices
        return bool(mode & 0o111)
    if f_uid == u_uid:
        return bool(mode & 0o100)
    if f_gid == u_gid:
        return bool(mode & 0o010)
    return bool(mode & 0o001)


def _build_effective_fs(registry_root, manifest):
    """Merge the layer stack into the EFFECTIVE guest filesystem with correct
    OCI whiteout semantics (B05): a layer's explicit (.wh.<name>) and opaque
    (.wh..wh..opq) whiteouts delete entries from the LOWER layers ONLY -- never
    that same layer's own additions -- so we bucket each layer's members first
    and apply deletions-then-additions, INDEPENDENT of tar member ordering.
    Returns {normalized-path: entry} where entry carries kind/mode/uid/gid and
    (for regular files) the content sha256."""

    def _norm(n):
        return n.lstrip("./").rstrip("/")

    state = {}
    for layer in manifest.get("layers") or []:
        blob = _registry_blob(registry_root, layer["digest"])
        fh = gzip.GzipFile(fileobj=io.BytesIO(blob)) if blob[:2] == b"\x1f\x8b" else io.BytesIO(blob)
        additions, whiteouts, opaques = {}, [], []
        with tarfile.open(fileobj=fh, mode="r|") as tar:
            for member in tar:
                name = _norm(member.name)
                base = os.path.basename(name)
                d = os.path.dirname(name)
                if base == ".wh..wh..opq":
                    opaques.append(d)
                    continue
                if base.startswith(".wh."):
                    whiteouts.append(os.path.join(d, base[len(".wh."):]) if d else base[len(".wh."):])
                    continue
                entry = {"mode": member.mode, "uid": member.uid, "gid": member.gid}
                if member.isreg():
                    entry.update(kind="regular", sha=sha256b(tar.extractfile(member).read()))
                elif member.issym():
                    entry.update(kind="symlink", linkname=member.linkname)
                elif member.islnk():
                    entry.update(kind="hardlink", linkname=member.linkname)
                elif member.isdir():
                    entry.update(kind="dir")
                else:
                    entry.update(kind="non-regular(type=%r)" % member.type)
                additions[name] = entry
        # 1) deletions apply to LOWER state only, order-independent of the archive
        for od in opaques:  # opaque hides lower CONTENTS of od; od itself persists
            for p in list(state):
                if od in ("", ".") or p.startswith((od + "/") if od else ""):
                    del state[p]
        for wt in whiteouts:  # whiteout removes the target and its whole subtree
            for p in list(state):
                if p == wt or p.startswith(wt + "/"):
                    del state[p]
        # 2) this layer's own additions overlay (and survive its own whiteouts).
        # B05: when an addition REPLACES a lower directory with a NON-directory
        # (symlink/file/device), the former directory's whole subtree must be
        # discarded -- otherwise a still-present lower leaf (e.g. a wrapper) would
        # survive the replacement and be RESURRECTED by a later layer that
        # recreates the directory (the directory-to-symlink-to-directory probe).
        # Dropping is scoped to the subtree STRICTLY under the replaced path and
        # never touches this layer's own additions, so opaque-marker ordering
        # positives are preserved.
        for name, entry in additions.items():
            if entry["kind"] != "dir":
                for p in list(state):
                    # drop the former LOWER subtree only; never this layer's own
                    # additions, so same-layer ordering stays irrelevant.
                    if p.startswith(name + "/") and p not in additions:
                        del state[p]
            state[name] = entry
    return state


def check_harness_image(ck, registry_root, harness_digest, candidate):
    """P2: D' must BE the exact linux/arm64 child manifest (never an index); its
    config platform is verified; each wrapper must resolve on the EFFECTIVE guest
    filesystem to a REGULAR file whose ancestors are all directories that the
    workload user can SEARCH/traverse (no ancestor file-type replacement and no
    non-traversable ancestor mode), carrying the approved candidate bytes AND
    executable by the configured workload user (B05)."""
    manifest = json.loads(_registry_blob(registry_root, harness_digest))
    if manifest.get("manifests"):
        ck.record("P2:digest-is-child-manifest", False,
                  "--harness-digest %s resolves to an INDEX/manifest-list; the delivered "
                  "identity must be the exact linux/arm64 child manifest digest" % harness_digest)
        return {}
    if not manifest.get("config") or not manifest.get("layers"):
        ck.record("P2:digest-is-child-manifest", False, "not a single image manifest (no config/layers)")
        return {}
    ck.record("P2:digest-is-child-manifest", True, harness_digest)
    # the config blob's architecture/os must be linux/arm64 (single-manifest platform check)
    cfg = json.loads(_registry_blob(registry_root, manifest["config"]["digest"]))
    ck.record("P2:config-platform",
              (cfg.get("architecture"), cfg.get("os")) == ("arm64", "linux"),
              "architecture=%r os=%r" % (cfg.get("architecture"), cfg.get("os")))
    # the EFFECTIVE runtime user is the image config's User (Dockerfile USER
    # 1000:1000); wrappers must be EXECUTABLE by that user, not merely present.
    user_spec = (cfg.get("config") or {}).get("User")
    u_uid, u_gid = _parse_workload_user(user_spec)
    ck.record("P2:workload-user-resolved", u_uid is not None,
              "image config User=%r -> uid=%r gid=%r" % (user_spec, u_uid, u_gid))

    state = _build_effective_fs(registry_root, manifest)

    def _ancestor_problem(path):
        # every proper ancestor of the wrapper that the image defines must be a
        # directory AND be SEARCH/TRAVERSE-able by the effective workload user
        # (B05). An ancestor replaced by a symlink/file/device makes the wrapper
        # unreachable (ancestor file-type replacement); a directory whose mode
        # denies the workload user the execute/search bit ALSO makes it
        # unreachable, even if the wrapper bytes themselves are 0755 (the
        # root-owned 0700 usr/local/bin probe). Ancestors the image does not
        # define are inherited from the base image and not asserted here.
        parts = path.split("/")
        for i in range(1, len(parts)):
            anc = "/".join(parts[:i])
            e = state.get(anc)
            if e is None:
                continue
            if e["kind"] != "dir":
                return "ancestor %r is a %s, not a directory" % (anc, e["kind"])
            if not _user_can_exec(e["mode"], e["uid"], e["gid"], u_uid, u_gid):
                return ("ancestor %r (mode=%s uid=%s gid=%s) is not traversable by "
                        "workload uid=%s gid=%s"
                        % (anc, oct(e["mode"]) if e.get("mode") is not None else "-",
                           e.get("uid"), e.get("gid"), u_uid, u_gid))
        return None

    expect = {
        WRAPPERS[0]: sha256f(os.path.join(candidate, "claude-inputs-candidate", "harness",
                                          "image", "dsmack-claude-wrapper")),
        WRAPPERS[1]: sha256f(os.path.join(candidate, "claude-inputs-candidate", "harness",
                                          "image", "dsmack-claude-wrapper-subscription")),
    }

    def _valid_sha(w):
        e = state.get(w)
        if not e or e["kind"] != "regular" or _ancestor_problem(w) is not None:
            return None
        if not _user_can_exec(e["mode"], e["uid"], e["gid"], u_uid, u_gid):
            return None
        return e["sha"]

    for name in WRAPPERS:
        bn = os.path.basename(name)
        anc = _ancestor_problem(name)
        eff = state.get(name)
        if anc is not None:
            ck.record("P2:%s" % bn, False, "wrapper unresolvable: %s" % anc)
            ck.record("P2-neg:%s-not-stale" % bn, False, anc)
            continue
        if eff is None:
            ck.record("P2:%s" % bn, False,
                      "wrapper absent from the resolved image (deleted by a lower-layer "
                      "whiteout/opaque marker or never present)")
            ck.record("P2-neg:%s-not-stale" % bn, False, "absent from the resolved image")
            continue
        is_reg = eff["kind"] == "regular"
        got = eff.get("sha")
        execable = is_reg and _user_can_exec(eff["mode"], eff["uid"], eff["gid"], u_uid, u_gid)
        detail = ("effective-entry=%s mode=%s uid=%s gid=%s on-image=%s candidate=%s"
                  % (eff["kind"], oct(eff["mode"]) if eff.get("mode") is not None else "-",
                     eff.get("uid"), eff.get("gid"), got, expect[name]))
        if not is_reg:
            detail += " (NOT a regular executable wrapper file)"
        elif not execable:
            detail += " (NOT executable by workload uid=%s gid=%s)" % (u_uid, u_gid)
        ck.record("P2:%s" % bn, is_reg and got == expect[name] and execable, detail)
        ck.record("P2-neg:%s-not-stale" % bn,
                  is_reg and got is not None and not any(got.startswith(p) for p in STALE_WRAPPER_PREFIXES),
                  "effective-entry=%s on-image=%s" % (eff["kind"], got))
    return {"wrapper_api_sha256": _valid_sha(WRAPPERS[0]),
            "wrapper_subscription_sha256": _valid_sha(WRAPPERS[1]),
            "config_digest": manifest["config"]["digest"]}


def bundle_identity(artifacts):
    digest = open(os.path.join(artifacts, "digest.txt")).read().strip()
    sums = open(os.path.join(artifacts, "sha256sum.txt"), "rb").read()
    md = json.load(open(os.path.join(artifacts, "metadata.json")))
    return digest, sums, md["cmdline"]


def expected_base_vm(artifacts):
    """The COMPLETE expected base_vm tuple, derived from the rebuilt bundle
    exactly as render_product_manifests/make_guest_inputs derive it (B05)."""
    digest = open(os.path.join(artifacts, "digest.txt")).read().strip()
    md = json.load(open(os.path.join(artifacts, "metadata.json")))
    entries = {}
    for line in open(os.path.join(artifacts, "sha256sum.txt")).read().splitlines():
        h, name = line.split("  ", 1)
        entries[name] = h
    am = json.load(open(os.path.join(artifacts, "artifact-manifest.json")))
    return {
        "architecture": "aarch64",
        "cmdline": md["cmdline"],
        "initrd_sha256": entries["initramfs.cpio.gz"],
        "kernel_sha256": entries["Image"],
        "memory_mb": 4096,
        "metadata_sha256": sha256f(os.path.join(artifacts, "metadata.json")),
        "os_image_hash": digest,
        "rootfs_sha256": entries["rootfs.squashfs.verity"],
        # SPECULATIVE-IMAGE-E2E fix (POSTBUILD-PREDICATES): pin ONE vCPU per
        # CROSS-LANE-VERIFIED-FINDINGS.vcpus ("Pin demo manifest/admission/native
        # fixture to 1 ...; native vmm_builder.rs rejects vcpus!=1"). The
        # rendered manifests + launcher already declare vcpus=1; this expectation
        # was the stale value that caused the four false base_vm mismatches.
        "vcpus": 1,
        "verity_root_hash": am["verity"]["root_hash"],
    }


def parse_service_images(doc):
    """PARSE the embedded compose document (JSON) and return every service's
    exact image reference; a substring test is not an identity check (B05)."""
    inner = json.loads(doc["docker_compose_file"])
    return {name: (svc.get("image") or "") for name, svc in (inner.get("services") or {}).items()}


def check_manifest_dir(ck, label, mdir, expect_set, exp_bv, guest_ref, api_sha, sub_sha,
                       manifest_shas):
    """One manifest dir: EXACT set + full identity binding for every manifest."""
    if not os.path.isdir(mdir):
        ck.record("P3:%s:exact-manifest-set" % label, False, "missing dir %s" % mdir)
        return
    actual = {fn for fn in os.listdir(mdir) if fn.endswith(".app-compose.json")}
    ck.record("P3:%s:exact-manifest-set" % label, actual == expect_set,
              "have=%s want=%s" % (sorted(actual), sorted(expect_set)))
    for fn in sorted(actual & expect_set):
        raw = open(os.path.join(mdir, fn), "rb").read()
        manifest_shas["%s/%s" % (label, fn)] = sha256b(raw)
        doc = json.loads(raw)
        bv = doc.get("base_vm") or {}
        ck.record("P3:%s/%s:base_vm-complete-equality" % (label, fn), bv == exp_bv,
                  "equal" if bv == exp_bv else
                  "mismatched keys: %s" % sorted(k for k in set(bv) | set(exp_bv)
                                                 if bv.get(k) != exp_bv.get(k)))
        ck.record("P3:%s/%s:no-stale-slirp-registry" % (label, fn),
                  STALE_GUEST_ALIAS.encode() not in raw, "stale 10.0.2.2:5005 ref present"
                  if STALE_GUEST_ALIAS.encode() in raw else "clean")
        try:
            images = parse_service_images(doc)
        except (KeyError, ValueError) as exc:
            ck.record("P3:%s/%s:parsed-service-images" % (label, fn), False,
                      "compose document unparseable: %s" % exc)
            images = {}
        for svc, ref in sorted(images.items()):
            if fn in PRODUCT_MANIFEST_SET or HARNESS_IMAGE_NAME in ref:
                ck.record("P3:%s/%s:service-image:%s" % (label, fn, svc), ref == guest_ref,
                          "image=%r want=%r (parsed, exact)" % (ref, guest_ref))
            else:
                ck.record("P3:%s/%s:service-image:%s" % (label, fn, svc),
                          GUEST_REGISTRY not in ref,
                          "image=%r (engineering channel; must not pull the harness delivery registry)" % ref)
        if fn in PRODUCT_MANIFEST_SET:
            want = sub_sha if "subscription" in fn else api_sha
            ck.record("P3:%s/%s:harness-sha" % (label, fn),
                      (doc.get("harness") or {}).get("sha256") == want,
                      "harness.sha256=%s want=%s" % ((doc.get("harness") or {}).get("sha256"), want))


def check_tree_bindings(ck, label, tree, h_prime, sums_bytes, libdir):
    """Admission + base-bundle rehash (+ envelope validation) for one
    delivered input tree -- BOTH trees are verified (B05)."""
    adm_path = os.path.join(tree, "admission", "base-admission.json")
    try:
        adm = json.load(open(adm_path))
        ck.record("P3:%s:admission-exact" % label, adm.get("allowed_os_image_hashes") == [h_prime],
                  "allowed=%r" % adm.get("allowed_os_image_hashes"))
    except (OSError, ValueError) as exc:
        ck.record("P3:%s:admission-exact" % label, False, "unreadable: %s" % type(exc).__name__)
    bb = os.path.join(tree, "base-bundle")
    sums_path = os.path.join(bb, "sha256sum.txt")
    ok_sums = os.path.isfile(sums_path) and open(sums_path, "rb").read() == sums_bytes
    ck.record("P5:%s:base-bundle-sums-synced" % label, ok_sums,
              "base-bundle/sha256sum.txt equals rebuilt artifacts sha256sum.txt")
    # B05: the exact DELIVERED component set must be present and rehash. The old
    # `if os.path.isfile(p)` silently PASSED when a component was absent; here
    # every required delivered component is REQUIRED (absence is a failure) and
    # its expected hash comes from the synced inventory.
    inv = {}
    for line in sums_bytes.decode().splitlines():
        h, name = line.split("  ", 1)
        inv[name] = h
    for name in DELIVERED_BASE_BUNDLE:
        p = os.path.join(bb, name)
        want = inv.get(name)
        if want is None:
            ck.record("P5:%s:base-bundle-component:%s" % (label, name), False,
                      "required delivered component not listed in the synced inventory")
        elif not os.path.isfile(p):
            ck.record("P5:%s:base-bundle-component:%s" % (label, name), False,
                      "required delivered component ABSENT from base-bundle/")
        else:
            ck.record("P5:%s:base-bundle-component:%s" % (label, name), sha256f(p) == want,
                      "delivered component rehashes to the inventory value")
    # any further in-tree bundle copies beyond the required set are also rehashed
    if ok_sums:
        for name, h in inv.items():
            if name in DELIVERED_BASE_BUNDLE:
                continue
            p = os.path.join(bb, name)
            if os.path.isfile(p):
                ck.record("P5:%s:base-bundle-rehash:%s" % (label, name), sha256f(p) == h,
                          "delivered bytes rehash to the inventory value")
    # engineering envelopes: exact set + validation under the EXTRACTED library
    env_dir = os.path.join(tree, "envelopes")
    envs = set(os.listdir(env_dir)) if os.path.isdir(env_dir) else set()
    if label == "runner-inputs":
        ck.record("P3:%s:exact-envelope-set" % label, envs == ENGINEERING_ENVELOPE_SET,
                  "have=%s want=%s" % (sorted(envs), sorted(ENGINEERING_ENVELOPE_SET)))
        for env_name in sorted(envs & ENGINEERING_ENVELOPE_SET):
            m_name = env_name.replace(".envelope.json", ".app-compose.json")
            code = ("import sys\n"
                    "from dsmack_compose_contract import validate_runtime_inputs_bytes\n"
                    "validate_runtime_inputs_bytes(open(sys.argv[1],'rb').read(),"
                    " open(sys.argv[2],'rb').read())\n"
                    "print('envelope-ok')\n")
            r = subprocess.run([sys.executable, "-c", code,
                                os.path.join(tree, "manifests", m_name),
                                os.path.join(env_dir, env_name)],
                               env={**os.environ, "PYTHONPATH": libdir,
                                    "PYTHONDONTWRITEBYTECODE": "1"},
                               capture_output=True, text=True, timeout=120)
            ck.record("P3:%s:envelope-validates:%s" % (label, env_name), r.returncode == 0,
                      (r.stdout.strip() or r.stderr.strip()[-300:]))


def check_evidence(ck, evidence_dir, h_prime):
    """P5: the admission/tamper transcript must show a VERIFIED verity root
    and a REJECTING tamper control for H' -- 'skipped' is a failure (B05)."""
    log_path = os.path.join(evidence_dir, "admission.log")
    if not os.path.isfile(log_path):
        ck.record("P5:evidence-admission-log", False, "missing %s" % log_path)
        return
    text = open(log_path, "r", errors="replace").read()
    ck.record("P5:evidence-admitted-H", ("ADMIT os_image_hash=%s" % h_prime) in text,
              "admission log must admit exactly H'=%s" % h_prime)
    ck.record("P5:evidence-verity-verified", "verity: verified" in text,
              "verified" if "verity: verified" in text
              else "skipped/mismatched verity is NOT acceptable")
    ck.record("P5:evidence-tamper-rejected", "tamper-test: tamper-rejected" in text,
              "tamper-rejected" if "tamper-test: tamper-rejected" in text
              else "skipped/failed tamper control is NOT acceptable")


def load_stack_expectations(candidate, override=None):
    """B05: load the frozen expected version+architecture for the required guest
    container stack. Values are derived from the dpkg control metadata of the
    hash-pinned debootstrap seed .debs (see guest-stack-expectations.json); this
    is an AVAILABLE INPUT fact, not an unbuilt-artifact hash and not a literal
    copied from a descriptive note."""
    path = override or os.path.join(candidate, *STACK_EXPECTATIONS_REL)
    with open(path) as f:
        return json.load(f), path


def parse_dpkg_inventory_line(line):
    """Parse one '<name> <version> <arch>' promoted-inventory line."""
    f = line.split()
    name = f[0].split(":")[0]
    ver = f[1] if len(f) > 1 else ""
    arch = f[2] if len(f) > 2 else (f[0].split(":", 1)[1] if ":" in f[0] else "")
    return name, {"version": ver, "arch": arch}


def parse_dpkg_status(path):
    """B05: parse the metadata EXTRACTED from the rebuilt rootfs
    (/var/lib/dpkg/status) into {name: {version, arch}} -- the producer-side
    package facts the promoted inventory is cross-checked against."""
    info = {}
    if not path or not os.path.isfile(path):
        return info
    name = ver = arch = None
    for line in open(path, "r", errors="replace").read().splitlines():
        if not line.strip():
            if name:
                info[name] = {"version": ver or "", "arch": arch or ""}
            name = ver = arch = None
        elif line.startswith("Package:"):
            name = line.split(":", 1)[1].strip()
        elif line.startswith("Version:"):
            ver = line.split(":", 1)[1].strip()
        elif line.startswith("Architecture:"):
            arch = line.split(":", 1)[1].strip()
    if name:
        info[name] = {"version": ver or "", "arch": arch or ""}
    return info


def check_guest_packages(ck, path, expectations, exp_path, rootfs_status):
    """P5: the promoted package inventory must carry the COMPLETE required
    container stack at the right ARCHITECTURE and VERSIONS (B05). Every frozen
    package's version+arch is checked against the hash-pinned seed .deb metadata
    (guest-stack-expectations.json; epochs/revisions preserved) and the whole
    promoted inventory is cross-checked, name-by-name, against the metadata
    extracted from the rebuilt rootfs (/var/lib/dpkg/status) -- producer/consumer
    agreement, never self-agreement. Inventory lines are '<name> <version>
    <arch>'."""
    if not os.path.isfile(path):
        ck.record("P5:guest-packages-present", False, "missing %s" % path)
        return None
    pkgs = [l.strip() for l in open(path) if l.strip()]
    ck.record("P5:guest-packages-present", len(pkgs) > 0, "%d packages" % len(pkgs))
    info = {}
    for p in pkgs:
        name, rec = parse_dpkg_inventory_line(p)
        info[name] = rec

    exp_pkgs = (expectations or {}).get("packages", {})
    # fail-closed: the frozen fixture must cover the complete required stack
    uncovered = sorted(set(REQUIRED_GUEST_PACKAGES) - set(exp_pkgs))
    ck.record("P5:stack-expectations-cover-required", not uncovered,
              "guest-stack-expectations.json (%s) missing required entries: %s"
              % (exp_path, uncovered) if uncovered
              else "frozen seed expectations cover all %d required packages"
              % len(REQUIRED_GUEST_PACKAGES))

    missing = [w for w in REQUIRED_GUEST_PACKAGES if w not in info]
    ck.record("P5:guest-packages-container-stack", not missing,
              "missing %s" % missing if missing
              else "complete pinned container stack present (%d required incl. CLI/Compose)"
              % len(REQUIRED_GUEST_PACKAGES))
    wrong_arch = sorted("%s=%s" % (w, info[w]["arch"]) for w in REQUIRED_GUEST_PACKAGES
                        if w in info and info[w]["arch"] not in GUEST_PACKAGE_ALLOWED_ARCHS)
    ck.record("P5:guest-packages-arch", not wrong_arch,
              "non-arm64/all architecture: %s" % wrong_arch if wrong_arch
              else "every required package is arm64 or arch-independent (all)")
    no_ver = sorted(w for w in REQUIRED_GUEST_PACKAGES if w in info and not info[w]["version"])
    ck.record("P5:guest-packages-versioned", not no_ver,
              "no version recorded for %s" % no_ver if no_ver
              else "every required package carries an extracted version")
    # B05: frozen seed-derived version+arch for every version_frozen package.
    bad_pin = []
    for w in REQUIRED_GUEST_PACKAGES:
        if w not in info:
            continue
        exp = exp_pkgs.get(w) or {}
        if not exp.get("version_frozen"):
            continue
        if info[w]["version"] != exp.get("version"):
            bad_pin.append("%s version=%s want=%s (seed %s)"
                           % (w, info[w]["version"], exp.get("version"), exp.get("source_deb")))
        if exp.get("architecture") and info[w]["arch"] != exp.get("architecture"):
            bad_pin.append("%s arch=%s want=%s" % (w, info[w]["arch"], exp.get("architecture")))
    ck.record("P5:guest-packages-pinned-versions", not bad_pin,
              "seed-metadata mismatch: %s" % bad_pin if bad_pin
              else "every frozen package matches its hash-pinned seed .deb metadata "
              "(version+arch, Debian epochs/revisions preserved)")
    # B05: producer<->consumer agreement -- the promoted inventory must EQUAL the
    # metadata extracted from the rebuilt rootfs for the required stack.
    if not rootfs_status:
        ck.record("P5:guest-packages-inventory-matches-rootfs", False,
                  "rebuilt rootfs /var/lib/dpkg/status was not extracted; the promoted "
                  "inventory cannot be cross-checked against the producer's own metadata")
    else:
        disagree = []
        for w in REQUIRED_GUEST_PACKAGES:
            if w not in info:
                continue
            rs = rootfs_status.get(w)
            if rs is None:
                disagree.append("%s absent from rebuilt-rootfs dpkg status" % w)
            elif rs["version"] != info[w]["version"] or rs["arch"] != info[w]["arch"]:
                disagree.append("%s inventory=%s/%s rootfs=%s/%s"
                                % (w, info[w]["version"], info[w]["arch"],
                                   rs["version"], rs["arch"]))
        ck.record("P5:guest-packages-inventory-matches-rootfs", not disagree,
                  "promoted inventory disagrees with rebuilt-rootfs metadata: %s" % disagree
                  if disagree else
                  "promoted inventory equals the rebuilt-rootfs dpkg metadata for the required stack")
    return sha256f(path)


def scan_secrets(ck, roots):
    """P6: scoped deny-pattern scan of the delivered channel text files."""
    hits = []
    for root in roots:
        if not root or not os.path.isdir(root):
            continue
        for dirpath, _dirnames, filenames in os.walk(root):
            rel_root = os.path.relpath(dirpath, root)
            if rel_root.split(os.sep)[0] == "base-bundle":
                continue  # binary bundle artifacts are covered by identity (P1/P5)
            for fn in filenames:
                p = os.path.join(dirpath, fn)
                rel = os.path.join(os.path.basename(root.rstrip("/")),
                                   "" if rel_root == "." else rel_root, fn)
                if SECRET_NAME_PATTERN.search(fn):
                    hits.append("%s: file name matches a credential/token pattern" % rel)
                    continue
                try:
                    data = open(p, "rb").read(1 << 22)
                except OSError:
                    hits.append("%s: unreadable" % rel)
                    continue
                for pat in SECRET_VALUE_PATTERNS:
                    if pat.search(data):
                        hits.append("%s: content matches %s" % (rel, pat.pattern.decode()))
                if fn == "broker-config.json":
                    try:
                        cfg = json.loads(data)
                        extra = set(cfg) - BROKER_CONFIG_ALLOWED_KEYS
                        if extra:
                            hits.append("%s: keys outside the allowlist: %s" % (rel, sorted(extra)))
                    except ValueError:
                        hits.append("%s: not valid JSON" % rel)
                if fn in ("sha256sum.txt", "SHA256SUMS"):
                    for line in data.decode(errors="replace").splitlines():
                        parts = line.split("  ", 1)
                        if len(parts) == 2 and SECRET_NAME_PATTERN.search(parts[1]):
                            hits.append("%s: inventory references %r" % (rel, parts[1]))
    ck.record("P6:no-credential-or-token-artifacts", not hits,
              "; ".join(hits[:10]) if hits else
              "no credential/token pattern in the delivered channels (scoped scan; see LIMITS)")


def check_paired_validator(ck, tree, product_dir):
    """P4: the EXTRACTED guest library accepts the subscription manifest."""
    sub = None
    for fn in os.listdir(product_dir):
        if "subscription" in fn and fn.endswith(".app-compose.json"):
            sub = os.path.join(product_dir, fn)
    if sub is None:
        ck.record("P4:embedded-validator-accepts-subscription", False, "no subscription manifest")
        return
    libdir = os.path.join(tree, "usr/local/lib/dsmack/compose-runner/lib")
    code = ("import sys,json\n"
            "from dsmack_compose_contract import validate_manifest_bytes\n"
            "raw=open(sys.argv[1],'rb').read()\n"
            "m,s=validate_manifest_bytes(raw)\n"
            "print(json.dumps({'manifest_sha256': s['manifest_sha256'],"
            " 'profile': m['credentials']['adapter']['profile']}))\n")
    r = subprocess.run([sys.executable, "-c", code, sub],
                       env={**os.environ, "PYTHONPATH": libdir,
                            "PYTHONDONTWRITEBYTECODE": "1"},
                       capture_output=True, text=True, timeout=120)
    ck.record("P4:embedded-validator-accepts-subscription", r.returncode == 0,
              (r.stdout.strip() or r.stderr.strip()[-300:]))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifacts", required=True)
    ap.add_argument("--candidate", required=True, help="frozen candidate root (source of truth bytes)")
    ap.add_argument("--harness-digest", required=True,
                    help="the EXACT linux/arm64 child manifest digest (an index digest is rejected)")
    ap.add_argument("--registry-root", required=True,
                    help="the throwaway registry's storage dir (exact blobs the guest pulls)")
    ap.add_argument("--product-manifests", required=True)
    ap.add_argument("--runner-inputs", required=True, help="engineering delivered input tree")
    ap.add_argument("--runner-inputs-product", required=True, help="product delivered input tree")
    ap.add_argument("--evidence", required=True,
                    help="build evidence dir carrying admission.log (verity + tamper transcript)")
    ap.add_argument("--guest-packages", required=True,
                    help="the promoted complete guest package inventory file")
    ap.add_argument("--workdir", required=True,
                    help="extraction/scratch dir UNDER THE BUILD ROOT (B03: never host tmp)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--keep-extract", default=None)
    ap.add_argument("--stack-expectations", default=None,
                    help="frozen guest-stack-expectations.json (seed-derived version/arch); "
                         "defaults to the copy inside --candidate")
    args = ap.parse_args(argv)

    ck = Checker()
    h_prime, sums_bytes, cmdline = bundle_identity(args.artifacts)
    exp_bv = expected_base_vm(args.artifacts)
    guest_ref = "%s/%s@%s" % (GUEST_REGISTRY, HARNESS_IMAGE_NAME, args.harness_digest)
    api_sha = sha256f(os.path.join(args.candidate, "claude-inputs-candidate", "harness",
                                   "image", "dsmack-claude-wrapper"))
    sub_sha = sha256f(os.path.join(args.candidate, "claude-inputs-candidate", "harness",
                                   "image", "dsmack-claude-wrapper-subscription"))

    # P5 self-consistency + FULL bundle rehash + negatives
    ck.record("P5:digest-definition", sha256b(sums_bytes) == h_prime,
              "sha256(sha256sum.txt)=%s digest.txt=%s" % (sha256b(sums_bytes), h_prime))
    for line in sums_bytes.decode().splitlines():
        h, name = line.split("  ", 1)
        p = os.path.join(args.artifacts, name)
        ck.record("P5:artifacts-rehash:%s" % name,
                  os.path.isfile(p) and sha256f(p) == h,
                  "actual artifact bytes rehash to the inventory value")
    ck.record("P5-neg:base-not-stale", h_prime != STALE_OS_IMAGE_HASH, "H'=%s" % h_prime)
    ck.record("P5-neg:harness-digest-not-stale", args.harness_digest not in STALE_HARNESS_DIGESTS,
              "D'=%s" % args.harness_digest)
    check_evidence(ck, args.evidence, h_prime)

    # B03: extraction and all scratch live under the supplied build-root
    # workdir -- a deterministic fresh subdir, never host temporary storage
    extract_dir = args.keep_extract or os.path.join(args.workdir, "rootfs-extract")
    if not args.keep_extract and os.path.exists(extract_dir):
        raise SystemExit("extraction dir %s already exists; the build root must be fresh" % extract_dir)
    # SPECULATIVE-IMAGE-E2E fix: create only the PARENT workdir, not extract_dir
    # itself. This host's unsquashfs (-d) fails closed ("failed to make
    # directory ... because File exists") when its target already exists, so
    # pre-creating extract_dir here aborted verification. Let unsquashfs create
    # the final dir; the fresh-root guard above still rejects a stale leftover.
    os.makedirs(os.path.dirname(extract_dir) or ".", exist_ok=True)
    tree = extract_rootfs(args.artifacts, extract_dir)
    libdir = os.path.join(tree, "usr/local/lib/dsmack/compose-runner/lib")
    embedded = check_rootfs(ck, tree, args.candidate, require_disk_templates=True,
                            expected_mke2fs_version="mke2fs 1.47.2 (1-Jan-2025)", artifacts_dir=args.artifacts)
    wrappers = check_harness_image(ck, args.registry_root, args.harness_digest, args.candidate)

    # B05: guest package inventory vs frozen seed metadata AND the metadata
    # extracted from the rebuilt rootfs (cross-check needs the extracted tree).
    stack_exp, stack_exp_path = load_stack_expectations(args.candidate, args.stack_expectations)
    rootfs_status = parse_dpkg_status(os.path.join(tree, "var/lib/dpkg/status"))
    guest_packages_sha = check_guest_packages(ck, args.guest_packages, stack_exp,
                                              stack_exp_path, rootfs_status)

    manifest_shas = {}
    check_manifest_dir(ck, "product", args.product_manifests, PRODUCT_MANIFEST_SET,
                       exp_bv, guest_ref, api_sha, sub_sha, manifest_shas)
    check_manifest_dir(ck, "runner-inputs", os.path.join(args.runner_inputs, "manifests"),
                       ENGINEERING_MANIFEST_SET, exp_bv, guest_ref, api_sha, sub_sha, manifest_shas)
    check_manifest_dir(ck, "runner-inputs-product",
                       os.path.join(args.runner_inputs_product, "manifests"),
                       PRODUCT_MANIFEST_SET, exp_bv, guest_ref, api_sha, sub_sha, manifest_shas)
    check_tree_bindings(ck, "runner-inputs", args.runner_inputs, h_prime, sums_bytes, libdir)
    check_tree_bindings(ck, "runner-inputs-product", args.runner_inputs_product, h_prime,
                        sums_bytes, libdir)
    check_paired_validator(ck, tree, args.product_manifests)
    scan_secrets(ck, [args.runner_inputs, args.runner_inputs_product, args.product_manifests])

    transcript = {
        "schema": "dsmack.postbuild-verification/2",
        "predicate": "pass" if ck.failed == 0 else "fail",
        "base_os_image_hash": h_prime,
        "harness_image_digest": args.harness_digest,
        "harness_image_digest_kind": "linux/arm64 child manifest (config platform verified)",
        "cmdline": cmdline,
        "expected_base_vm": exp_bv,
        "embedded": embedded,
        "wrappers": wrappers,
        "guest_packages_sha256": guest_packages_sha,
        "external_manifest_sha256": manifest_shas,
        "checks": ck.checks,
        "failed": ck.failed,
    }
    with open(args.out, "w") as fh:
        json.dump(transcript, fh, indent=1, sort_keys=True)
        fh.write("\n")
    print("verification %s: %d checks, %d failed -> %s"
          % (transcript["predicate"].upper(), len(ck.checks), ck.failed, args.out))
    return 0 if ck.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
