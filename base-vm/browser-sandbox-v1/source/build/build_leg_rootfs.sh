#!/bin/bash
# Rootfs build for one reproducibility leg (lane dstack-runner-join).
# Byte-logic port of dstack-smoke-finish/source/build/build_leg_rootfs.sh
# (prior lane, read-only). Documented deltas — everything else verbatim
# (debootstrap --foreign, dpkg-deb -x unpack, synthesized status, overlays,
# fail-fast checks):
#   JOIN-1: the kernel is NOT rebuilt. This lane starts from the PROVEN
#     dstack-smoke-finish bundle (os_image_hash ec83a3fc…): Image +
#     config-6.18.40-dstack are taken byte-identical from /proven, and the
#     module store is extracted per leg from the proven verity rootfs itself
#     (same bytes both legs; the tar/verity assembly re-measures everything).
#   JOIN-2: guest package list += python3 (the approved compose runner is the
#     contract10 Python package; stdlib-only, Python 3.10+ per the library).
#   JOIN-3: the APPROVED runner content is installed into the rootfs:
#     /usr/local/lib/dsmack/compose-runner/{dsmack_compose_runner,lib/
#     dsmack_compose_contract} + /usr/local/bin/dsmack-compose-runner
#     (installed-form wrapper: same argparse surface, sys.path pointed at the
#     installed locations) + SHA256SUMS of the installed bytes. The bytes come
#     from this lane's source/runner-content copy, which was verified
#     byte-identical to the frozen compose-runner inventory before the build
#     (evidence/runner-content-copy-verify.txt).
#   JOIN-4 (S01, this freeze): the per-run credential SENTINEL package and its
#     dependency modules (harness/__init__.py + harness/sentinel/{__init__,
#     sentinel,sentinel_oauth}.py + harness/adapter/{__init__,
#     claude_subscription_document}.py — all stdlib-only) are installed into
#     the rootfs at /usr/local/lib/dsmack/sentinel/harness/… so the
#     supervisor's broker lifecycle (start_broker) runs the sentinel as
#     MEASURED rootfs bytes. Source: the frozen candidate mounted read-only
#     at /cand. SHA256SUMS of the installed sentinel bytes are recorded in
#     the rootfs alongside the runner's.
# Runs INSIDE dsmack-dstack-arm64/builder:trixie-20260721 with this lane at /w
# (source ro + build rw submounts; see BUILD.sh), the frozen candidate root
# read-only at /cand, dstack-base-image read-only at /prior (debootstrap seed
# cache), and dstack-smoke-finish read-only at /proven (kernel bytes).
set -euo pipefail
umask 0022

W=/w
LANE=$W
PRIOR=/prior
PROVEN=/proven
CAND=/cand
PROFILE=$LANE/source/profile/dstack-trixie-arm64-minimal
LEG_REL=${1:?leg name required}
LEG=$LANE/build/legs/$LEG_REL
export SOURCE_DATE_EPOCH=1784592000
export TZ=UTC LC_ALL=C

KERNEL_VERSION=6.18.40
DEBIAN_RELEASE=trixie
DEBIAN_SNAPSHOT=20260721T000000Z
DSTACK_UPSTREAM_REVISION=247c3add65d0e8e6ba90eae5f6b981a9063cf701
IMAGE_NAME=dstack-trixie-arm64-minimal
IMAGE_VERSION=0.6.3.runner
MIRROR="https://snapshot.debian.org/archive/debian/$DEBIAN_SNAPSHOT"
PACKAGES=docker.io,docker-cli,docker-compose,containerd,busybox-static,bash,ca-certificates,iproute2,dmsetup,cryptsetup-bin,python3

# ---- kernel bytes from the PROVEN bundle (no rebuild this lane) ----
[ -f "$PROVEN/build/artifacts/Image" ] && [ -f "$PROVEN/build/artifacts/config-$KERNEL_VERSION-dstack" ] || {
  echo "proven kernel artifacts missing at /proven/build/artifacts" >&2; exit 1; }
sha256sum -c --status <<EOF || { echo 'proven kernel/rootfs bytes do not match the ec83a3fc bundle pins' >&2; exit 1; }
415e59cc1fbaa957b8737749f0e7822e4d843b27b363345cdb9e6a2a870a6d88  $PROVEN/build/artifacts/Image
4cf4325bff9c5ed1078487c5aa6b25b4b8179db0b64e306c2215239eab21ba99  $PROVEN/build/artifacts/config-$KERNEL_VERSION-dstack
5720f6049c2c524c83b8e0932cdbe7dceac6dea2532c0d82401e67118dc84395  $PROVEN/build/artifacts/rootfs.squashfs.verity
EOF
mkdir -p "$LEG/files"
install -m0644 "$PROVEN/build/artifacts/Image" "$LEG/files/Image"
install -m0644 "$PROVEN/build/artifacts/config-$KERNEL_VERSION-dstack" "$LEG/files/config-$KERNEL_VERSION-dstack"

# ---- rootfs (verbatim prior logic) ----
# (this lane has no kernel phase, so the leg's work/ and files/ dirs are
# created here — the prior flow created them in build_kernel_leg.sh)
mkdir -p "$LEG/files" "$LEG/work"
TREE=$LEG/work/rootfs
mkdir -p "$TREE"
if compgen -G "$PRIOR/cache/debootstrap/*.deb" >/dev/null; then
  mkdir -p "$TREE/var/cache/apt/archives"
  cp "$PRIOR"/cache/debootstrap/*.deb "$TREE/var/cache/apt/archives/"
fi
debootstrap --foreign --arch=arm64 --variant=minbase \
    --include="$PACKAGES" "$DEBIAN_RELEASE" "$TREE" "$MIRROR" \
    >"$LEG/work/debootstrap.log" 2>&1 || { tail -n 30 "$LEG/work/debootstrap.log"; exit 1; }
mapfile -t debs < <(find "$TREE/var/cache/apt/archives" "$TREE/debootstrap" \
    -name '*.deb' -type f 2>/dev/null | LC_ALL=C sort)
[ ${#debs[@]} -gt 0 ] || { echo 'no downloaded debs found after debootstrap --foreign' >&2; exit 1; }
: > "$TREE/var/lib/dpkg/status"
for deb in "${debs[@]}"; do
  dpkg-deb -x "$deb" "$TREE"
  pkg=$(dpkg-deb -f "$deb" Package); ver=$(dpkg-deb -f "$deb" Version); arch=$(dpkg-deb -f "$deb" Architecture)
  grep -q "^Package: $pkg$" "$TREE/var/lib/dpkg/status" || \
    printf 'Package: %s\nStatus: install ok unpacked\nArchitecture: %s\nVersion: %s\n\n' \
      "$pkg" "$arch" "$ver" >> "$TREE/var/lib/dpkg/status"
done
echo "stage-2 unpack: ${#debs[@]} debs extracted into rootfs"
rm -rf "$TREE/var/cache/apt/archives" "$TREE/debootstrap"

install -D -m0755 "$LANE/source/guest/supervisor-dstack-trixie.sh" "$TREE/usr/bin/dsmack-supervisor"
install -D -m0644 "$PROFILE/docker-daemon.json" "$TREE/etc/docker/daemon.json"
install -d -m0755 "$TREE/etc/docker"
# docker-state mountpoint must exist IN the image: the verity root is
# read-only (prior lane smoke try4, fail 7).
install -d -m0755 "$TREE/var/lib/docker"
echo dstack > "$TREE/etc/hostname"
ln -sfn /usr/share/zoneinfo/UTC "$TREE/etc/localtime" 2>/dev/null || true
printf '%s\n' \
  '{"image":"'$IMAGE_NAME'","version":"'$IMAGE_VERSION'", ' \
  '"derived_from":"Dstack-TEE/dstack@'$DSTACK_UPSTREAM_REVISION'", ' \
  '"debian_snapshot":"'$DEBIAN_SNAPSHOT'","platform":"arm64"}' \
  > "$TREE/etc/dstack-image.json"
for alt in iptables ip6tables; do
  for sub in '' -restore -save; do
    [ -e "$TREE/usr/sbin/$alt-nft$sub" ] && ln -sfn "$alt-nft$sub" "$TREE/usr/sbin/$alt$sub"
  done
done
mapfile -t certs < <(find "$TREE/usr/share/ca-certificates" -name '*.crt' -type f 2>/dev/null | LC_ALL=C sort)
if [ ${#certs[@]} -gt 0 ]; then
  mkdir -p "$TREE/etc/ssl/certs"
  : > "$TREE/etc/ssl/certs/ca-certificates.crt"
  for c in "${certs[@]}"; do cat "$c" >> "$TREE/etc/ssl/certs/ca-certificates.crt"; done
fi
local_missing=()
for f in usr/sbin/dockerd usr/bin/docker usr/bin/containerd usr/bin/runc \
         usr/sbin/iptables etc/ssl/certs/ca-certificates.crt usr/bin/python3 \
         usr/libexec/docker/cli-plugins/docker-compose; do
  [ -e "$TREE/$f" ] || local_missing+=("$f")
done
find "$TREE" -maxdepth 3 -type f -name busybox | grep -q . || local_missing+=('busybox (any bin dir)')
[ ${#local_missing[@]} -eq 0 ] || { echo "guest prerequisites missing after unpack: ${local_missing[*]}" >&2; exit 1; }

# ---- JOIN-3: install the APPROVED runner content (verified copy) ----
RDEST=$TREE/usr/local/lib/dsmack/compose-runner
install -d -m0755 "$TREE/usr/local/bin" "$RDEST/dsmack_compose_runner" "$RDEST/lib/dsmack_compose_contract"
install -m0644 $LANE/source/runner-content/dsmack_compose_runner/*.py \
  "$RDEST/dsmack_compose_runner/"
install -m0644 $LANE/source/runner-content/lib/dsmack_compose_contract/*.py \
  "$RDEST/lib/dsmack_compose_contract/"
install -m0644 "$LANE/source/runner-content/lib/dsmack_compose_contract/browser-sandbox-v1.json" \
  "$RDEST/lib/dsmack_compose_contract/"
cat > "$TREE/usr/local/bin/dsmack-compose-runner" <<'EOF'
#!/usr/bin/python3
"""dsmack-compose-runner -- installed-form CLI entry (lane dstack-runner-join).

Same argparse surface and behavior as the approved candidate's
bin/dsmack-compose-runner; the ONLY delta is sys.path: this build installs the
package and the read-only contract library under
/usr/local/lib/dsmack/compose-runner (measured rootfs bytes, see SHA256SUMS).
"""
import os
import sys

_BASE = "/usr/local/lib/dsmack/compose-runner"
for path in (_BASE, os.path.join(_BASE, "lib")):
    sys.path.insert(0, path)

from dsmack_compose_runner.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
EOF
chmod 0755 "$TREE/usr/local/bin/dsmack-compose-runner"
( cd "$RDEST" && find . -type f | LC_ALL=C sort | xargs sha256sum ) \
  > "$RDEST/SHA256SUMS"
python3 -c "import ast,sys; ast.parse(open('$TREE/usr/local/bin/dsmack-compose-runner').read())"
echo "runner content installed: $(grep -c . "$RDEST/SHA256SUMS") files"

# ---- JOIN-4 (S01): install the per-run credential sentinel package ----
# The supervisor launches the sentinel as a flat script
# (python3 /usr/local/lib/dsmack/sentinel/harness/sentinel/sentinel.py); its
# __main__ shim re-enters through the package path three levels up, so the
# installed tree MUST preserve the harness/{sentinel,adapter} package layout.
SSRC=$CAND/claude-inputs-candidate/harness
for need in "$SSRC/__init__.py" "$SSRC/sentinel/__init__.py" \
            "$SSRC/sentinel/sentinel.py" "$SSRC/sentinel/sentinel_oauth.py" \
            "$SSRC/adapter/__init__.py" \
            "$SSRC/adapter/claude_subscription_document.py"; do
  [ -f "$need" ] || { echo "sentinel source missing: $need (candidate not mounted at /cand?)" >&2; exit 1; }
done
SDEST=$TREE/usr/local/lib/dsmack/sentinel/harness
install -d -m0755 "$SDEST/sentinel" "$SDEST/adapter"
install -m0644 "$SSRC/__init__.py" "$SDEST/__init__.py"
install -m0644 "$SSRC/sentinel/__init__.py" "$SDEST/sentinel/__init__.py"
install -m0644 "$SSRC/sentinel/sentinel.py" "$SDEST/sentinel/sentinel.py"
install -m0644 "$SSRC/sentinel/sentinel_oauth.py" "$SDEST/sentinel/sentinel_oauth.py"
install -m0644 "$SSRC/adapter/__init__.py" "$SDEST/adapter/__init__.py"
install -m0644 "$SSRC/adapter/claude_subscription_document.py" "$SDEST/adapter/claude_subscription_document.py"
for pyf in "$SDEST/sentinel/sentinel.py" "$SDEST/sentinel/sentinel_oauth.py" \
           "$SDEST/adapter/claude_subscription_document.py"; do
  python3 -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$pyf"
done
( cd "$TREE/usr/local/lib/dsmack/sentinel" && find . -type f | LC_ALL=C sort | xargs sha256sum ) \
  > "$TREE/usr/local/lib/dsmack/sentinel/SHA256SUMS"
echo "sentinel package installed: $(grep -c . "$TREE/usr/local/lib/dsmack/sentinel/SHA256SUMS") files"

# ---- JOIN-5 (guest-io-integration): install the measured guest-I/O helpers ----
# The trusted supervisor invokes these as MEASURED rootfs bytes for the generic
# I/O-continuity delta: the safe private-input transport parser (vde reader) and
# the portable offline digest-preserving OCI publisher. Source is this lane's
# own runner-content/dsmack_guest_io copy (stdlib-only; no dependency on the
# contract library or any caller-provided helper). An installed-form wrapper
# /usr/local/bin/dsmack-guest-io points sys.path at the installed package.
GDEST=$TREE/usr/local/lib/dsmack/guest-io
install -d -m0755 "$GDEST/dsmack_guest_io"
install -m0644 $LANE/source/runner-content/dsmack_guest_io/*.py "$GDEST/dsmack_guest_io/"
cat > "$TREE/usr/local/bin/dsmack-guest-io" <<'EOF'
#!/usr/bin/python3
"""dsmack-guest-io -- installed-form CLI entry (guest-io-integration).

Same argparse surface as dsmack_guest_io.cli; the only delta is sys.path,
pointed at the measured install location /usr/local/lib/dsmack/guest-io.
"""
import os
import sys

sys.path.insert(0, "/usr/local/lib/dsmack/guest-io")

from dsmack_guest_io.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
EOF
chmod 0755 "$TREE/usr/local/bin/dsmack-guest-io"
for pyf in "$GDEST"/dsmack_guest_io/*.py "$TREE/usr/local/bin/dsmack-guest-io"; do
  python3 -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$pyf"
done
# GIO10: exclude the checksum inventory from its own enumeration. The `>`
# redirection creates (truncates) SHA256SUMS BEFORE `find` runs, so an
# unfiltered find would hash the empty inventory file into itself.
( cd "$GDEST" && find . -type f ! -name SHA256SUMS | LC_ALL=C sort | xargs sha256sum ) > "$GDEST/SHA256SUMS"
echo "guest-io helpers installed: $(grep -c . "$GDEST/SHA256SUMS") files"

# JOIN-5b: the MEASURED guest network-profile declaration (values = the VERIFIED
# upstream gvproxy v0.8.9 unconfigured NAT profile, 192.168.127.2/24 gw+DNS
# 192.168.127.1 -- the user-pinned transport for BOTH the Zed external-client
# path and the native Mini path).
install -D -m0644 "$PROFILE/guest-network.env" "$TREE/usr/local/lib/dsmack/net/guest-network.env"
echo "guest network profile installed: /usr/local/lib/dsmack/net/guest-network.env"

# ---- modules from the PROVEN verity rootfs (extracted per leg) ----
mkdir -p "$LEG/work/mods"
unsquashfs -n -f -d "$LEG/work/mods/rootfs" \
  "$PROVEN/build/artifacts/rootfs.squashfs.verity" \
  'usr/lib/modules/*' >"$LEG/work/unsquash-mods.log" 2>&1
mkdir -p "$TREE/usr/lib/modules"
cp -a "$LEG/work/mods/rootfs/usr/lib/modules/." "$TREE/usr/lib/modules/"
rm -rf "$LEG/work/mods/rootfs"
rm -f "$TREE/usr/lib/modules/$KERNEL_VERSION-dstack/build" \
      "$TREE/usr/lib/modules/$KERNEL_VERSION-dstack/source"
echo "rootfs done: $(du -sh "$TREE" | cut -f1) (kernel bytes from the proven ec83a3fc bundle)"
