#!/bin/bash
# Kernel build for one reproducibility leg (lane dstack-smoke-finish).
# Byte-logic port of the kernel phase of dstack-base-image/source/build/
# build_image_arm64.sh @ c195f6ce (prior lane, read-only): same pinned tarball,
# same reproducibility env (KBUILD_*, debug-prefix-map into the leg work tree,
# SOURCE_DATE_EPOCH), same defconfig+merge_config+olddefconfig flow, same
# config gate. ONE change, required by this lane's root cause: the profile
# fragment now carries CONFIG_NFT_{NAT,MASQ,CT,COMPAT}=y (dockerd's iptables-nft
# NAT path; see fragment comment). Each leg builds its OWN kernel and its OWN
# module store — leg independence covers kernel AND rootfs this round (the
# prior round reused the kernel by reference because its identity was already
# two-build proven; the repaired kernel is new, so it is proven here).
# Runs INSIDE dsmack-dstack-arm64/builder:trixie-20260721 with this lane at /w
# and prior lane dstack-base-image (tarball+deb cache) read-only at /prior.
set -euo pipefail
umask 0022

W=/w
LANE=$W
PRIOR=/prior
PROFILE=$LANE/source/profile/dstack-trixie-arm64-minimal
LEG_REL=${1:?leg name required}
LEG=$LANE/build/legs/$LEG_REL
export SOURCE_DATE_EPOCH=1784592000
export TZ=UTC LC_ALL=C
JOBS=${JOBS:-6}

KERNEL_VERSION=6.18.40
KERNEL_SHA256=3712fc1ec839e4daac981176c8518912e8f452650aaedfe4381da4419613a431

mkdir -p "$LEG"/{work,files}
cd "$LEG/work"
echo "== leg $LEG_REL: kernel build (jobs=$JOBS) =="

tarball=$PRIOR/cache/downloads/linux-$KERNEL_VERSION.tar.xz
echo "$KERNEL_SHA256  $tarball" | sha256sum --check --strict || { echo 'kernel source checksum mismatch' >&2; exit 1; }
export ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-
export KBUILD_BUILD_TIMESTAMP="@$SOURCE_DATE_EPOCH"
export KBUILD_BUILD_USER=dstack KBUILD_BUILD_HOST=reproducible KBUILD_BUILD_VERSION=1
export KCONFIG_NOTIMESTAMP=1
local_map="-fdebug-prefix-map=$LEG/work=/usr/src/linux -fmacro-prefix-map=$LEG/work=/usr/src/linux"
export KCFLAGS="${KCFLAGS:-} $local_map" KAFLAGS="${KAFLAGS:-} $local_map" KCPPFLAGS="${KCPPFLAGS:-} $local_map"
tar -C "$LEG/work" --no-same-owner -xf "$tarball"
make -C "linux-$KERNEL_VERSION" O="$LEG/work/kb" ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- defconfig
"linux-$KERNEL_VERSION/scripts/kconfig/merge_config.sh" -m -O "$LEG/work/kb" \
    "$LEG/work/kb/.config" "$PROFILE/kernel-fragment-arm64.config"
make -C "linux-$KERNEL_VERSION" O="$LEG/work/kb" ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- olddefconfig
bash "$LANE/source/tests/check_kernel_config.sh" "$LEG/work/kb/.config" \
    "$PROFILE/kernel-fragment-arm64.config"
grep -qx 'CONFIG_NFT_NAT=y' "$LEG/work/kb/.config" || { echo 'CONFIG_NFT_NAT=y did not stick' >&2; exit 1; }
grep -qx 'CONFIG_NFT_MASQ=y' "$LEG/work/kb/.config" || { echo 'CONFIG_NFT_MASQ=y did not stick' >&2; exit 1; }
grep -qx 'CONFIG_NFT_CT=y' "$LEG/work/kb/.config" || { echo 'CONFIG_NFT_CT=y did not stick' >&2; exit 1; }
grep -qx 'CONFIG_NFT_COMPAT=y' "$LEG/work/kb/.config" || { echo 'CONFIG_NFT_COMPAT=y did not stick' >&2; exit 1; }
if [ "${CONFIG_ONLY:-0}" = 1 ]; then echo "CONFIG-ONLY-OK leg=$LEG_REL"; exit 0; fi
make -C "linux-$KERNEL_VERSION" O="$LEG/work/kb" ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- \
     -j"$JOBS" Image modules
make -C "linux-$KERNEL_VERSION" O="$LEG/work/kb" ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- \
     INSTALL_MOD_PATH="$LEG/work/mods" modules_install
install -m0644 "$LEG/work/kb/arch/arm64/boot/Image" "$LEG/files/Image"
install -m0644 "$LEG/work/kb/.config" "$LEG/files/config-$KERNEL_VERSION-dstack"
# Debian usr-merge + the lane-2 one-byte defect: normalize into /usr/lib and
# drop the absolute build/source symlinks modules_install writes (they leak the
# leg name and are dangling in the image anyway).
mkdir -p "$LEG/work/mods/usr/lib"
mv "$LEG/work/mods/lib/modules" "$LEG/work/mods/usr/lib/"
rmdir "$LEG/work/mods/lib"
rm -f "$LEG/work/mods/usr/lib/modules/$KERNEL_VERSION-dstack/build" \
      "$LEG/work/mods/usr/lib/modules/$KERNEL_VERSION-dstack/source"
echo "kernel done: $LEG_REL/files/Image $(stat -c %s "$LEG/files/Image") bytes; modules: $(find "$LEG/work/mods/usr/lib/modules" -name '*.ko*' | wc -l)"
