#!/bin/bash
set -euo pipefail
umask 0022
LEG=/w/build/legs/diagnostic
mkdir -p "$LEG/files" "$LEG/work"
unsquashfs -no-progress -processors 4 -d "$LEG/work/rootfs" /prior-image/rootfs.squashfs.verity
TREE=$LEG/work/rootfs
# Rebuild the supplied kernel configuration with scratch encryption built in.
# Fixed build paths and metadata make independent derivations byte-identical.
echo '3712fc1ec839e4daac981176c8518912e8f452650aaedfe4381da4419613a431  /linux.tar.xz' | sha256sum -c -
tar -xJf /linux.tar.xz -C "$LEG/work"
KERNEL=$LEG/work/linux-6.18.40
cp /prior-image/config-6.18.40-dstack "$KERNEL/.config"
export ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-
export SOURCE_DATE_EPOCH=1784592000 TZ=UTC LC_ALL=C
export KBUILD_BUILD_TIMESTAMP="@$SOURCE_DATE_EPOCH"
export KBUILD_BUILD_USER=dstack KBUILD_BUILD_HOST=reproducible KBUILD_BUILD_VERSION=1
"$KERNEL/scripts/config" --file "$KERNEL/.config" --enable DM_CRYPT --enable CRYPTO_XTS
make -C "$KERNEL" olddefconfig
make -C "$KERNEL" -j4 Image modules
rm -rf "$TREE/usr/lib/modules/6.18.40-dstack"
make -C "$KERNEL" INSTALL_MOD_PATH="$TREE/usr" INSTALL_MOD_STRIP=1 modules_install
cp "$KERNEL/arch/arm64/boot/Image" "$LEG/files/Image"
cp "$KERNEL/.config" "$LEG/files/config-6.18.40-dstack"

install -m0755 /guest-egress/usr/sbin/mke2fs "$TREE/usr/sbin/mkfs.ext4"
install -m0644 /guest-egress/etc/mke2fs.conf "$TREE/etc/mke2fs.conf"
install -m0755 /guest-egress/usr/sbin/cryptsetup "$TREE/usr/sbin/cryptsetup"
install -m0755 /guest-egress/usr/sbin/nft "$TREE/usr/sbin/nft"
cp -a /guest-egress/usr/lib/aarch64-linux-gnu/*.so* "$TREE/usr/lib/aarch64-linux-gnu/"
bash /repo/base-vm/browser-sandbox-v1/install-guest.sh /repo "$TREE"
bash /w/source/build/assemble_leg.sh diagnostic
chmod 0644 "$LEG/files/"*
