#!/bin/bash
set -euo pipefail
umask 0022
LEG=/w/build/legs/diagnostic
mkdir -p "$LEG/files" "$LEG/work"
unsquashfs -no-progress -processors 4 -d "$LEG/work/rootfs" /prior-image/rootfs.squashfs.verity
TREE=$LEG/work/rootfs
RDEST=$TREE/usr/local/lib/dsmack/compose-runner
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

install -m0755 /w/source/guest/supervisor-dstack-trixie.sh "$TREE/usr/bin/dsmack-supervisor"
install -m0755 /guest-egress/usr/sbin/mke2fs "$TREE/usr/sbin/mkfs.ext4"
install -m0644 /guest-egress/etc/mke2fs.conf "$TREE/etc/mke2fs.conf"
install -m0755 /guest-egress/usr/sbin/cryptsetup "$TREE/usr/sbin/cryptsetup"
for file in /w/source/guest/sentinel/harness/*.py /w/source/guest/sentinel/harness/adapter/*.py /w/source/guest/sentinel/harness/sentinel/*.py; do
 install -D -m0644 "$file" "$TREE/usr/local/lib/dsmack/sentinel/${file#/w/source/guest/sentinel/}"
done
install -m0755 /guest-egress/usr/sbin/nft "$TREE/usr/sbin/nft"
cp -a /guest-egress/usr/lib/aarch64-linux-gnu/*.so* "$TREE/usr/lib/aarch64-linux-gnu/"
for file in public_inputs.py public_toc.py; do
 install -m0644 "/w/source/runner-content/dsmack_guest_io/$file" "$TREE/usr/local/lib/dsmack/guest-io/dsmack_guest_io/$file"
done
for file in manifest.py lowering.py egress.py security.py browser-sandbox-v1.json; do
 install -m0644 "/w/source/runner-content/lib/dsmack_compose_contract/$file" "$RDEST/lib/dsmack_compose_contract/$file"
done
install -m0644 /w/source/runner-content/dsmack_compose_runner/lifecycle.py "$RDEST/dsmack_compose_runner/lifecycle.py"
for file in agent.py guest_attest.py dsmack_dstack.py secret_box.py; do
 install -D -m0644 "/w/dstack-compat/$file" "$TREE/usr/local/lib/dsmack/dstack-agent/$file"
done
(cd "$RDEST" && find . -type f ! -name SHA256SUMS ! -path '*/__pycache__/*' -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > SHA256SUMS)
bash /w/source/build/assemble_leg.sh diagnostic
chmod 0644 "$LEG/files/"*
