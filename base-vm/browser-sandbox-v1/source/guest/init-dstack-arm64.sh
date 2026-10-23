#!/bin/busybox sh
# initramfs /init for the dstack-derived minimal ARM64 base image.
# Owned adaptation of Dstack-TEE/dstack @ 247c3add65d0e8e6ba90eae5f6b981a9063cf701
# os/yocto/layers/meta-dstack/recipes-core/images/dstack-initscript/init
# (Apache-2.0). Documented deltas from upstream — everything else is the same
# protocol and the same fail-closed checks:
#   1. Root device: upstream defaults to PARTLABEL=dstack-rootfs on a parted
#      image; this profile boots an unpartitioned raw verity image on the first
#      virtio disk, so dstack.rootfs_device= is REQUIRED (fail-closed if absent
#      or not a block device). No sysfs PARTLABEL scan is kept because there is
#      no partition table to scan.
#   2. /run is mounted with an explicit 512 MiB size: the workload staging area
#      (/run/appcompose) must scale with the workload transport tar, a sizing
#      gap measured by the arm64-compatibility lane (128 MiB tmpfs failed with
#      ENOSPC on a 166 MB workload image). tmpfs is demand-allocated.
#   3. switch_root target: upstream execs /sbin/init (systemd). This minimal
#      profile has no service manager; it execs the trusted supervisor
#      /usr/bin/dsmack-supervisor pinned inside the verity root.
PATH=/sbin:/bin:/usr/sbin:/usr/bin

log() { printf '[dstack-init] %s\n' "$*" >&2; }

fail() { log "FATAL: $*"; exit 1; }

mkdir -p /proc /sys /run /dev /root
mount -t proc -o nosuid,nodev,noexec proc /proc || fail "mount proc"
mount -t sysfs -o nosuid,nodev,noexec sysfs /sys || fail "mount sysfs"
mount -t tmpfs -o nosuid,nodev,mode=0755,size=3072M tmpfs /run || fail "mount run"
mount -t devtmpfs -o nosuid,strictatime,mode=0755 devtmpfs /dev || fail "mount dev"
mkdir -p /dev/pts

log "booting dstack-derived initramfs (arm64 minimal)"

ROOT_HASH=
DATA_SIZE=
ROOTFS_DEVICE=
for param in $(cat /proc/cmdline); do
    case "$param" in
    "dstack.rootfs_hash="*)  ROOT_HASH="${param#*=}" ;;
    "dstack.rootfs_size="*)  DATA_SIZE="${param#*=}" ;;
    "dstack.rootfs_device="*) ROOTFS_DEVICE="${param#*=}" ;;
    *) ;;
    esac
done

[ -n "$ROOT_HASH" ] && [ -n "$DATA_SIZE" ] || fail "missing dstack.rootfs_hash/dstack.rootfs_size (measured identity) on cmdline"
[ -n "$ROOTFS_DEVICE" ] || fail "missing dstack.rootfs_device="
[ -b "$ROOTFS_DEVICE" ] || fail "$ROOTFS_DEVICE is not a block device"
log "root device $ROOTFS_DEVICE root_hash=${ROOT_HASH} data_size=$DATA_SIZE"

# dm-verity needs the sha256 crypto transform; this kernel builds it as a
# module (CONFIG_CRYPTO_SHA256=m — measured from the booted config, lane-2
# smoke try1), so load it from the measured module file shipped in this
# initramfs (kernel/crypto/sha256.ko, no dependencies per modules.dep)
# before the verity open. The check must match the ALGORITHM name line
# exactly: /proc/crypto also lists composed instance names such as
# essiv(cbc(aes),sha256) which a plain word-grep matches without the bare
# sha256 algorithm being registered (that false positive skipped the insmod
# in smoke try2; caught by an instrumented debug boot, build/diag/dbg-boot.log).
# Fail-closed if the transform is then unavailable.
have_sha256() { grep -Eq '^name[[:space:]]*: sha256[[:space:]]*$' /proc/crypto 2>/dev/null; }
if ! have_sha256; then
    for m in /lib/modules/*/kernel/crypto/sha256.ko; do
        [ -e "$m" ] || continue
        insmod "$m" || fail "insmod $m"
    done
fi
have_sha256 || fail "sha256 crypto transform unavailable (dm-verity cannot run)"

veritysetup open "$ROOTFS_DEVICE" rootfs "$ROOTFS_DEVICE" "$ROOT_HASH" \
    --hash-offset="$DATA_SIZE" --panic-on-corruption || fail "veritysetup open rejected the image"
mount -t squashfs -o ro /dev/mapper/rootfs /root || fail "mount verified squashfs root"

mkdir -p /root/sys /root/proc /root/dev /root/run
mount --move /sys  /root/sys  || fail "move sys"
mount --move /proc /root/proc || fail "move proc"
mount --move /dev  /root/dev  || fail "move dev"
mount --move /run  /root/run  || fail "move run"
log "switching root to verified rootfs"
exec switch_root /root /usr/bin/dsmack-supervisor
fail "switch_root failed"
