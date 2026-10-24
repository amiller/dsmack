#!/bin/bash
# Assemble the verity rootfs, initramfs, metadata and checksums for one build leg.
# Runs inside the builder container.
set -euo pipefail
umask 0022

W=/w
LANE=$W
PROFILE=$LANE/source/profile/dstack-trixie-arm64-minimal
LEG_REL=${1:?leg name required}
LEG=$LANE/build/legs/$LEG_REL
export SOURCE_DATE_EPOCH=1784592000
export TZ=UTC LC_ALL=C
JOBS=${JOBS:-6}

KERNEL_VERSION=6.18.40
DEBIAN_RELEASE=trixie
DEBIAN_SNAPSHOT=20260721T000000Z
DSTACK_UPSTREAM_REVISION=247c3add65d0e8e6ba90eae5f6b981a9063cf701
IMAGE_NAME=dstack-trixie-arm64-minimal
IMAGE_VERSION=0.7.0.browser-sandbox-v1

TREE=$LEG/work/rootfs
[ -d "$TREE/usr/lib/modules/$KERNEL_VERSION-dstack" ] || { echo 'rootfs tree missing modules' >&2; exit 1; }

# ------------------------------------------- rootfs.squashfs.verity (FIX-2) ----
rootfs="$LEG/files/rootfs.squashfs.verity"
tarfile="$LEG/work/rootfs.tar"
truncate -s 0 "$rootfs"
( cd "$TREE" && tar --sort=name --format=gnu \
    --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
    --mode=g-s --hard-dereference -cf "$tarfile" . )
echo "rootfs tar: $(stat -c %s "$tarfile") bytes sha256=$(sha256sum "$tarfile" | awk '{print $1}')"
sha256sum "$tarfile" | awk '{print $1}' > "$LEG/rootfs-tar.sha256"
env -u SOURCE_DATE_EPOCH mksquashfs - "$rootfs" -tar \
    -noappend -all-root -no-progress -exports -no-hardlinks -no-tailends \
    -no-xattrs -processors "$JOBS" -comp zstd -mkfs-time "$SOURCE_DATE_EPOCH" \
    -all-time "$SOURCE_DATE_EPOCH" <"$tarfile" >"$LEG/work/mksquashfs.log" 2>&1
grep -v '^Empty tar filename' "$LEG/work/mksquashfs.log" | grep -iE 'error|fatal' && {
  echo 'mksquashfs reported an error (see work/mksquashfs.log)' >&2; exit 1; }
data_size=$(stat -c %s "$rootfs")
data_size=$(( (data_size + 4095) / 4096 * 4096 ))
truncate -s "$data_size" "$rootfs"
verity_output=$(veritysetup format "$rootfs" "$rootfs" \
  --hash-offset="$data_size" --data-block-size=4096 --hash-block-size=4096 \
  --uuid=00000000-0000-0000-0000-000000000000 \
  --salt="$(printf '%064x' 0)")
root_hash=$(awk '/Root hash:/ {print $3}' <<<"$verity_output")
[[ $root_hash =~ ^[0-9a-f]{64}$ ]] || { echo "failed to obtain verity root hash" >&2; exit 1; }
echo "root_hash=$root_hash data_size=$data_size"

# ------------------------------------------------------------- initramfs ----
ird=$(mktemp -d "$LEG/work/.initramfs.XXXXXX")
mkdir -p "$ird"/{bin,sbin,dev,proc,sys,run,root,usr/bin,usr/sbin}
busybox_bin=$(find "$TREE" -maxdepth 3 -type f -name busybox | LC_ALL=C sort | head -1)
[ -n "$busybox_bin" ] || { echo 'busybox not found in rootfs tree' >&2; exit 1; }
install -m0755 "$busybox_bin" "$ird/bin/busybox"
for applet in sh mount mkdir cat grep head cut basename realpath switch_root insmod; do
  ln -s busybox "$ird/bin/$applet"
done
# dm-verity's sha256 crypto transform is a module in this kernel
# (CONFIG_CRYPTO_SHA256=m, measured on smoke try1); ship it in the measured
# initramfs so /init can insmod it before veritysetup open. No deps
# (modules.dep); copied from the same verity-protected module set as the
# rootfs (build/module-store).
sha256_ko="$TREE/usr/lib/modules/$KERNEL_VERSION-dstack/kernel/crypto/sha256.ko"
[ -f "$sha256_ko" ] || { echo 'sha256.ko missing from module set' >&2; exit 1; }
install -D -m0644 "$sha256_ko" \
  "$ird/lib/modules/$KERNEL_VERSION-dstack/kernel/crypto/sha256.ko"
mapfile -d '' -t verity_matches < <(
  find "$TREE" -type f \( -path '*/sbin/veritysetup' -o -path '*/bin/veritysetup' \) \
    -print0 | sort -z)
[[ ${#verity_matches[@]} -gt 0 ]] || { echo 'veritysetup missing from rootfs tree' >&2; exit 1; }
verity_bin=${verity_matches[0]}
install -m0755 "$verity_bin" "$ird/sbin/veritysetup"
lddtree_out=$(lddtree -l -R "$TREE" "${verity_bin#"$TREE"}") || {
    echo 'lddtree failed to resolve the veritysetup dependency tree' >&2; exit 1; }
while read -r lib; do
  [[ -n $lib ]] || continue
  [[ $lib == "$verity_bin" ]] && continue
  [[ $lib == /* ]] || { echo "lddtree could not resolve '$lib' inside the tree" >&2; exit 1; }
  rel=${lib#"$TREE"}
  [[ $rel == "$lib" ]] && { echo "lddtree resolved outside the tree: $lib" >&2; exit 1; }
  install -Dm0755 "$lib" "$ird$rel"
done <<< "$lddtree_out"
install -m0755 "$LANE/source/guest/init-dstack-arm64.sh" "$ird/init"
find "$ird" -print0 | xargs -0 touch -h -d "@$SOURCE_DATE_EPOCH"
(cd "$ird" && find . -print0 | sort -z | \
  cpio --null -o --format=newc --reproducible --owner=0:0 2>/dev/null) \
  | gzip -n -9 > "$LEG/files/initramfs.cpio.gz"

# Copy the selected disk templates; their digests are bound into the kernel cmdline.
cp --sparse=always /selected-templates/scratch-template.ext4 "$LEG/files/"
cp --sparse=always /selected-templates/result-template.ext4 "$LEG/files/"
cp /selected-templates/disk-templates.json "$LEG/files/"
scratch_tpl_sha=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["templates"]["scratch"]["sha256"])' "$LEG/files/disk-templates.json")
result_tpl_sha=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["templates"]["result"]["sha256"])' "$LEG/files/disk-templates.json")
[[ $scratch_tpl_sha =~ ^[0-9a-f]{64}$ && $result_tpl_sha =~ ^[0-9a-f]{64}$ ]] \
  || { echo 'GIO08: template digests unavailable for cmdline binding' >&2; exit 1; }
echo "GIO08: disk templates built; binding scratch=$scratch_tpl_sha result=$result_tpl_sha into cmdline"

# ------------------------------------------------- identity: metadata+cm ----
source "$PROFILE/kernel-cmdline.sh"
# GIO08: bind the two template digests into the authenticated cmdline.
cmdline=$(dstack_kernel_cmdline_arm64 "$root_hash" "$data_size" /dev/vda "$scratch_tpl_sha" "$result_tpl_sha")
touch -d "@$SOURCE_DATE_EPOCH" "$LEG/files/"*

cat > "$LEG/files/metadata.json" <<EOF
{
    "kernel": "Image",
    "cmdline": "$cmdline",
    "initrd": "initramfs.cpio.gz",
    "rootfs": "rootfs.squashfs.verity",
    "version": "$IMAGE_VERSION",
    "git_revision": "$DSTACK_UPSTREAM_REVISION",
    "builder": "$IMAGE_NAME",
    "shared_ro": true,
    "is_dev": false,
    "platform": "arm64",
    "os_image_hash_def": "sha256(sha256sum.txt)"
}
EOF
touch -d "@$SOURCE_DATE_EPOCH" "$LEG/files/metadata.json"

CHECKSUM_FILES=(Image initramfs.cpio.gz metadata.json rootfs.squashfs.verity)
( cd "$LEG/files" && sha256sum "${CHECKSUM_FILES[@]}" > sha256sum.txt \
  && sha256sum sha256sum.txt | awk '{print $1}' > digest.txt )
touch -d "@$SOURCE_DATE_EPOCH" "$LEG/files/sha256sum.txt" "$LEG/files/digest.txt"

python3 - "$LEG/files/artifact-manifest.json" "$LEG/files/disk-templates.json" <<PY
import json, sys
data = {"schema_version": 1, "backend": "$IMAGE_NAME",
 "image": {"name": "$IMAGE_NAME", "version": "$IMAGE_VERSION", "flavor": "minimal", "is_dev": False},
 "source": {"git_revision": "$DSTACK_UPSTREAM_REVISION"},
 "boot": {"ovmf_variant": "none-direct-kernel-boot"},
 "verity": {"root_hash": "$root_hash", "data_size": "$data_size"},
 "artifacts": {"initramfs": "initramfs.cpio.gz", "kernel": "Image",
               "firmware": None, "rootfs_verity": "rootfs.squashfs.verity",
               "firmware_sev": None, "uki": None, "kernel_devel": None},
 "backend_metadata": {"machine": "dstack-generic-vm", "distribution": "debian",
                      "release": "$DEBIAN_RELEASE", "snapshot": "$DEBIAN_SNAPSHOT",
                      "architecture": "arm64",
                      "schema_delta": "firmware=null,firmware_sev=null,uki=null allowed; rootfs_verity included in sha256sum.txt (upstream binds it via metadata+TDX measurements)"}}
t = json.load(open(sys.argv[2]))
data["disk_templates"] = {"schema": t["schema"],
 "template_bytes_max": t.get("template_bytes_max", 1073741824),
 "template_role_bytes_max": t["template_role_bytes_max"],
 "mke2fs_version": t.get("mke2fs_version"), "templates": t["templates"],
 "admission_binding": t.get("admission_binding"),
 "binding_note": "pinned image asset; final build MUST promote these digests into the "
                 "authenticated image identity (metadata key-set extension) and admission, "
                 "and MUST verify built template bytes against admission_binding.descriptors"}
with open(sys.argv[1], "w") as f: json.dump(data, f, indent=2, sort_keys=True); f.write("\n")
PY

touch -d "@$SOURCE_DATE_EPOCH" "$LEG/files/artifact-manifest.json" \
  "$LEG/files/scratch-template.ext4" "$LEG/files/result-template.ext4" \
  "$LEG/files/disk-templates.json"

dpkg-query --admindir "$TREE/var/lib/dpkg" -W -f='${Package} ${Version} ${Architecture}\n' \
  | LC_ALL=C sort > "$LEG/guest-packages.txt"

echo "== leg $LEG_REL assembled (assemble_leg.sh) =="
sha256sum "$LEG"/files/* | sed 's/^/  /'
