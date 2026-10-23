# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash
# Guest kernel command line for the dstack-derived minimal ARM64 profile.
# Port of Dstack-TEE/dstack @ 247c3add65d0e8e6ba90eae5f6b981a9063cf701
# os/image/kernel-cmdline.sh (single-definition discipline preserved: this one
# string is baked into metadata.json AND echoed by build_image_arm64.sh for the
# launcher -- one definition, no second construction site).
# Deltas from the upstream x86/TDX line, each required by the ARM64/Mac target:
#   console=hvc0 (not ttyS0): the Mac HVF boot contract and the shared QEMU
#     virtio-console harness both speak hvc0; PL011 ttyAMA0 stays a secondary
#     early console under QEMU via the launcher's own -append (QEMU only).
#   dropped mce=off, pci=noearly, tsc=reliable, no-kvmclock: x86 machine-check
#     / legacy-PCI / TSC / KVM clock tokens with no arm64 equivalent and no
#     TEE claim here (platform trust deltas stay open per the reconciliation).
#   dropped random.trust_cpu / random.trust_bootloader: the RANDOM_TRUST_*
#     Kconfig symbols were removed from the kernel before 6.18, so the tokens
#     are inert there (the upstream x86 line still carries random.trust_cpu=y;
#     this profile does not repeat a policy token the kernel cannot implement).
#   dstack.rootfs_device= added: unpartitioned raw verity image on vda
#     (upstream boots a parted image by PARTLABEL).

dstack_kernel_cmdline_arm64() {
    local root_hash=${1:?root hash required}
    local data_size=${2:?data size required}
    local root_dev=${3:-/dev/vda}
    # GIO08: optional template-descriptor binding. When the two blank disk-
    # template digests (vdb scratch / vdd result) are supplied they are appended
    # as NAMESPACED dstack.* tokens. The cmdline is baked into metadata.json
    # whose sha256 is covered by sha256sum.txt == os_image_hash, so the
    # authenticated image identity CRYPTOGRAPHICALLY COMMITS to the template
    # digests (not merely two mutable JSON documents agreeing). The tokens are
    # additive and inert to the kernel (dstack.* tokens pass to /init, which
    # greps only the ones it knows); a consumer formatting from these templates
    # verifies the actual bytes against the os_image_hash-authenticated digest,
    # so a coordinated template+descriptor substitution is rejected against the
    # authenticated identity. Omitting the args preserves the exact prior line.
    local scratch_tpl_sha=${4:-}
    local result_tpl_sha=${5:-}
    local line="console=hvc0 init=/init panic=1 oops=panic net.ifnames=0 biosdevname=0 dstack.rootfs_hash=$root_hash dstack.rootfs_size=$data_size dstack.rootfs_device=$root_dev"
    if [ -n "$scratch_tpl_sha" ] && [ -n "$result_tpl_sha" ]; then
        line="$line dstack.scratch_template_sha256=$scratch_tpl_sha dstack.result_template_sha256=$result_tpl_sha"
    fi
    echo "$line"
}
