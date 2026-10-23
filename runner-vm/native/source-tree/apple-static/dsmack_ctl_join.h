/* dsmack control-profile C ABI, version 1 (stable, versioned).
 *
 * This is the integration contract between the mar app and the joined backend:
 * one fixed approved profile — verified pinned kernel/initrd/cmdline bytes,
 * 1 vCPU / 512 MiB, an output-only diagnostics console, a DEDICATED named
 * bidirectional `dsmack-ctl` control console over the caller's socket/pipe
 * descriptor, and one content-pinned READ-ONLY system disk. Everything else
 * (devices, NICs, vsock, TSI, host paths, extra consoles, more vCPUs) is
 * rejected before any VM construction.
 *
 * Pins (kernel/initrd/cmdline AND system-disk SHA-256) are compiled into the
 * archive and are NOT caller-suppliable: no claimant can approve a different
 * boot closure through this ABI. Check dsmack_ctl_join_abi_version() before
 * any other call; refuse to run against an unexpected version.
 */
#ifndef DSMACK_CTL_JOIN_H
#define DSMACK_CTL_JOIN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ABI version implemented by this archive. */
#define DSMACK_CTL_JOIN_ABI_VERSION 1

/* Returns DSMACK_CTL_JOIN_ABI_VERSION of the loaded archive. */
int32_t dsmack_ctl_join_abi_version(void);

/* Smallest err buffer accepted by this ABI (bytes, incl. NUL). */
size_t dsmack_ctl_join_err_cap_min(void);

/* Build the control-profile VM. Refusals (all BEFORE any VM exists):
 *   - kernel/initrd: caller-held buffers; BOTH must be non-NULL with non-zero
 *     lengths; their bytes must hash to the compiled-in pins.
 *   - console_path: diagnostics console log; NUL-terminated path, created
 *     O_EXCL, must not exist, must be a regular file.
 *   - control_fd: the guest end of a bidirectional socketpair/pipe whose host
 *     end stays with the control-channel driver. Must be a socket or pipe —
 *     regular files, directories and devices are refused. The archive takes
 *     ownership of this descriptor (it may be closed inside the call or when
 *     the VM is torn down); the caller must not close or reuse it afterwards.
 *   - disk_path: the authenticated system disk; must be a regular file whose
 *     FULL content hashes to the compiled-in disk pin; attached read-only.
 * err/err_cap: writable buffer (>= dsmack_ctl_join_err_cap_min()), NUL-filled
 * on refusal. Returns an opaque handle > 0, or 0 on refusal (err set). */
int64_t dsmack_ctl_join_vm_new(const uint8_t *kernel, size_t kernel_len,
                               const uint8_t *initrd, size_t initrd_len,
                               const char *console_path,
                               int control_fd,
                               const char *disk_path,
                               char *err, size_t err_cap);

/* Run the whole returning lifecycle to completion (identical checked teardown
 * to dsmack_join_run: observer drain with bounded worker joins, vCPU destroy,
 * vm.destroy(), then guest memory released — and never while a device worker
 * is live). The handle is CONSUMED (do not reuse). Returns the VMM code
 * (0 = guest halt via PSCI, NOT workload success) or -1 on an unrecoverable
 * lifecycle fault (err set). Read the console log only AFTER this returns. */
int32_t dsmack_ctl_join_run(int64_t handle, char *err, size_t err_cap);

#ifdef __cplusplus
}
#endif
#endif /* DSMACK_CTL_JOIN_H */
