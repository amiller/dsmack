/* signed-app-join C ABI over the reviewed returning lifecycle.
 * UNSIGNED INTEGRATION FIXTURE — requires independent exact source review before any
 * execution or signing. Pins (kernel/initrd/cmdline SHA-256) are compiled into the
 * archive and are NOT caller-suppliable; the returning profile rejects any device,
 * console or option outside the profile before VM construction. */
#ifndef DSMACK_JOIN_H
#define DSMACK_JOIN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Smallest err buffer accepted by this ABI (bytes, incl. NUL). */
size_t dsmack_join_err_cap_min(void);

/* Build the returning-profile VM from OWNED bytes (read-once semantics).
 * kernel/initrd: caller-held buffers; initrd may be NULL only if initrd_len == 0.
 * console_path: NUL-terminated path; the file is created O_EXCL and must not exist.
 * err/err_cap: writable buffer (>= dsmack_join_err_cap_min()), NUL-filled on refusal.
 * Returns an opaque handle > 0, or 0 on refusal (err set). Pins mismatch and every
 * returning-profile guard fire here, BEFORE any VM exists. */
int64_t dsmack_join_vm_new(const uint8_t *kernel, size_t kernel_len,
                           const uint8_t *initrd, size_t initrd_len,
                           const char *console_path,
                           char *err, size_t err_cap);

/* Run the whole returning lifecycle to completion: run_returning performs the checked
 * stop_returning (observer drain, bounded vCPU joins) and finish_returning
 * (drop-owners -> vm.destroy() -> drop guest memory) before returning. The handle is
 * CONSUMED (do not reuse). Returns the VMM code (0 = guest halt via PSCI, NOT workload
 * success) or -1 on an unrecoverable lifecycle fault (err set). Read the console log
 * only AFTER this returns — output commitments are taken over the final bytes, after
 * checked teardown, never from a live guest. */
int32_t dsmack_join_run(int64_t handle, char *err, size_t err_cap);

#ifdef __cplusplus
}
#endif
#endif /* DSMACK_JOIN_H */
