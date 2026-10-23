/* dsmack control-profile C ABI, version 3 — PROSPECTIVE IMPLEMENTATION HEADER.
 *
 * native-v3-backend lane, 2026-10-21. v3 is an ADDITIVE, EXPLICITLY VERSIONED
 * successor to v2 (apple-static/dsmack_ctl_join_v2.h). It is implemented by the
 * dsmack-backend-v3 crate (backend-v3/src/ctl_capi_v3.rs) and, on aarch64
 * macOS, by the HVF consumption adapter + libkrun block/net/builder changes
 * described in source-changes/.
 *
 * STATUS: PROSPECTIVE, pending independent review. Nothing here claims freeze
 * authority. The v1 (DSMACK_CTL_JOIN_ABI_VERSION 1) and v2
 * (DSMACK_CTL_JOIN_ABI_VERSION 2) ABIs stay frozen and untouched; v3 uses NEW
 * struct layouts and NEW `*_v3` entrypoints so v2 memory is NEVER reinterpreted
 * as v3 — a mismatched caller gets a version refusal, not a silent struct
 * re-read.
 *
 * WHAT CHANGES FROM v2:
 *   - the device set grows from vda/vdb/vdc to vda/vdb/vdc/vdd/vde:
 *       vda  measured RO system          (verify-on-open; unchanged)
 *       vdb  fresh RW scratch            (now initialized from an ADMITTED
 *                                         blank filesystem template: a distinct
 *                                         fresh inode, byte-copied, never a
 *                                         hardlink, never mutating the base)
 *       vdc  measured RO public workload (verify-on-open; unchanged)
 *       vdd  fresh RW result             (ADMITTED blank template; the verified
 *                                         inode itself is retained and attached
 *                                         to storage I/O, finalized with CHECKED
 *                                         storage flush/sync BEFORE destruction,
 *                                         then hashed through the retained
 *                                         descriptor at exact length)
 *       vde  OPTIONAL unmeasured RO       (genuinely private input: NO content
 *            private input                digest in the spec, receipt, trace or
 *                                         diagnostics — only presence)
 *   - ONE bounded, allowlisted generic virtio-net option over a caller-handed
 *     CONNECTED SOCK_STREAM fd (net_fd). The far end is an external NAT/transport
 *     helper (see NATIVE-V3-NETWORK.md). No tap / unix path / host device /
 *     host share / arbitrary device_manager is accepted. net_fd == -1 means no
 *     NIC. The guest's expected static config is 10.0.2.15 / gw 10.0.2.2 /
 *     DNS 10.0.2.3 (satisfied by the helper, not configured by the backend).
 *   - a run-result accessor (dsmack_ctl_join_result_v3) returning the
 *     envelope-shaped result_disk / console / runtime_input / lifecycle digests
 *     (dsmack-backend-v3/run-result/1), aligned with the I/O reference
 *     (io-contract-reference protocol ENVELOPE_* key sets).
 *
 * PRESERVED from v2 (protected integration points): owned-buffer verified boot
 * R1-R5 (kernel/initrd read exactly once, copied into backend-owned immutable
 * storage, hashed against the admitted spec pins; guest memory populated ONLY
 * from the owned copies; cmdline frozen); zero compiled-in image/harness/task
 * identity (every pin arrives in the admitted launch_spec); the O_EXCL
 * regular-file console; refusals fire BEFORE any guest executes; the backend
 * never learns workload semantics.
 *
 * FD OWNERSHIP (exact, on every return):
 *   - control_fd and net_fd move into dsmack_ctl_join_vm_new_v3 UNCONDITIONALLY.
 *     On ANY refusal each valid descriptor is closed exactly once. On success
 *     each lives inside the handle and is closed exactly once by
 *     dsmack_ctl_join_free_v3. The caller must never use or close either again.
 *   - control_fd and net_fd MUST be DISTINCT descriptors: an aliased pair is
 *     refused (owning the same fd twice would close it twice).
 *   - control_fd MUST be a socket or pipe transport (checked); a regular file
 *     or device is refused.
 *   - a negative control_fd is "no descriptor": refused, nothing claimed.
 *   - net_fd == -1 is "no NIC": nothing claimed.
 *
 * VALIDATION TIMING: on the real HVF backend the returning VmmBuilder::build()
 * STARTS the vCPUs. Every mandatory validation (spec, owned-buffer boot, disk
 * verify/create, template verify, vde bounds, net fd type, control fd type)
 * runs inside dsmack_ctl_join_vm_new_v3 BEFORE the consumption build step, i.e.
 * before any guest instruction executes. dsmack_ctl_join_run_v3 then runs the
 * returning lifecycle; dsmack_ctl_join_finalize_v3 performs the checked
 * teardown/finalization (on HVF it is fused into run_v3's teardown).
 */
#ifndef DSMACK_CTL_JOIN_V3_H
#define DSMACK_CTL_JOIN_V3_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DSMACK_CTL_JOIN_ABI_VERSION 3

/* Digest + resource expectations for one launch. Every field the backend
 * consumes has an expectation here; the backend verifies the actual
 * bytes/devices against them and refuses on ANY mismatch. The two
 * *_template_* pairs are the ADMITTED blank-template identities for the fresh
 * RW disks (vdb, vdd): the backend verifies the template content+size, then
 * byte-copies it into a fresh dest inode. There is NO vde field — vde is
 * unmeasured by construction. */
typedef struct {
    const char *spec_sha256;             /* admitted launch-spec digest (hex)   */
    const char *kernel_sha256;           /* expected kernel digest (hex)        */
    const char *initrd_sha256;           /* expected initrd digest (hex) or NULL*/
    const char *cmdline;                 /* exact NUL-terminated command line   */
    const char *cmdline_sha256;          /* digest of the exact cmdline bytes   */
    const char *system_sha256;           /* vda measured digest (hex)           */
    const char *verity_root_hash;        /* dm-verity root committed by initrd  */
    const char *workload_sha256;         /* vdc measured digest (hex)           */
    const char *scratch_template_sha256; /* vdb admitted template digest (hex)  */
    uint64_t    scratch_template_bytes;  /* vdb admitted template size (512-mul)*/
    const char *result_template_sha256;  /* vdd admitted template digest (hex)  */
    uint64_t    result_template_bytes;   /* vdd admitted template size (512-mul)*/
    uint32_t ram_mib;                    /* from the admitted measured profile  */
    uint32_t vcpus;                      /* from the admitted measured profile  */
} dsmack_ctl_launch_spec_v3;

/* Device paths the backend opens itself. The two fresh RW dests
 * (scratch_path, result_path) must NOT pre-exist (created O_EXCL 0600;
 * refused if present; unlinked again on a later refusal — fresh per ATTEMPT).
 * private_path is OPTIONAL (NULL = no vde). */
typedef struct {
    const char *system_path;           /* vda: read-only, verified on open     */
    const char *scratch_template_path; /* vdb: admitted blank template (base)  */
    const char *scratch_path;          /* vdb: fresh dest (must not pre-exist) */
    const char *workload_path;         /* vdc: read-only, verified on open     */
    const char *result_template_path;  /* vdd: admitted blank template (base)  */
    const char *result_path;           /* vdd: fresh dest (must not pre-exist) */
    const char *private_path;          /* vde: unmeasured RO, or NULL          */
} dsmack_ctl_disk_set_v3;

/* Returns DSMACK_CTL_JOIN_ABI_VERSION (3). F06: this probe is VERSIONED with a
 * `_v3` suffix so it never collides with v2's unversioned
 * `dsmack_ctl_join_abi_version` when both backends are archived together. */
int32_t dsmack_ctl_join_abi_version_v3(void);

/* One-time platform initialization: installs the aarch64-macOS HVF consumption
 * as the v3 backend's platform factory. MUST be called exactly once, as the
 * FIRST backend call, BEFORE the first dsmack_ctl_join_vm_new_v3. Returns 0 on
 * success, or -1 if a factory is already installed or the backend ABI version
 * is not 3 (the caller must then refuse to proceed). This symbol is provided by
 * the apple-static HVF adapter (hvf_consumption_v3.rs); it is ABSENT from a
 * host/mock-only build, which uses the mock platform without initialization. */
int32_t dsmack_ctl_v3_init(void);

/* Smallest err buffer accepted (bytes, incl. NUL). v3 = 512 (as v2). F06:
 * `_v3`-suffixed to avoid colliding with v2's unversioned symbol. */
size_t dsmack_ctl_join_err_cap_min_v3(void);

/* Build the v3 control-profile VM. Returns an opaque handle > 0, or 0 on
 * refusal (err set). All refusals happen BEFORE any guest executes and close
 * control_fd/net_fd exactly once when they were valid descriptors. net_fd == -1
 * means no NIC; otherwise net_fd MUST be a connected SOCK_STREAM (anything else
 * — tap/path/host device/regular file/unconnected socket — is refused). */
int64_t dsmack_ctl_join_vm_new_v3(const uint8_t *kernel, size_t kernel_len,
                                  const uint8_t *initrd, size_t initrd_len,
                                  const dsmack_ctl_launch_spec_v3 *spec,
                                  const dsmack_ctl_disk_set_v3 *disks,
                                  const char *console_path,
                                  int control_fd,
                                  int net_fd,
                                  char *err, size_t err_cap);

/* Advance the returning lifecycle to a proven halt (on HVF, run the guest to
 * PSCI halt with checked teardown; on the host mock, perform the quiescence
 * transition WITHOUT executing a guest — the mock runs no guest and fakes no
 * guest output). Must be called exactly once before finalize; finalize is
 * REFUSED until run reports a halt. Does NOT free the handle. Returns the VMM
 * code (0 = halt via PSCI, NOT workload success) or -1 on refusal (err set). */
int32_t dsmack_ctl_join_run_v3(int64_t handle, char *err, size_t err_cap);

/* Checked finalization of vdd + console (R06): checked storage flush/sync
 * BEFORE destruction, retained-descriptor sync, fixed-size check, I/O-vs-hash
 * descriptor identity check, then bounded chunked pread of the EXACT result and
 * console bytes. A failure at ANY step is a refusal and NO result is produced
 * (a Drop-time log is not success). On HVF this is fused into run_v3's
 * teardown; on the host mock it is called directly. 0 on success, -1 on
 * refusal (err set). */
int32_t dsmack_ctl_join_finalize_v3(int64_t handle, char *err, size_t err_cap);

/* Copy the launch receipt JSON (dsmack-backend-v3/launch-receipt/1) into out,
 * NUL-terminated. Never truncates: too-small out_cap is a refusal. The receipt
 * records the admitted template identities and vde PRESENCE only (never vde
 * content or size). Handle not consumed. 0 on success, -1 on refusal. */
int32_t dsmack_ctl_join_receipt_v3(int64_t handle, char *out, size_t out_cap);

/* Copy the run-result JSON (dsmack-backend-v3/run-result/1): result_disk
 * {role, template_sha256, template_bytes, sha256, bytes}, console {sha256,
 * bytes, truncated, limit_bytes}, runtime_input {present, max_bytes,
 * commitment_claim} (NO vde content/size/hash), lifecycle {vmm_code, run_ms,
 * backend_abi}. -1 if finalize has not run or out_cap too small. Handle not
 * consumed. */
int32_t dsmack_ctl_join_result_v3(int64_t handle, char *out, size_t out_cap);

/* Teardown: free the handle and close every owned descriptor (control, net,
 * console, vdd + retained dups) exactly once. */
void dsmack_ctl_join_free_v3(int64_t handle);

#ifdef __cplusplus
}
#endif
#endif /* DSMACK_CTL_JOIN_V3_H */
