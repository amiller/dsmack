/* dsmack control-profile C ABI, version 2 — IMPLEMENTATION HEADER (PROVISIONAL).
 *
 * mac-backend-implementation lane, 2026-10-21. This header finalizes the
 * SHAPE of mac-general-prep's dsmack_ctl_join_v2_proposal.h into the ABI the
 * backend-v2 crate implements (backend-v2/src/ctl_capi.rs), plus the
 * boot-binding-spike DESIGN R1-R5 consumption semantics, and ONE addition:
 * `dsmack_ctl_join_receipt` (R5 needs a backend-side evidence surface; the
 * proposal records a receipt but names no accessor).
 *
 * STATUS: PROVISIONAL against the shared contract9 (NOT YET APPROVED —
 * contract9-review/astra-gate.json does not exist at write time). Changes
 * against it are provisional and must be reconciled with the approved final
 * contract before integration; this header changes NO public contract and
 * claims NO freeze authority. The v1 ABI (morning/source3,
 * DSMACK_CTL_JOIN_ABI_VERSION 1) stays frozen and untouched.
 *
 * WHAT CHANGES FROM v1:
 *   - ZERO compiled-in image identity: kernel/initrd/cmdline AND disk
 *     digests arrive in the admission-bound launch_spec whose sha256 an
 *     EXTERNAL policy admitted. Admitting a new image is a policy edit +
 *     manifest, never a backend rebuild or app re-sign (ledger 12.1).
 *   - the device set is the pinned guest contract triple: vda system
 *     (ro, verify-on-open), vdb scratch (rw, FRESH per launch — the backend
 *     refuses a pre-existing scratch inode), vdc workload (ro,
 *     verify-on-open; the guest supervisor re-verifies SHA256SUMS — dual
 *     control unchanged).
 *   - ram_mib/vcpus come from the admitted measured profile (resource zero
 *     refused; policy caps are enforced by the caller BEFORE the call).
 *   - verified boot is the owned-buffer route (R1-R5): caller buffers are
 *     read exactly once, copied into backend-owned immutable storage,
 *     hashed against the spec pins; guest memory is populated ONLY from the
 *     owned copies; the cmdline is part of the verified tuple and any
 *     post-verification mutation route is a refusal; the receipt records
 *     what actually booted.
 *
 * UNCHANGED from v1 (protected integration points): the O_EXCL regular-file
 * diagnostics console; the dedicated named `dsmack-ctl` bidirectional
 * control console over the caller's socket/pipe descriptor (ownership moves
 * into the call on EVERY return — closed exactly once on refusal, alive in
 * the handle on success, astra-gate R4); refusals fire BEFORE any VM
 * exists; `dsmack_ctl_join_run` consumes the handle, checked teardown,
 * VMM code 0 = guest halt (PSCI), never workload success.
 *
 * The backend NEVER learns workload semantics: compose/Claude/task/
 * marketplace policy stays outside it. Structural parsing authorizes
 * nothing — the app enforces external admission BEFORE calling, and the
 * verifier checks BOTH app identity and image identity.
 */
#ifndef DSMACK_CTL_JOIN_V2_H
#define DSMACK_CTL_JOIN_V2_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DSMACK_CTL_JOIN_ABI_VERSION 2

/* Digest expectations for one launch. Every field the backend consumes has
 * an expectation here; the backend verifies the actual bytes/devices against
 * them and refuses on ANY mismatch. `spec_sha256` is the digest of the
 * canonical launch_spec document the external policy admitted (the backend
 * checks syntax only — admission authentication is the app/verifier side). */
typedef struct {
    const char *spec_sha256;      /* admitted launch-spec digest (hex)        */
    const char *kernel_sha256;    /* expected kernel digest (hex)             */
    const char *initrd_sha256;    /* expected initrd digest (hex) or NULL     */
    const char *cmdline;          /* exact NUL-terminated command line        */
    const char *cmdline_sha256;   /* digest of the exact cmdline bytes (hex)  */
    const char *system_sha256;    /* expected system disk digest (hex)        */
    const char *verity_root_hash; /* dm-verity root committed by the initrd   */
    const char *workload_sha256;  /* expected workload tar digest (hex)       */
    uint32_t ram_mib;             /* from the admitted measured profile       */
    uint32_t vcpus;               /* from the admitted measured profile       */
} dsmack_ctl_launch_spec;

/* Block-device triple of the pinned guest contract. Paths are host paths the
 * BACKEND opens itself; the backend hashes system/workload at open time and
 * refuses on mismatch (verify-on-open; engineering narrowing — the rootfs
 * security binding is the verified initrd's in-guest dm-verity + panic=-1).
 * scratch must NOT pre-exist: the backend creates it O_EXCL 0600 (fresh per
 * launch; a refused launch leaves no scratch behind). The scratch path is
 * recorded verbatim in the launch receipt (R5), so it is bounded: more than
 * 256 bytes is a refusal (fable-native-audit F4). */
typedef struct {
    const char *system_path;   /* vda: read-only, verified on open            */
    const char *scratch_path;  /* vdb: read-write, fresh, guest-formatted     */
    const char *workload_path; /* vdc: read-only, verified on open (tar@0)    */
} dsmack_ctl_disk_set;

/* Returns DSMACK_CTL_JOIN_ABI_VERSION (2) of this backend. */
int32_t dsmack_ctl_join_abi_version(void);

/* v2 consumption-factory install (apple-static HVF returning backend): call
 * exactly once before the first dsmack_ctl_join_vm_new. 0 = installed; -1 =
 * already installed or the backend ABI version mismatched (the caller must
 * refuse to proceed). Exported by the integrated apple-static staticlib. */
int32_t dsmack_ctl_v2_init(void);

/* Smallest err buffer accepted by this ABI (bytes, incl. NUL). v2 = 512:
 * v2 refusals name fields plus both digest sides; the version bump makes
 * every v1 caller re-query instead of under-allocating. */
size_t dsmack_ctl_join_err_cap_min(void);

/* Build the general control-profile VM. Refusals (all BEFORE any VM exists;
 * every one closes control_fd exactly once when it was a valid descriptor):
 *   - kernel/initrd buffers must hash to the spec expectations (R1: buffers
 *     are read exactly once and verified against the OWNED copies; initrd
 *     pointer presence must equal initrd pin presence);
 *   - cmdline bytes must hash to cmdline_sha256 (R3: the cmdline is part of
 *     the verified tuple; every post-verification mutation route is a
 *     refusal, never a re-verification);
 *   - system/workload paths must be regular 512-multiple files whose FULL
 *     content hashes to the spec expectations at open time (verify-on-open);
 *   - scratch must not pre-exist (fresh inode, created O_EXCL by the
 *     backend; cleaned up again if a later step refuses);
 *   - ram_mib/vcpus must be non-zero;
 *   - control_fd must be a socket/pipe descriptor (ownership moves to the
 *     backend on EVERY return, as v1);
 *   - dstack.rootfs_hash in the cmdline, when present, must equal
 *     verity_root_hash (admission cross-check, fail-closed);
 *   - console_path must not exist (O_EXCL) and must become a regular file.
 * On success the observed digests, cmdline, resources, verity root and
 * spec_sha256 are recorded in the handle's receipt (R5; see
 * dsmack_ctl_join_receipt). Returns an opaque handle > 0, or 0 on refusal
 * (err set). */
int64_t dsmack_ctl_join_vm_new(const uint8_t *kernel, size_t kernel_len,
                               const uint8_t *initrd, size_t initrd_len,
                               const dsmack_ctl_launch_spec *spec,
                               const dsmack_ctl_disk_set *disks,
                               const char *console_path,
                               int control_fd,
                               char *err, size_t err_cap);

/* Unchanged from v1: whole returning lifecycle to completion with checked
 * teardown. Consumes the handle. Returns VMM code (0 = guest halt via PSCI,
 * NOT workload success) or -1 on refusal/fault (err set). Read the console
 * log and the receipt only AFTER this returns (or never run and query the
 * receipt first — the handle stays valid until run). */
int32_t dsmack_ctl_join_run(int64_t handle, char *err, size_t err_cap);

/* v2 addition (R5 evidence surface): copy the handle's launch receipt JSON
 * (dsmack-backend-v2/launch-receipt/1: observed owned-copy digests,
 * spec_sha256, exact cmdline, disk digests, verity root, ram/vcpus,
 * consumption label, honesty block) into out, NUL-terminated. The receipt
 * is NEVER truncated: an out_cap smaller than the receipt is a refusal
 * (fable-native-audit F4 — the implementation always refused; this text
 * now says so). The handle is NOT consumed. 0 on success, -1 on refusal
 * (zero handle, null out, out_cap < dsmack_ctl_join_receipt_cap_min()). */
int32_t dsmack_ctl_join_receipt(int64_t handle, char *out, size_t out_cap);

/* Smallest out buffer dsmack_ctl_join_receipt accepts: the COMPUTED WORST
 * CASE for any receipt this ABI can produce (max cmdline, bounded scratch
 * path, verbatim honesty block) — not a fixed floor. A caller allocating
 * this value always succeeds for any legal launch. */
size_t dsmack_ctl_join_receipt_cap_min(void);

#ifdef __cplusplus
}
#endif
#endif /* DSMACK_CTL_JOIN_V2_H */
