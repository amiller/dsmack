//! Generic native backend (control-profile ABI v2) for the dsmack general launcher.
//!
//! mac-backend-implementation lane, 2026-10-21. This crate implements the
//! CONCRETE backend half of the v2 ABI proposed by mac-general-prep
//! (`abi/dsmack_ctl_join_v2_proposal.h`) with the boot-binding-spike DESIGN
//! R1-R5 consumption semantics wired in, replacing source3's compiled-in-pin
//! control profile (v1) with:
//!
//! - **owned-buffer verified boot over a pointer/length FFI** (`ctl_capi`):
//!   kernel/initrd are caller buffers read EXACTLY ONCE, copied into
//!   backend-owned immutable storage, and verified against the spec pins
//!   (R1); guest memory is populated only from the owned copies (R2, the
//!   vendored `guest_write` placement rules);
//! - **external admitted image pins** (`spec`): every digest expectation
//!   arrives in the admitted `launch_spec` — the archive carries ZERO
//!   compiled-in image identity, so admitting a new image is a policy edit,
//!   never a rebuild or re-sign;
//! - **the vda/vdb/vdc disk triple** (`disks`): system read-only with
//!   verify-on-open, workload read-only with verify-on-open, scratch
//!   read-write refused unless a FRESH inode (created O_EXCL by the backend);
//! - **resource profiles** (`spec`): ram_mib/vcpus arrive from the admitted
//!   measured profile; zero is refused; policy caps are enforced by the
//!   caller app BEFORE this ABI (the backend refuses only what it can know);
//! - **R5 evidence**: every successful build records a receipt (observed
//!   owned-copy digests, spec_sha256, exact cmdline, verity root, resource
//!   profile, honesty block) — `receipt`.
//!
//! Integration points preserved unchanged from source3/morning (NOT
//! reimplemented here): the protected terminal and supervisor staging flow,
//! the named `dsmack-ctl` bidirectional control console over the caller's
//! socketpair/pipe descriptor (astra-gate R4 descriptor ownership is kept
//! verbatim), the O_EXCL regular-file diagnostics console, and the App
//! Attest flow in the app layer (`marAttest`), which binds receipts AFTER
//! the run via the contract attestation interface. The backend never learns
//! workload semantics: compose/Claude/task/marketplace policy stays outside
//! it entirely.
//!
//! Platform honesty (mirrors the cfg-gated surface):
//! - on non-macOS hosts the default consumption is the
//!   `memory_placement_model` — the SAME placement/verification logic the
//!   HVF backend runs, executed against host memory so the ABI semantics are
//!   unit-proven on Zed (engineering evidence, never a VM, never claimed as
//!   Mac qualification);
//! - on aarch64 macOS the krun/HVF consumption arrives through the
//!   integration patch (`integration/apple-static-v1-to-v2.patch`); this
//!   crate alone refuses to run there rather than half-implementing HVF.

pub mod ctl_capi;
pub mod disks;
pub mod guest_write;
pub mod owned_verified;
pub mod receipt;
pub mod spec;

pub mod consumption;
pub use consumption::{Consumption, GuestVm, MemoryPlacement, PLACEMENT_MODEL_LABEL};
pub use disks::{AttachedDisk, DiskRole};
pub use owned_verified::{VerifiedBootError, VerifiedBootImages, VerifiedBootPins};
pub use receipt::{LaunchReceipt, HONESTY_BLOCK_JSON};
pub use spec::{LaunchSpec, SpecError};

/// Vendored from src/arch/src/aarch64/layout.rs:63 (exact upstream aarch64
/// value, via boot-binding-spike proto/src/lib.rs).
pub mod arch {
    pub const CMDLINE_MAX_SIZE: usize = 2048;
}
