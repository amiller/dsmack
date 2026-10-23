//! The consumption seam: how verified bytes + verified disks become a VM.
//!
//! R2 (single-source consumption): the ONLY way boot bytes reach the guest
//! is from the backend-owned `VerifiedBootImages` — there is no host path
//! for kernel/initrd/cmdline anywhere in the verified route. This module
//! defines the seam the two consumption implementations share:
//!
//! - [`MemoryPlacement`] — engineering consumption for non-macOS hosts:
//!   runs the EXACT vendored placement rules (guest_write::write_verified_images)
//!   against a plain host-memory "guest RAM", keeps the owned control
//!   descriptor alive inside the built object (v1 R4 success semantics),
//!   and models the upstream cmdline-freeze refusal. Labeled in every
//!   receipt: engineering evidence on Zed, NEVER a VM, never Mac evidence.
//! - HVF consumption (krun `Payload::load_external_raw_verified` +
//!   `VmmBuilder` + `ctl_channel` + the vda/vdb/vdc attachments) is
//!   cfg-gated for aarch64 macOS and arrives through
//!   `integration/apple-static-v1-to-v2.patch` — this crate alone refuses
//!   there instead of half-implementing HVF.
//!
//! Descriptor ownership (astra-gate R4, unchanged from v1): the caller's
//! `control_fd` arrives here as an owned `OwnedFd` — on a build refusal the
//! consumption drops it (closed exactly once); on success it lives inside
//! the returned handle until teardown.

use std::os::fd::OwnedFd;

use vm_memory::Bytes;

use crate::disks::AttachedDisk;
use crate::guest_write;
use crate::owned_verified::VerifiedBootImages;
use crate::receipt::LaunchReceipt;

pub const PLACEMENT_MODEL_LABEL: &str =
    "memory-placement-model (engineering; not a VM; not Mac evidence)";

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum BuildRefused {
    #[error("cmdline freeze violated: verified cmdline would be modified \
             (R3: append/override/earlycon refusals, builder.rs:1341 semantics)")]
    CmdlineFreeze,
    #[error("consumption unavailable on this platform: {0}")]
    Platform(String),
    #[error("guest placement refused: {0}")]
    Placement(String),
}

/// A built (not yet running) guest from the verified inputs.
pub trait GuestVm {
    /// Run to completion. Returns the VMM code — 0 = guest halt (PSCI),
    /// NEVER workload success. The engineering placement model refuses to
    /// "run" (nothing executes) and records why.
    fn run(self: Box<Self>) -> Result<i32, BuildRefused>;
    /// Read-back digests of the boot bytes AS PLACED (R2 proof artifact:
    /// recomputed from guest RAM, not from the owned copies).
    fn placed_kernel_sha256(&self) -> String;
    fn placed_initrd_sha256(&self) -> Option<String>;
    fn receipt(&self) -> &LaunchReceipt;
    /// R3 probe: any post-verification cmdline mutation route is a refusal,
    /// never a re-verification (models upstream `set_kernel_console` /
    /// `append_cmdline` refusals + the builder.rs freeze check).
    fn attempt_cmdline_override(self: Box<Self>, _new: &str) -> Result<(), BuildRefused> {
        Err(BuildRefused::CmdlineFreeze)
    }
    /// Downcast support for the test/engineering surface (the HVF impl may
    /// return self; this keeps the trait object usable without a second API).
    fn as_any(&self) -> &dyn std::any::Any;
}

/// The consumption seam itself. `build` receives EVERYTHING already
/// verified — boot images (owned copies), the verified disk triple, the
/// owned control descriptor, the O_EXCL console log, and the prebuilt
/// receipt; it must not re-open any boot path (there are none) and must
/// consume boot bytes only from `images`.
pub trait Consumption {
    fn label(&self) -> &'static str;
    fn build(
        &self,
        images: VerifiedBootImages,
        disks: Vec<AttachedDisk>,
        control: OwnedFd,
        console: std::fs::File,
        receipt: LaunchReceipt,
    ) -> Result<Box<dyn GuestVm>, BuildRefused>;
}

// ---------------------------------------------------------------------------
// Engineering placement model (non-macOS hosts; explicit opt-in elsewhere)
// ---------------------------------------------------------------------------

/// Guest-RAM layout constants of the MODEL (not the real HVF layout — the
/// real one lives in libkrun's aarch64 loader; the model only needs the
/// placement RULES to be identical: 2 MiB-aligned kernel base, initrd
/// ending exactly at the FDT address, no overlap).
const MODEL_RAM_BASE: u64 = 0x4000_0000;
const MODEL_RAM_SIZE: u64 = 128 << 20; // 128 MiB
const MODEL_KERNEL_ADDR: u64 = MODEL_RAM_BASE + 0x20_0000; // 2 MiB aligned

/// Deterministic model FDT address: end of model RAM.
fn model_fdt_addr() -> u64 {
    MODEL_RAM_BASE + MODEL_RAM_SIZE
}

fn sha_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(b))
}

pub struct MemoryPlacement;

pub struct PlacementVm {
    guest_ram: Vec<u8>,
    kernel_addr: u64,
    initrd_range: Option<(u64, u64)>,
    placed_kernel_sha256: String,
    placed_initrd_sha256: Option<String>,
    receipt: LaunchReceipt,
    cmdline: String,
    /// The caller's control descriptor, alive inside the handle exactly as
    /// in v1's success path (closed here at teardown — never by the caller).
    _control: OwnedFd,
}

impl Consumption for MemoryPlacement {
    fn label(&self) -> &'static str {
        PLACEMENT_MODEL_LABEL
    }

    fn build(
        &self,
        images: VerifiedBootImages,
        _disks: Vec<AttachedDisk>,
        control: OwnedFd,
        mut console: std::fs::File,
        receipt: LaunchReceipt,
    ) -> Result<Box<dyn GuestVm>, BuildRefused> {
        // Engineering marker: the placement model logs one honest banner line
        // into the O_EXCL console so the console file is never mistaken for
        // guest output (guest output exists only on the HVF run path).
        use std::io::Write as _;
        let _ = writeln!(
            console,
            "DSMACK_BACKEND_V2 consumption={PLACEMENT_MODEL_LABEL} \
             kernel_sha256={kernel} initrd_sha256={initrd}",
            kernel = receipt.observed_kernel_sha256,
            initrd = receipt
                .observed_initrd_sha256
                .as_deref()
                .unwrap_or("<none>"),
        );
        let guest_ram = vec![0u8; MODEL_RAM_SIZE as usize];
        let fdt_addr = model_fdt_addr();
        let initrd_len = images.initrd().map_or(0, |i| i.len() as u64);
        let initrd_addr = fdt_addr - initrd_len;
        let guest_mem = vm_memory::GuestMemoryMmap::from_ranges(&[(
            vm_memory::GuestAddress(MODEL_RAM_BASE),
            MODEL_RAM_SIZE as usize,
        )])
        .map_err(|e| BuildRefused::Placement(format!("model guest memory: {e}")))?;
        let (kernel_addr, _initrd_config) = guest_write::write_verified_images(
            &guest_mem,
            MODEL_KERNEL_ADDR,
            initrd_addr,
            fdt_addr,
            &images,
        )
        .map_err(|e| BuildRefused::Placement(e.to_string()))?;
        // R2 proof: read back from GUEST RAM and hash what landed there.
        let klen = images.kernel().len();
        let mut placed_kernel = vec![0u8; klen];
        guest_mem
            .read_slice(&mut placed_kernel, vm_memory::GuestAddress(kernel_addr.0))
            .map_err(|e| BuildRefused::Placement(format!("kernel readback: {e}")))?;
        let placed_kernel_sha256 = sha_hex(&placed_kernel);
        let placed_initrd_sha256 = match images.initrd() {
            Some(i) => {
                let mut placed = vec![0u8; i.len()];
                guest_mem
                    .read_slice(&mut placed, vm_memory::GuestAddress(initrd_addr))
                    .map_err(|e| BuildRefused::Placement(format!("initrd readback: {e}")))?;
                assert_eq!(
                    sha_hex(&placed),
                    sha_hex(i),
                    "model placement R2 violation"
                );
                Some(sha_hex(&placed))
            }
            None => None,
        };
        // Freeze the verified cmdline into the model VMM (upstream keeps
        // `kernel_cmdline` on the VMM and refuses any divergence in build()).
        let cmdline = images.cmdline().to_string();
        Ok(Box::new(PlacementVm {
            guest_ram,
            kernel_addr: kernel_addr.0,
            initrd_range: images
                .initrd()
                .map(|_| (initrd_addr, initrd_addr + initrd_len)),
            placed_kernel_sha256,
            placed_initrd_sha256,
            receipt,
            cmdline,
            _control: control,
        }))
    }
}

impl GuestVm for PlacementVm {
    fn run(self: Box<Self>) -> Result<i32, BuildRefused> {
        // Honest refusal: the placement model never executes a guest. The
        // HVF consumption (integration patch, aarch64 macOS) is the run path.
        Err(BuildRefused::Platform(
            "memory-placement-model does not execute guests; the run path is the \
             krun HVF consumption on aarch64 macOS (integration patch)"
                .into(),
        ))
    }

    fn placed_kernel_sha256(&self) -> String {
        self.placed_kernel_sha256.clone()
    }

    fn placed_initrd_sha256(&self) -> Option<String> {
        self.placed_initrd_sha256.clone()
    }

    fn receipt(&self) -> &LaunchReceipt {
        &self.receipt
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl PlacementVm {
    /// Direct R2 evidence accessor: guest RAM is inspectable, and it must
    /// equal the owned copies at the placed addresses (used by the
    /// adversarial tests; not part of the C ABI).
    pub fn guest_ram(&self) -> &[u8] {
        &self.guest_ram
    }
    pub fn kernel_addr(&self) -> u64 {
        self.kernel_addr
    }
    pub fn initrd_range(&self) -> Option<(u64, u64)> {
        self.initrd_range
    }
    pub fn frozen_cmdline(&self) -> &str {
        &self.cmdline
    }
}
