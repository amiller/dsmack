// VENDORED from morning/source3 libkrun builder.rs (exact line ranges recorded in
// VENDORED-SOURCES.txt). Only adaptation: StartMicrovmError -> local StartError with
// the same VerifiedBoot(String)/KernelFormatUnsupported variants used by these fns.
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

use crate::owned_verified::VerifiedBootImages;

#[derive(Debug)]
pub enum StartError {
    VerifiedBoot(String),
    KernelFormatUnsupported,
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            StartError::VerifiedBoot(e) => write!(f, "Verified boot refused: {e}"),
            StartError::KernelFormatUnsupported => write!(f, "kernel format unsupported"),
        }
    }
}


/// Type for passing information about the initrd in the guest memory.
pub struct InitrdConfig {
    /// Load address of initrd in guest memory
    pub address: vm_memory::GuestAddress,
    /// Size of initrd in guest memory
    pub size: usize,
}

/// Write the owned kernel at `kernel_addr` and the owned initrd at `initrd_addr`, requiring
/// the initrd to end exactly at `fdt_addr` and the kernel to end at or below `initrd_addr`.
// ADAPTATION: upstream cfg(any(target_arch = "aarch64", test)) removed for
// integration-test consumption on the x86_64 Zed host (pure memory placement).
pub const ARM64_IMAGE_ALIGN: u64 = 0x20_0000;

/// Returns the image_size of a modern little-endian arm64 boot Image
/// (Documentation/arch/arm64/booting.rst): magic "ARM\x64" at 56, text_offset at 8,
/// image_size (including BSS) at 16, flags at 24. The Image is written at a 2 MiB aligned
/// base, so text_offset must be 0; image_size == 0 (pre-3.17) is not supported.
pub fn arm64_image_size(kernel: &[u8]) -> std::result::Result<u64, String> {
    let le64 = |o: usize| u64::from_le_bytes(kernel[o..o + 8].try_into().unwrap());
    if kernel.len() < 64 {
        return Err(format!(
            "kernel is {} bytes, shorter than arm64 Image header",
            kernel.len()
        ));
    }
    if kernel[56..60] != *b"ARM\x64" {
        return Err("kernel lacks arm64 Image magic".into());
    }
    let (text_offset, image_size, flags) = (le64(8), le64(16), le64(24));
    if flags & 1 != 0 {
        return Err("big-endian arm64 Image not supported".into());
    }
    if text_offset != 0 {
        return Err(format!("arm64 Image text_offset {text_offset:#x} != 0"));
    }
    if image_size < kernel.len() as u64 {
        return Err(format!(
            "arm64 Image image_size {image_size:#x} < file length {:#x}",
            kernel.len()
        ));
    }
    Ok(image_size)
}


pub fn write_verified_images(
    guest_mem: &GuestMemoryMmap,
    kernel_addr: u64,
    initrd_addr: u64,
    fdt_addr: u64,
    images: &VerifiedBootImages,
) -> std::result::Result<(GuestAddress, Option<InitrdConfig>), StartError> {
    let err = |m: String| StartError::VerifiedBoot(m);
    let image_size = arm64_image_size(images.kernel()).map_err(err)?;
    if kernel_addr % ARM64_IMAGE_ALIGN != 0 {
        return Err(err(format!(
            "kernel address {kernel_addr:#x} not 2 MiB aligned"
        )));
    }
    let initrd_len = images.initrd().map_or(0, |i| i.len() as u64);
    let kernel_end = kernel_addr
        .checked_add(image_size)
        .ok_or_else(|| err("kernel end overflows".into()))?;
    if kernel_end > initrd_addr {
        return Err(err(format!(
            "kernel [{kernel_addr:#x}, {kernel_end:#x}) overlaps initrd/FDT at {initrd_addr:#x}"
        )));
    }
    if initrd_addr.checked_add(initrd_len) != Some(fdt_addr) {
        return Err(err(format!(
            "initrd at {initrd_addr:#x} + {initrd_len:#x} does not end at FDT {fdt_addr:#x}"
        )));
    }
    guest_mem
        .write_slice(images.kernel(), GuestAddress(kernel_addr))
        .map_err(|e| err(format!("kernel write: {e}")))?;
    let initrd_config = match images.initrd() {
        Some(initrd) => {
            guest_mem
                .write_slice(initrd, GuestAddress(initrd_addr))
                .map_err(|e| err(format!("initrd write: {e}")))?;
            Some(InitrdConfig {
                address: GuestAddress(initrd_addr),
                size: initrd.len(),
            })
        }
        None => None,
    };
    Ok((GuestAddress(kernel_addr), initrd_config))
}
