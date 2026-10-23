//! The admitted launch_spec for ABI v3 (dsmack_ctl_join_v3.h).
//!
//! v3 is ADDITIVE over v2 spec.rs: the boot tuple, measured RO disks and
//! resource profile are unchanged; v3 adds the admitted blank-template
//! identities for the two fresh RW disks (vdb scratch, vdd result) and leaves
//! the optional vde private input UNMEASURED (no digest field exists for it).
//! As in v2 the backend performs syntax + internal-consistency validation only;
//! that the spec was admitted is the relying party's boundary.

use std::ffi::CStr;

pub fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// Path length cap for any disk path recorded in evidence (receipt). Bounds the
/// scratch/result dest paths exactly like v2 bounded the scratch path.
pub const DISK_PATH_MAX_BYTES: usize = 256;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum SpecError {
    #[error("null {0}")]
    Null(&'static str),
    #[error("{0} not UTF-8")]
    NotUtf8(&'static str),
    #[error("{0} is not 64 lowercase hex characters")]
    DigestSyntax(&'static str),
    #[error("cmdline contains a byte outside printable ASCII")]
    CmdlineInvalid,
    #[error("cmdline is {0} bytes, limit {1}")]
    CmdlineTooLong(usize, usize),
    #[error("ram_mib must be non-zero (resource-zero refusal)")]
    RamZero,
    #[error("vcpus must be non-zero (resource-zero refusal)")]
    VcpusZero,
    #[error("vcpus {0} exceeds builder maximum 255")]
    VcpusTooLarge(u32),
    #[error("{0} template bytes must be a non-zero multiple of 512")]
    TemplateBytes(&'static str),
    #[error("{0} template bytes {1} exceeds cap {2}")]
    TemplateTooLarge(&'static str, u64, u64),
    #[error("cmdline dstack.rootfs_hash {got} != spec verity_root_hash")]
    VerityCmdlineMismatch { got: String },
}

/// Validated v3 launch spec.
#[derive(Clone, Debug)]
pub struct LaunchSpecV3 {
    pub spec_sha256: String,
    pub kernel_sha256: String,
    pub initrd_sha256: Option<String>,
    pub cmdline: String,
    pub cmdline_sha256: String,
    pub system_sha256: String,
    pub verity_root_hash: String,
    pub workload_sha256: String,
    pub scratch_template_sha256: String,
    pub scratch_template_bytes: u64,
    pub result_template_sha256: String,
    pub result_template_bytes: u64,
    pub ram_mib: u32,
    pub vcpus: u8,
}

impl LaunchSpecV3 {
    pub fn pins(&self) -> crate::owned_verified::VerifiedBootPins<'_> {
        crate::owned_verified::VerifiedBootPins {
            kernel_sha256: &self.kernel_sha256,
            initrd_sha256: self.initrd_sha256.as_deref(),
            cmdline_sha256: &self.cmdline_sha256,
        }
    }

    pub fn cmdline_max() -> usize {
        crate::owned_verified::VERIFIED_CMDLINE_MAX_BYTES.min(crate::arch::CMDLINE_MAX_SIZE - 1)
    }

    pub fn check_verity_cmdline_consistency(&self) -> Result<(), SpecError> {
        const KEY: &str = "dstack.rootfs_hash=";
        if let Some(pos) = self.cmdline.find(KEY) {
            let rest = &self.cmdline[pos + KEY.len()..];
            let end = rest
                .find(|c: char| c == ' ' || c == '\t')
                .unwrap_or(rest.len());
            let got = &rest[..end];
            if got != self.verity_root_hash {
                return Err(SpecError::VerityCmdlineMismatch {
                    got: got.to_string(),
                });
            }
        }
        Ok(())
    }
}

fn read_cstr<'a>(p: *const std::ffi::c_char, what: &'static str) -> Result<&'a str, SpecError> {
    if p.is_null() {
        return Err(SpecError::Null(what));
    }
    // SAFETY: caller contract — valid NUL-terminated string for the call.
    unsafe { CStr::from_ptr(p) }
        .to_str()
        .map_err(|_| SpecError::NotUtf8(what))
}

fn check_template(
    bytes: u64,
    what_bytes: &'static str,
    cap: u64,
) -> Result<(), SpecError> {
    if bytes == 0 || bytes % 512 != 0 {
        return Err(SpecError::TemplateBytes(what_bytes));
    }
    if bytes > cap {
        return Err(SpecError::TemplateTooLarge(
            what_bytes,
            bytes,
            cap,
        ));
    }
    Ok(())
}

/// Parse + validate the raw v3 C launch_spec. Reads every pointed-to string
/// exactly once and owns the result.
///
/// # Safety
/// `raw` must point to a fully initialized `DsmackCtlLaunchSpecV3` whose char
/// pointers are null only where documented (initrd) or valid NUL-terminated
/// UTF-8 for the call.
pub unsafe fn launch_spec_from_raw(
    raw: &crate::ctl_capi_v3::DsmackCtlLaunchSpecV3,
) -> Result<LaunchSpecV3, SpecError> {
    let cmdline = read_cstr(raw.cmdline, "spec.cmdline")?.to_string();
    let initrd_sha256 = if raw.initrd_sha256.is_null() {
        None
    } else {
        Some(read_cstr(raw.initrd_sha256, "spec.initrd_sha256")?.to_string())
    };
    let mut spec = LaunchSpecV3 {
        spec_sha256: read_cstr(raw.spec_sha256, "spec.spec_sha256")?.to_string(),
        kernel_sha256: read_cstr(raw.kernel_sha256, "spec.kernel_sha256")?.to_string(),
        initrd_sha256,
        cmdline,
        cmdline_sha256: read_cstr(raw.cmdline_sha256, "spec.cmdline_sha256")?.to_string(),
        system_sha256: read_cstr(raw.system_sha256, "spec.system_sha256")?.to_string(),
        verity_root_hash: read_cstr(raw.verity_root_hash, "spec.verity_root_hash")?.to_string(),
        workload_sha256: read_cstr(raw.workload_sha256, "spec.workload_sha256")?.to_string(),
        scratch_template_sha256: read_cstr(
            raw.scratch_template_sha256,
            "spec.scratch_template_sha256",
        )?
        .to_string(),
        scratch_template_bytes: raw.scratch_template_bytes,
        result_template_sha256: read_cstr(
            raw.result_template_sha256,
            "spec.result_template_sha256",
        )?
        .to_string(),
        result_template_bytes: raw.result_template_bytes,
        ram_mib: raw.ram_mib,
        vcpus: 0,
    };
    if spec.ram_mib == 0 {
        return Err(SpecError::RamZero);
    }
    if raw.vcpus == 0 {
        return Err(SpecError::VcpusZero);
    }
    if raw.vcpus > u8::MAX as u32 {
        return Err(SpecError::VcpusTooLarge(raw.vcpus));
    }
    spec.vcpus = raw.vcpus as u8;
    for (val, what) in [
        (&spec.spec_sha256, "spec.spec_sha256"),
        (&spec.kernel_sha256, "spec.kernel_sha256"),
        (&spec.cmdline_sha256, "spec.cmdline_sha256"),
        (&spec.system_sha256, "spec.system_sha256"),
        (&spec.verity_root_hash, "spec.verity_root_hash"),
        (&spec.workload_sha256, "spec.workload_sha256"),
        (&spec.scratch_template_sha256, "spec.scratch_template_sha256"),
        (&spec.result_template_sha256, "spec.result_template_sha256"),
    ] {
        if !is_hex64(val) {
            return Err(SpecError::DigestSyntax(what));
        }
    }
    if let Some(pin) = &spec.initrd_sha256 {
        if !is_hex64(pin) {
            return Err(SpecError::DigestSyntax("spec.initrd_sha256"));
        }
    }
    if !spec.cmdline.bytes().all(|c| matches!(c, b' '..=b'~')) {
        return Err(SpecError::CmdlineInvalid);
    }
    let cmax = LaunchSpecV3::cmdline_max();
    if spec.cmdline.len() > cmax {
        return Err(SpecError::CmdlineTooLong(spec.cmdline.len(), cmax));
    }
    check_template(spec.scratch_template_bytes, "scratch", crate::disks_v3::SCRATCH_TEMPLATE_BYTES_MAX)?;
    check_template(spec.result_template_bytes, "result", crate::disks_v3::TEMPLATE_BYTES_MAX)?;
    spec.check_verity_cmdline_consistency()?;
    Ok(spec)
}

#[cfg(test)]
mod template_capacity_tests {
    use super::*;
    #[test]
    fn separate_caps_and_alignment_refuse_boundaries() {
        for (name, cap) in [("scratch", crate::disks_v3::SCRATCH_TEMPLATE_BYTES_MAX), ("result", crate::disks_v3::TEMPLATE_BYTES_MAX)] {
            assert!(check_template(512, name, cap).is_ok());
            assert!(check_template(cap, name, cap).is_ok());
            for refused in [0, cap + 1, cap + 512] {
                assert!(check_template(refused, name, cap).is_err());
            }
        }
        assert!(check_template((1 << 30) + 512, "scratch", crate::disks_v3::SCRATCH_TEMPLATE_BYTES_MAX).is_ok());
        assert!(check_template((1 << 30) + 512, "result", crate::disks_v3::TEMPLATE_BYTES_MAX).is_err());
    }
}
