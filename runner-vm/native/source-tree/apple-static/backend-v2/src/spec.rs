//! The admitted launch_spec: the EXTERNAL identity unit of the v2 backend.
//!
//! v1 compiled image identity into the archive; v2 receives it in the
//! admission-bound `dsmack_ctl_launch_spec` (see abi/dsmack_ctl_join_v2.h,
//! from mac-general-prep's dsmack_ctl_join_v2_proposal.h). The backend
//! re-verifies every expectation against the bytes/devices it actually
//! consumes and refuses BEFORE any VM exists on ANY mismatch.
//!
//! Division of trust (deliberate, mirrors mac-general-prep launcher core):
//! - this module performs SYNTAX + internal-consistency validation only.
//!   That the spec_sha256 is one an external admission policy actually
//!   admitted is the relying party's boundary (the app must enforce
//!   admission before calling; the verifier checks both app identity and
//!   image identity). Structural parsing never authorizes anything
//!   (astra C01): a syntactically perfect spec for a non-admitted image is
//!   still refused by admission — OUTSIDE this crate.
//! - resource bounds: ram_mib/vcpus must be non-zero (the v2 "resource
//!   zero" refusal, mac-general-prep JOIN-PLAN step 1.2) and vcpus must fit
//!   the builder's u8. The POLICY caps (e.g. ≤3 GiB / ≤4 vCPU smoke bounds)
//!   are enforced by the caller before the call; the backend cannot know
//!   them and does not pretend to.

use std::ffi::CStr;

use crate::ctl_capi;
use crate::owned_verified::{self, VerifiedBootPins};

/// Lowercase-hex sha256 syntax (64 chars) — the same rule as the vendored
/// pin syntax check in owned_verified.rs.
pub fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// Maximum scratch-path length the disk-set parse accepts. This is the
/// receipt-evidence bound: the launch receipt carries the scratch path
/// verbatim (R5), so the path the caller supplies is bounded exactly like
/// the cmdline (fable-native-audit F4). The constant lives beside the
/// cmdline limit and `crate::receipt::worst_case_cap()` is written against
/// it; enforcement is at the FFI disk-set read (ctl_capi).
pub const SCRATCH_PATH_MAX_BYTES: usize = 256;

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
    #[error("cmdline dstack.rootfs_hash {got} != spec verity_root_hash")]
    VerityCmdlineMismatch { got: String },
}

/// The validated Rust form of `dsmack_ctl_launch_spec`. `cmdline` is owned
/// immediately: the C string is read exactly once here and never borrowed.
#[derive(Clone, Debug)]
pub struct LaunchSpec {
    pub spec_sha256: String,
    pub kernel_sha256: String,
    pub initrd_sha256: Option<String>,
    pub cmdline: String,
    pub cmdline_sha256: String,
    pub system_sha256: String,
    pub verity_root_hash: String,
    pub workload_sha256: String,
    pub ram_mib: u32,
    pub vcpus: u8,
}

/// The verified-boot pins derived from the admitted spec — this is how the
/// external policy replaces the v1 compiled-in pins. Nothing else in the
/// backend may manufacture pins.
impl LaunchSpec {
    pub fn pins(&self) -> VerifiedBootPins<'_> {
        VerifiedBootPins {
            kernel_sha256: &self.kernel_sha256,
            initrd_sha256: self.initrd_sha256.as_deref(),
            cmdline_sha256: &self.cmdline_sha256,
        }
    }

    /// cmdline byte limit: VERIFIED_CMDLINE_MAX_BYTES (4096) capped by the
    /// upstream aarch64 CMDLINE_MAX_SIZE (2048, NUL included) — identical to
    /// the vendored check in owned_verified.rs.
    pub fn cmdline_max() -> usize {
        owned_verified::VERIFIED_CMDLINE_MAX_BYTES.min(crate::arch::CMDLINE_MAX_SIZE - 1)
    }

    /// contract8 admission cross-check, wired as a backend refusal (D-series:
    /// "verity_root_hash must equal the cmdline's dstack.rootfs_hash"): when
    /// the cmdline carries the dstack rootfs binding, the spec's committed
    /// verity root must equal it, byte for byte. Images whose cmdline has no
    /// dstack.rootfs_hash= (e.g. the Alpine prototype fixtures) skip this.
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

fn read_cstr<'a>(
    p: *const std::ffi::c_char,
    what: &'static str,
) -> Result<std::borrow::Cow<'a, str>, SpecError> {
    if p.is_null() {
        return Err(SpecError::Null(what));
    }
    // SAFETY: caller passes a valid NUL-terminated string for the whole call
    // (ABI contract); we dereference once here, never retain the pointer.
    unsafe { CStr::from_ptr(p) }
        .to_str()
        .map(std::borrow::Cow::Borrowed)
        .map_err(|_| SpecError::NotUtf8(what))
}

fn read_digest(
    p: *const std::ffi::c_char,
    what: &'static str,
) -> Result<String, SpecError> {
    // STRICT lowercase-hex (no normalization): an uppercase digest is a
    // refusal, matching the vendored pin-syntax rule — fail closed, never
    // silently canonicalize caller identity material.
    Ok(read_cstr(p, what)?.to_string())
}

/// Parse + validate the raw C launch_spec. Reads every pointed-to string
/// EXACTLY ONCE and owns the result (R1 discipline applies to the spec too:
/// the caller may free it right after the call).
///
/// # Safety
/// `raw` must point to a fully initialized `DsmackCtlLaunchSpec` whose char
/// pointers are either null (initrd_sha256 only) or valid NUL-terminated
/// UTF-8 strings for the whole call.
pub unsafe fn launch_spec_from_raw(
    raw: &ctl_capi::DsmackCtlLaunchSpec,
) -> Result<LaunchSpec, SpecError> {
    let cmdline = read_cstr(raw.cmdline, "spec.cmdline")?.to_string();
    let initrd_pin = if raw.initrd_sha256.is_null() {
        None
    } else {
        Some(read_digest(raw.initrd_sha256, "spec.initrd_sha256")?)
    };
    let spec = LaunchSpec {
        spec_sha256: read_digest(raw.spec_sha256, "spec.spec_sha256")?,
        kernel_sha256: read_digest(raw.kernel_sha256, "spec.kernel_sha256")?,
        initrd_sha256: initrd_pin,
        cmdline,
        cmdline_sha256: read_digest(raw.cmdline_sha256, "spec.cmdline_sha256")?,
        system_sha256: read_digest(raw.system_sha256, "spec.system_sha256")?,
        verity_root_hash: read_digest(raw.verity_root_hash, "spec.verity_root_hash")?,
        workload_sha256: read_digest(raw.workload_sha256, "spec.workload_sha256")?,
        ram_mib: raw.ram_mib,
        vcpus: 0, // set below after the bound check
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
    let mut spec = spec;
    spec.vcpus = raw.vcpus as u8;
    if !is_hex64(&spec.spec_sha256) {
        return Err(SpecError::DigestSyntax("spec.spec_sha256"));
    }
    if !is_hex64(&spec.kernel_sha256) {
        return Err(SpecError::DigestSyntax("spec.kernel_sha256"));
    }
    if let Some(pin) = &spec.initrd_sha256 {
        if !is_hex64(pin) {
            return Err(SpecError::DigestSyntax("spec.initrd_sha256"));
        }
    }
    if !is_hex64(&spec.cmdline_sha256) {
        return Err(SpecError::DigestSyntax("spec.cmdline_sha256"));
    }
    if !is_hex64(&spec.system_sha256) {
        return Err(SpecError::DigestSyntax("spec.system_sha256"));
    }
    if !is_hex64(&spec.verity_root_hash) {
        return Err(SpecError::DigestSyntax("spec.verity_root_hash"));
    }
    if !is_hex64(&spec.workload_sha256) {
        return Err(SpecError::DigestSyntax("spec.workload_sha256"));
    }
    if !spec.cmdline.bytes().all(|c| matches!(c, b' '..=b'~')) {
        return Err(SpecError::CmdlineInvalid);
    }
    let cmdline_max = LaunchSpec::cmdline_max();
    if spec.cmdline.len() > cmdline_max {
        return Err(SpecError::CmdlineTooLong(spec.cmdline.len(), cmdline_max));
    }
    spec.check_verity_cmdline_consistency()?;
    Ok(spec)
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    fn spec_full(cmdline: &str, verity: &str) -> Result<LaunchSpec, SpecError> {
        let c = std::ffi::CString::new(cmdline).unwrap();
        let d = std::ffi::CString::new(D).unwrap();
        let v = std::ffi::CString::new(verity).unwrap();
        let raw = ctl_capi::DsmackCtlLaunchSpec {
            spec_sha256: d.as_ptr(),
            kernel_sha256: d.as_ptr(),
            initrd_sha256: d.as_ptr(),
            cmdline: c.as_ptr(),
            cmdline_sha256: d.as_ptr(),
            system_sha256: d.as_ptr(),
            verity_root_hash: v.as_ptr(),
            workload_sha256: d.as_ptr(),
            ram_mib: 2048,
            vcpus: 2,
        };
        // SAFETY: test builds a fully initialized spec with valid strings.
        unsafe { launch_spec_from_raw(&raw) }
    }

    fn spec_with_cmdline(cmdline: &str) -> Result<LaunchSpec, SpecError> {
        spec_full(cmdline, D)
    }

    #[test]
    fn valid_spec_parses_and_owns_cmdline() {
        let s = spec_with_cmdline("console=hvc0 panic=-1").unwrap();
        assert_eq!(s.vcpus, 2);
        assert_eq!(s.ram_mib, 2048);
        assert_eq!(s.initrd_sha256.as_deref(), Some(D));
        assert_eq!(LaunchSpec::cmdline_max(), 2047);
    }

    #[test]
    fn resource_zero_refused() {
        let c = std::ffi::CString::new("x").unwrap();
        let d = std::ffi::CString::new(D).unwrap();
        let mk = |ram: u32, vcpus: u32| ctl_capi::DsmackCtlLaunchSpec {
            spec_sha256: d.as_ptr(),
            kernel_sha256: d.as_ptr(),
            initrd_sha256: d.as_ptr(),
            cmdline: c.as_ptr(),
            cmdline_sha256: d.as_ptr(),
            system_sha256: d.as_ptr(),
            verity_root_hash: d.as_ptr(),
            workload_sha256: d.as_ptr(),
            ram_mib: ram,
            vcpus,
        };
        // SAFETY: fully initialized spec, valid strings.
        assert_eq!(
            unsafe { launch_spec_from_raw(&mk(0, 1)) }.unwrap_err(),
            SpecError::RamZero
        );
        assert_eq!(
            unsafe { launch_spec_from_raw(&mk(1, 0)) }.unwrap_err(),
            SpecError::VcpusZero
        );
        assert_eq!(
            unsafe { launch_spec_from_raw(&mk(1, 256)) }.unwrap_err(),
            SpecError::VcpusTooLarge(256)
        );
    }

    #[test]
    fn digest_syntax_refused() {
        let c = std::ffi::CString::new("x").unwrap();
        let d = std::ffi::CString::new(D).unwrap();
        let upper = std::ffi::CString::new(D.to_uppercase()).unwrap();
        let raw = ctl_capi::DsmackCtlLaunchSpec {
            spec_sha256: upper.as_ptr(),
            kernel_sha256: d.as_ptr(),
            initrd_sha256: d.as_ptr(),
            cmdline: c.as_ptr(),
            cmdline_sha256: d.as_ptr(),
            system_sha256: d.as_ptr(),
            verity_root_hash: d.as_ptr(),
            workload_sha256: d.as_ptr(),
            ram_mib: 1,
            vcpus: 1,
        };
        // SAFETY: fully initialized spec, valid strings.
        // Uppercase is REFUSED, never normalized (fail-closed identity).
        assert_eq!(
            unsafe { launch_spec_from_raw(&raw) }.unwrap_err(),
            SpecError::DigestSyntax("spec.spec_sha256")
        );
    }

    #[test]
    fn dstack_verity_cmdline_binding_enforced() {
        let root = "78f5bd655d64cfdc64adcef693352e007a20f664f7101e521f1a2b2cd04a6756";
        let ok = format!(
            "console=hvc0 init=/init panic=1 dstack.rootfs_hash={root} dstack.rootfs_size=209592320"
        );
        assert!(spec_full(&ok, root).is_ok());

        let wrong = format!(
            "console=hvc0 init=/init panic=1 dstack.rootfs_hash={:064x} dstack.rootfs_size=1",
            0xdead
        );
        match spec_full(&wrong, root).unwrap_err() {
            SpecError::VerityCmdlineMismatch { got } => {
                assert_eq!(got, format!("{:064x}", 0xdead));
            }
            other => panic!("expected VerityCmdlineMismatch, got {other:?}"),
        }
        // Non-dstack cmdline (Alpine prototype shape) skips the binding.
        assert!(spec_with_cmdline("console=ttyAMA0,115200 console=hvc0 panic=-1").is_ok());
    }

    #[test]
    fn cmdline_invalid_and_too_long_refused() {
        // Interior NUL can never arrive through a NUL-terminated C string;
        // the printable-ASCII rule still refuses tab/newline/high bytes.
        assert_eq!(
            spec_with_cmdline("tab\there").unwrap_err(),
            SpecError::CmdlineInvalid
        );
        assert_eq!(
            spec_with_cmdline("nl\nhere").unwrap_err(),
            SpecError::CmdlineInvalid
        );
        let long = "a".repeat(LaunchSpec::cmdline_max() + 1);
        assert_eq!(
            spec_with_cmdline(&long).unwrap_err(),
            SpecError::CmdlineTooLong(LaunchSpec::cmdline_max() + 1, LaunchSpec::cmdline_max())
        );
    }
}
