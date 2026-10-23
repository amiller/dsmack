//! Control-profile C ABI, version 2 (abi/dsmack_ctl_join_v2.h).
//!
//! The general-launcher replacement for source3's v1 control profile
//! (backend/apple-static/src/ctl_capi.rs): compiled-in pins are GONE — every
//! identity expectation arrives in the external admitted `launch_spec`, the
//! device set is the vda/vdb/vdc triple, resources come from the admitted
//! profile, and the verified boot is the owned-buffer route (R1-R5).
//!
//! Preserved verbatim from v1 (protected integration points, NOT redesigned):
//! - the caller's `control_fd` is OWNED by this call on every return: closed
//!   exactly once on every refusal (astra-gate R4), kept alive inside the
//!   handle on success; the caller must never use or close it again;
//! - refusals fire BEFORE any VM exists;
//! - the console log is created O_EXCL as a regular file;
//! - `dsmack_ctl_join_run` consumes the handle and returns the VMM code
//!   (0 = guest halt via PSCI, NEVER workload success);
//! - `err`/`err_cap` semantics (null/0-tolerant, NUL-terminated messages).

use std::os::fd::{FromRawFd, OwnedFd};

use crate::consumption::{Consumption, MemoryPlacement};
use crate::disks::{self, DiskRole};
use crate::owned_verified::VerifiedBootImages;
use crate::receipt::LaunchReceipt;
use crate::spec;

/// v2: refusals name fields plus both digest sides, so the cap grows from
/// v1's 256 to 512; the version bump makes every old caller re-query.
pub const ERR_CAP_MIN: usize = 512;
pub const ABI_VERSION: i32 = 2;

/// `dsmack_ctl_launch_spec` — MUST match abi/dsmack_ctl_join_v2.h exactly.
#[repr(C)]
pub struct DsmackCtlLaunchSpec {
    pub spec_sha256: *const std::ffi::c_char,
    pub kernel_sha256: *const std::ffi::c_char,
    pub initrd_sha256: *const std::ffi::c_char, // NULL = no initrd
    pub cmdline: *const std::ffi::c_char,
    pub cmdline_sha256: *const std::ffi::c_char,
    pub system_sha256: *const std::ffi::c_char,
    pub verity_root_hash: *const std::ffi::c_char,
    pub workload_sha256: *const std::ffi::c_char,
    pub ram_mib: u32,
    pub vcpus: u32,
}

/// `dsmack_ctl_disk_set` — MUST match abi/dsmack_ctl_join_v2.h exactly.
#[repr(C)]
pub struct DsmackCtlDiskSet {
    pub system_path: *const std::ffi::c_char,
    pub scratch_path: *const std::ffi::c_char,
    pub workload_path: *const std::ffi::c_char,
}

pub(crate) fn err_set(err: *mut u8, err_cap: usize, msg: &str) {
    if err.is_null() || err_cap < ERR_CAP_MIN {
        return;
    }
    let bytes = msg.as_bytes();
    let n = bytes.len().min(err_cap - 1);
    // SAFETY: err writable for err_cap bytes (caller contract, checked above).
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), err, n);
        *err.add(n) = 0;
    }
}

fn cstr(p: *const std::ffi::c_char, what: &'static str) -> Result<String, String> {
    if p.is_null() {
        return Err(format!("{what}: null"));
    }
    // SAFETY: caller passes a valid NUL-terminated string for the whole call.
    unsafe { std::ffi::CStr::from_ptr(p) }
        .to_str()
        .map(str::to_string)
        .map_err(|_| format!("{what}: not UTF-8"))
}

/// The backend's consumption choice. On this crate alone (any host) the
/// engineering placement model proves the ABI semantics; the REAL guest run
/// path is the krun HVF consumption supplied by the integration patch on
/// aarch64 macOS — never a silent substitute.
fn default_consumption() -> Box<dyn Consumption> {
    // Integration hook first: the krun-backed archive (integration patch,
    // aarch64 macOS) installs its HVF factory exactly once, one-way. Never a
    // silent substitute — whatever serves the FFI is named in the receipt.
    let f = FACTORY.load(std::sync::atomic::Ordering::SeqCst);
    if f != 0 {
        let f: fn() -> Box<dyn Consumption> = unsafe { std::mem::transmute(f) };
        return f();
    }
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    {
        Box::new(HvfNotLinked)
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "macos")))]
    {
        Box::new(MemoryPlacement)
    }
}

/// One-way installation slot for the platform consumption factory (see
/// `default_consumption`). Returns false if a factory is already installed.
pub fn install_consumption_factory(f: fn() -> Box<dyn Consumption>) -> bool {
    FACTORY
        .compare_exchange(
            0,
            f as usize,
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
        )
        .is_ok()
}

static FACTORY: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
struct HvfNotLinked;
#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
impl Consumption for HvfNotLinked {
    fn label(&self) -> &'static str {
        "hvf-not-linked"
    }
    fn build(
        &self,
        _images: VerifiedBootImages,
        _disks: Vec<crate::disks::AttachedDisk>,
        control: OwnedFd,
        _console: std::fs::File,
        _receipt: LaunchReceipt,
    ) -> Result<Box<dyn crate::consumption::GuestVm>, crate::consumption::BuildRefused> {
        // Dropping `control` here closes the descriptor exactly once (R4).
        let _ = control;
        Err(crate::consumption::BuildRefused::Platform(
            "this archive alone does not implement the HVF consumption; link the \
             integration-patch apple-static v2 backend (krun) on aarch64 macOS"
                .into(),
        ))
    }
}

/// A built control-profile VM: the verified placement/VM and its receipt.
pub struct CtlVm {
    pub(crate) vm: Box<dyn crate::consumption::GuestVm>,
    pub(crate) receipt_json: String,
}

/// Build the general control-profile VM — ABI v2. Refusals (all BEFORE any
/// VM exists, each closing `control_fd` exactly once):
/// - `control_fd` negative (not a descriptor — nothing is claimed/closed);
/// - null/empty kernel buffer; initrd pointer presence != initrd pin presence;
/// - null/non-UTF-8 spec, disks, or console strings; any digest field not
///   64-lowercase-hex; cmdline not printable-ASCII or over limit;
///   `ram_mib`/`vcpus` zero; dstack.rootfs_hash cmdline binding mismatch;
/// - console log already existing (O_EXCL) or not a regular file;
/// - kernel/initrd/cmdline owned copies not hashing to the SPEC pins (R1);
/// - system/workload disk not a regular 512-multiple file or failing
///   verify-on-open; scratch inode already existing (fresh-inode refusal);
/// - consumption build failure (placement/freeze/platform).
///
/// # Safety
/// - `kernel`/`kernel_len` must describe a readable non-null non-empty
///   buffer for the whole call; `initrd`/`initrd_len` either both null/zero
///   (when the spec has no initrd pin) or a readable non-null non-empty
///   buffer. Slices are constructed only after these checks (A6 guard) and
///   read exactly once.
/// - `spec`, `disks` must point to fully initialized structs; every char*
///   within must be null (only where documented) or a valid NUL-terminated
///   UTF-8 string for the whole call.
/// - `console_path` must be a valid NUL-terminated UTF-8 path.
/// - `control_fd` must be an open bidirectional socket or pipe descriptor;
///   ownership moves into this call UNCONDITIONALLY.
/// - `err` (if non-null) must be writable for `err_cap` bytes with
///   `err_cap >= dsmack_ctl_join_err_cap_min()`; `err_cap == 0` requires
///   `err == null`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dsmack_ctl_join_vm_new(
    kernel: *const u8,
    kernel_len: usize,
    initrd: *const u8,
    initrd_len: usize,
    spec: *const DsmackCtlLaunchSpec,
    disks: *const DsmackCtlDiskSet,
    console_path: *const std::ffi::c_char,
    control_fd: i32,
    err: *mut u8,
    err_cap: usize,
) -> i64 {
    let fail = |m: String, err: *mut u8, cap: usize| -> i64 {
        err_set(err, cap, &m);
        0
    };
    // Ownership of the descriptor moves into this call FIRST — every refusal
    // below returns while `control` (or the console/builder state) is alive,
    // so the descriptor is closed exactly once on every path and never left
    // open-or-double-closeable (astra-gate R4, verbatim v1 discipline).
    let control = if control_fd >= 0 {
        // SAFETY: the caller handed us `control_fd` and must not touch it
        // again; it is a valid open descriptor until we close it.
        Some(unsafe { OwnedFd::from_raw_fd(control_fd) })
    } else {
        None // not a descriptor: nothing to own or close
    };
    let Some(control) = control else {
        return fail(format!("control fd {control_fd} invalid"), err, err_cap);
    };

    // Boot-buffer validation BEFORE any slice is constructed (A6 discipline:
    // a null pointer never reaches slice::from_raw_parts).
    if kernel.is_null() {
        return fail("null kernel buffer".into(), err, err_cap);
    }
    if kernel_len == 0 {
        return fail("empty kernel buffer".into(), err, err_cap);
    }
    if spec.is_null() {
        return fail("null launch_spec".into(), err, err_cap);
    }
    if disks.is_null() {
        return fail("null disk set".into(), err, err_cap);
    }
    // SAFETY: caller contract: fully initialized structs, valid strings.
    let (spec_res, disks_res) = unsafe { (&*spec, &*disks) };
    let spec = match spec::launch_spec_from_raw(spec_res) {
        Ok(s) => s,
        Err(e) => return fail(format!("launch_spec: {e}"), err, err_cap),
    };

    // initrd pointer presence must equal initrd pin presence, and a
    // non-null pointer with zero length is a refusal (ambiguous — v1 A6).
    let initrd_slice: Option<&[u8]> = if initrd.is_null() {
        if initrd_len != 0 {
            return fail("initrd_len set with null initrd".into(), err, err_cap);
        }
        None
    } else {
        if initrd_len == 0 {
            return fail("empty initrd buffer".into(), err, err_cap);
        }
        // SAFETY: validated non-null non-empty above; readable for the call.
        Some(unsafe { std::slice::from_raw_parts(initrd, initrd_len) })
    };
    if initrd_slice.is_some() != spec.initrd_sha256.is_some() {
        return fail(
            "initrd presence does not match initrd pin presence".into(),
            err,
            err_cap,
        );
    }

    let system_path = match cstr(disks_res.system_path, "disks.system_path") {
        Ok(p) => p,
        Err(m) => return fail(m, err, err_cap),
    };
    let scratch_path = match cstr(disks_res.scratch_path, "disks.scratch_path") {
        Ok(p) => p,
        Err(m) => return fail(m, err, err_cap),
    };
    // fable-native-audit F4: the scratch path is recorded verbatim in the
    // launch receipt (R5 evidence), so it is bounded exactly like the
    // cmdline. Over-bound paths are a refusal BEFORE anything is created.
    if scratch_path.len() > spec::SCRATCH_PATH_MAX_BYTES {
        return fail(
            format!(
                "disks.scratch_path {} bytes exceeds the {}-byte receipt-evidence bound",
                scratch_path.len(),
                spec::SCRATCH_PATH_MAX_BYTES
            ),
            err,
            err_cap,
        );
    }
    let workload_path = match cstr(disks_res.workload_path, "disks.workload_path") {
        Ok(p) => p,
        Err(m) => return fail(m, err, err_cap),
    };
    let console = match cstr(console_path, "console_path") {
        Ok(p) => p,
        Err(m) => return fail(m, err, err_cap),
    };
    let log = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&console)
    {
        Ok(f) => f,
        Err(e) => return fail(format!("console log {console}: {e}"), err, err_cap),
    };
    if log
        .metadata()
        .map(|m| !m.file_type().is_file())
        .unwrap_or(true)
    {
        return fail("console must be a regular file".into(), err, err_cap);
    }

    // R1: the ONLY pin source is the admitted spec; the owned copies are
    // hashed inside VerifiedBootImages::new. Caller buffers were read exactly
    // once (slices above); refusal happens before any VM object exists.
    let k = unsafe { std::slice::from_raw_parts(kernel, kernel_len) };
    let images = match VerifiedBootImages::new(k, initrd_slice, &spec.cmdline, &spec.pins()) {
        Ok(v) => v,
        Err(e) => return fail(format!("verified boot: {e}"), err, err_cap),
    };

    // Disk triple: verify-on-open for vda/vdc, fresh-inode O_EXCL for vdb.
    let mut attached = Vec::with_capacity(3);
    match disks::open_verified_ro(DiskRole::System, &system_path, &spec.system_sha256) {
        Ok(d) => attached.push(d),
        Err(e) => return fail(format!("{e}"), err, err_cap),
    }
    match disks::create_scratch(&scratch_path) {
        Ok(d) => attached.push(d),
        Err(e) => {
            return fail(format!("{e}"), err, err_cap);
        }
    }
    match disks::open_verified_ro(DiskRole::Workload, &workload_path, &spec.workload_sha256) {
        Ok(d) => attached.push(d),
        Err(e) => {
            // scratch was created on this path; best-effort unlink so a
            // refused launch leaves NO fresh scratch behind (fresh is per
            // ATTEMPT, not per refusal).
            let _ = std::fs::remove_file(&scratch_path);
            return fail(format!("{e}"), err, err_cap);
        }
    }

    let consumption = default_consumption();
    let receipt = LaunchReceipt::record(&spec, &images, &attached, consumption.label());
    // `control` and the console log move into the consumption (the descriptor
    // closed exactly once on its refusal, alive inside the handle on success
    // — v1 R4 semantics; the console log belongs to the built VM).
    let vm = match consumption.build(images, attached, control, log, receipt) {
        Ok(vm) => vm,
        Err(e) => {
            let _ = std::fs::remove_file(&scratch_path);
            return fail(format!("consumption: {e}"), err, err_cap);
        }
    };
    let receipt_json = vm.receipt().to_json();
    Box::into_raw(Box::new(CtlVm {
        vm,
        receipt_json,
    })) as i64
}

/// Run the whole lifecycle to completion. The handle is CONSUMED. Returns
/// the VMM code (0 = guest halt via PSCI, NOT workload success) or -1 on a
/// refusal/fault (err set). The console log must be read only AFTER this.
///
/// # Safety
/// - `handle` must be a value returned by `dsmack_ctl_join_vm_new` not yet
///   run; consumed exactly once, never reused.
/// - `err` (if non-null) must be writable for `err_cap` bytes with
///   `err_cap >= dsmack_ctl_join_err_cap_min()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dsmack_ctl_join_run(handle: i64, err: *mut u8, err_cap: usize) -> i32 {
    if handle == 0 {
        err_set(err, err_cap, "run: zero handle");
        return -1;
    }
    // SAFETY: handle came from dsmack_ctl_join_vm_new and is consumed once.
    let vm = unsafe { Box::from_raw(handle as *mut CtlVm) };
    match vm.vm.run() {
        Ok(code) => code,
        Err(e) => {
            err_set(err, err_cap, &format!("run: {e}"));
            -1
        }
    }
}

/// v2 addition (R5 evidence surface): copy the launch receipt JSON of the
/// handle into `out` (NUL-terminated). The receipt is NEVER truncated: an
/// out_cap smaller than the receipt is a refusal (fable-native-audit F4 —
/// the header text said "truncated", the implementation always refused;
/// the contract is the refusal). The handle is NOT consumed; valid before
/// or after `dsmack_ctl_join_run` — but the handle must not be reused after
/// run consumed it. Returns 0 on success, -1 on refusal (zero handle, null
/// out, out_cap too small for `dsmack_ctl_join_receipt_cap_min()` bytes —
/// which is the computed worst case, so a cap_min allocation always
/// succeeds for any legal spec).
///
/// # Safety
/// `out` (if non-null) must be writable for `out_cap` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dsmack_ctl_join_receipt(
    handle: i64,
    out: *mut u8,
    out_cap: usize,
) -> i32 {
    if handle == 0 || out.is_null() || out_cap == 0 {
        return -1;
    }
    // SAFETY: handle is a live CtlVm pointer (not yet consumed by run);
    // we only read the receipt JSON — no state mutation.
    let vm = unsafe { &*(handle as *const CtlVm) };
    let bytes = vm.receipt_json.as_bytes();
    if bytes.len() + 1 > out_cap {
        return -1;
    }
    // SAFETY: out writable for out_cap bytes (caller contract).
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
        *out.add(bytes.len()) = 0;
    }
    0
}

/// Smallest `out` buffer `dsmack_ctl_join_receipt` accepts: the COMPUTED
/// WORST CASE for any receipt this ABI can produce (fable-native-audit F4:
/// the fixed 2048 was not a worst case — a max-length cmdline alone
/// overflowed it, and BackendV2.swift allocates exactly cap_min, so legal
/// launches could fail evidence collection). A caller allocating this
/// value always succeeds; a smaller buffer simply refuses.
#[unsafe(no_mangle)]
pub extern "C" fn dsmack_ctl_join_receipt_cap_min() -> usize {
    crate::receipt::worst_case_cap()
}

#[unsafe(no_mangle)]
pub extern "C" fn dsmack_ctl_join_abi_version() -> i32 {
    ABI_VERSION
}

#[unsafe(no_mangle)]
pub extern "C" fn dsmack_ctl_join_err_cap_min() -> usize {
    ERR_CAP_MIN
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_surface_values() {
        assert_eq!(dsmack_ctl_join_abi_version(), 2);
        assert_eq!(dsmack_ctl_join_err_cap_min(), 512);
        assert!(dsmack_ctl_join_receipt_cap_min() >= 1024);
    }

    #[test]
    fn consumption_factory_installs_one_way_and_is_used() {
        use sha2::{Digest, Sha256};
        let sha = |b: &[u8]| format!("{:x}", Sha256::digest(b));
        let c = |s: String| std::ffi::CString::new(s).unwrap();

        // A labeled stand-in factory proves the install point routes the FFI
        // (the krun HVF archive installs the REAL one on aarch64 macOS).
        struct FactoryProbe;
        impl Consumption for FactoryProbe {
            fn label(&self) -> &'static str {
                "factory-probe"
            }
            fn build(
                &self,
                _images: VerifiedBootImages,
                _disks: Vec<crate::disks::AttachedDisk>,
                control: OwnedFd,
                _console: std::fs::File,
                _receipt: LaunchReceipt,
            ) -> Result<Box<dyn crate::consumption::GuestVm>, crate::consumption::BuildRefused>
            {
                let _ = control; // closed exactly once on this refusal (R4)
                Err(crate::consumption::BuildRefused::Platform(
                    "factory-probe refusal (expected)".into(),
                ))
            }
        }
        fn factory() -> Box<dyn Consumption> {
            Box::new(FactoryProbe)
        }
        assert!(
            install_consumption_factory(factory),
            "first install must win"
        );
        assert!(
            !install_consumption_factory(factory),
            "second install must be refused (one-way)"
        );

        // Route the full FFI: the refusal must now come from the factory.
        let d = std::env::temp_dir().join(format!("dsmack-factory-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let mut kernel = vec![0u8; 512];
        kernel[56..60].copy_from_slice(b"ARM\x64");
        let sys = d.join("system.img");
        std::fs::write(&sys, vec![0u8; 512]).unwrap();
        let wl = d.join("workload.img");
        std::fs::write(&wl, vec![1u8; 512]).unwrap();
        let cmdline = c("console=hvc0".into());
        // Every CString binds to a local: the ABI reads pointers for the
        // duration of the call only, but temporaries inside the struct
        // literal would drop before the call below.
        let s_spec = c(sha(b"spec"));
        let s_k = c(sha(&kernel));
        let s_cmd = c(sha(cmdline.to_bytes()));
        let s_sys = c(sha(&[0u8; 512]));
        let s_ver = c(sha(b"verity"));
        let s_wl = c(sha(&[1u8; 512]));
        let p_sys = c(sys.to_str().unwrap().into());
        let p_scratch = c(d.join("scratch.img").to_str().unwrap().into());
        let p_wl = c(wl.to_str().unwrap().into());
        let console = c(d.join("console.log").to_str().unwrap().into());
        let spec = DsmackCtlLaunchSpec {
            spec_sha256: s_spec.as_ptr(),
            kernel_sha256: s_k.as_ptr(),
            initrd_sha256: std::ptr::null(),
            cmdline: cmdline.as_ptr(),
            cmdline_sha256: s_cmd.as_ptr(),
            system_sha256: s_sys.as_ptr(),
            verity_root_hash: s_ver.as_ptr(),
            workload_sha256: s_wl.as_ptr(),
            ram_mib: 512,
            vcpus: 1,
        };
        let disks = DsmackCtlDiskSet {
            system_path: p_sys.as_ptr(),
            scratch_path: p_scratch.as_ptr(),
            workload_path: p_wl.as_ptr(),
        };
        let mut fds = [0 as libc::c_int; 2];
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) },
            0
        );
        let mut err = [0u8; ERR_CAP_MIN];
        // SAFETY: fully initialized fixture, valid strings/buffers.
        let h = unsafe {
            dsmack_ctl_join_vm_new(
                kernel.as_ptr(),
                kernel.len(),
                std::ptr::null(),
                0,
                &spec,
                &disks,
                console.as_ptr(),
                fds[1],
                err.as_mut_ptr(),
                err.len(),
            )
        };
        assert_eq!(h, 0, "factory probe refuses before any VM");
        let end = err.iter().position(|b| *b == 0).unwrap_or(err.len());
        let msg = String::from_utf8_lossy(&err[..end]).into_owned();
        assert!(msg.contains("factory-probe refusal"), "{msg}");
        // descriptor closed exactly once by the probe refusal
        assert_eq!(unsafe { libc::fcntl(fds[1], libc::F_GETFD) }, -1);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn err_set_truncates_safely() {
        let mut buf = [0u8; ERR_CAP_MIN];
        let long = "x".repeat(4096);
        err_set(buf.as_mut_ptr(), ERR_CAP_MIN, &long);
        assert_eq!(buf[ERR_CAP_MIN - 1], 0);
        assert_eq!(buf[ERR_CAP_MIN - 2], b'x');
        // under-cap buffer: silently ignored (caller contract violation)
        let mut small = [0u8; 8];
        err_set(small.as_mut_ptr(), 8, "nope");
        assert_eq!(small, [0u8; 8]);
    }
}
