//! signed-app-join C ABI over the reviewed returning lifecycle (UNSIGNED INTEGRATION
//! FIXTURE — requires independent exact source review before any execution or signing).
//!
//! Minimal surface, pinned exactly like `dsmack_probe_main` (same compiled-in constants):
//! the caller supplies kernel+initrd BYTES (read-once semantics as in the mar app), the
//! console log path is created O_EXCL as a regular file, and the whole lifecycle —
//! verified payload, 1 vCPU / 512 MiB returning profile, run_returning, checked
//! stop/finish teardown — happens inside `dsmack_join_run`. No extra devices, consoles
//! or options are expressible: the returning profile rejects them before VM construction.
//! Code 0 means guest halt (PSCI SYSTEM_OFF/RESET), not workload success.
use crate::verified_bytes;
use krun::api::{Payload, VmmBuilder};
use std::fs::OpenOptions;

// Identical pins/limits to the reviewed probe wrapper (lib.rs) — single source of truth
// via `verified_bytes` in lib.rs; the constants stay compiled in, never caller-supplied.
pub(crate) const ERR_CAP_MIN: usize = 256;

pub(crate) fn err_set(err: *mut u8, err_cap: usize, msg: &str) {
    if err.is_null() || err_cap < ERR_CAP_MIN {
        return;
    }
    let bytes = msg.as_bytes();
    let n = bytes.len().min(err_cap - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), err, n);
        *err.add(n) = 0;
    }
}

/// Validate the caller-supplied byte buffers BEFORE any slice is constructed.
/// A null pointer must never reach `slice::from_raw_parts` — its contract is
/// violated by a null pointer even for a zero-length slice — and this
/// pinned-initrd profile additionally requires the initrd outright: the
/// compiled-in pins verify `Some(INITRD_SHA256)`, so an absent initrd is a
/// refusal, not an empty boot.
pub(crate) fn validate_boot_buffers(
    kernel: *const u8,
    kernel_len: usize,
    initrd: *const u8,
    initrd_len: usize,
) -> Result<(), &'static str> {
    if kernel.is_null() {
        return Err("null kernel buffer");
    }
    if kernel_len == 0 {
        return Err("empty kernel buffer");
    }
    if initrd.is_null() || initrd_len == 0 {
        return Err("absent initrd (this profile requires pinned initrd bytes)");
    }
    Ok(())
}

struct JoinVm {
    builder: VmmBuilder<'static>,
}

/// Build the returning-profile VM from owned bytes. Returns an opaque handle (>0) or 0 on
/// refusal. Refusals match the reviewed wrapper/probe semantics exactly: byte limits,
/// compiled-in pin mismatch, console log creation, and every returning-profile guard
/// (aarch64 macOS, 1 vCPU, verified owned payload, regular-file console) fire inside
/// `build()` BEFORE any VM exists.
///
/// # Safety
/// - `kernel`/`kernel_len` and `initrd`/`initrd_len` must describe readable buffers for
///   the whole call. Both pointers must be non-null with non-zero lengths: the
///   pinned-initrd profile refuses an absent initrd (refusal, not an empty boot).
/// - `console_path` must be a valid NUL-terminated UTF-8 path for the whole call.
/// - `err` (if non-null) must be writable for `err_cap` bytes, with
///   `err_cap >= dsmack_join_err_cap_min()`; `err_cap == 0` requires `err == null`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dsmack_join_vm_new(
    kernel: *const u8,
    kernel_len: usize,
    initrd: *const u8,
    initrd_len: usize,
    console_path: *const std::ffi::c_char,
    err: *mut u8,
    err_cap: usize,
) -> i64 {
    let fail = |m: String, err: *mut u8, cap: usize| -> i64 {
        err_set(err, cap, &m);
        0
    };
    if let Err(why) = validate_boot_buffers(kernel, kernel_len, initrd, initrd_len) {
        return fail(why.to_string(), err, err_cap);
    }
    // SAFETY: caller guarantees kernel/kernel_len and initrd/initrd_len describe readable
    // non-null buffers for the duration of this call (validated above); the bytes are
    // copied into the verified payload.
    let k = unsafe { std::slice::from_raw_parts(kernel, kernel_len) };
    let i = unsafe { std::slice::from_raw_parts(initrd, initrd_len) };
    let path = if console_path.is_null() {
        return fail("null console path".into(), err, err_cap);
    } else {
        // SAFETY: caller passes a valid NUL-terminated string for the lifetime of the call.
        match unsafe { std::ffi::CStr::from_ptr(console_path) }.to_str() {
            Ok(p) => p,
            Err(_) => return fail("console path not UTF-8".into(), err, err_cap),
        }
    };
    let log = match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(f) => f,
        Err(e) => return fail(format!("console log {path}: {e}"), err, err_cap),
    };
    if log
        .metadata()
        .map(|m| !m.file_type().is_file())
        .unwrap_or(true)
    {
        return fail("console must be a regular file".into(), err, err_cap);
    }
    let pins = verified_bytes::pins();
    let payload =
        match Payload::load_external_raw_verified(k, Some(i), verified_bytes::CMDLINE, &pins) {
            Ok(p) => p,
            Err(e) => return fail(format!("verified payload: {e:?}"), err, err_cap),
        };
    let builder = match VmmBuilder::new()
        .vcpus(1)
        .map_err(|e| format!("vcpus: {e:?}"))
    {
        Ok(b) => b,
        Err(m) => return fail(m, err, err_cap),
    };
    let builder = match builder.ram_mib(512).map_err(|e| format!("memory: {e:?}")) {
        Ok(b) => b,
        Err(m) => return fail(m, err, err_cap),
    };
    let builder = builder.payload(payload).returning_console(log);
    let join = Box::new(JoinVm { builder });
    Box::into_raw(join) as i64
}

/// Run the whole returning lifecycle to completion: run_returning performs the checked
/// `stop_returning` (observer drain, bounded vCPU joins) and `finish_returning`
/// (drop-owners -> vm.destroy() -> drop guest memory) before returning. The handle is
/// consumed. Returns the VMM code (0 = guest halt; PSCI, not workload success) or -1 on
/// an unrecoverable lifecycle fault (the library aborts on panic mid-teardown, mirroring
/// the reviewed wrapper guard).
///
/// # Safety
/// - `handle` must be a value returned by `dsmack_join_vm_new` that has not yet been run;
///   it is consumed exactly once and must not be reused afterwards.
/// - `err` (if non-null) must be writable for `err_cap` bytes, with
///   `err_cap >= dsmack_join_err_cap_min()`; `err_cap == 0` requires `err == null`.
/// - The console log must be read only AFTER this returns (output commitments over final
///   bytes, after checked teardown).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dsmack_join_run(handle: i64, err: *mut u8, err_cap: usize) -> i32 {
    if handle == 0 {
        err_set(err, err_cap, "run: zero handle");
        return -1;
    }
    let join = unsafe { Box::from_raw(handle as *mut JoinVm) };
    let vm = join.builder.build();
    let vm = match vm {
        Ok(v) => v,
        Err(e) => {
            err_set(err, err_cap, &format!("build: {e:?}"));
            return -1;
        }
    };
    // run_returning exists only for the aarch64-macOS returning profile; other
    // hosts compile this ABI for unit coverage only and never execute a VM.
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    {
        vm.run_returning() as i32
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "macos")))]
    {
        drop(vm);
        err_set(
            err,
            err_cap,
            "run: returning lifecycle requires aarch64 macOS",
        );
        -1
    }
}

/// Minimal-error-surface query for callers: the smallest err buffer this ABI accepts.
#[unsafe(no_mangle)]
pub extern "C" fn dsmack_join_err_cap_min() -> usize {
    ERR_CAP_MIN
}

#[cfg(test)]
mod tests {
    use super::validate_boot_buffers;

    // A6 boundary coverage: a null pointer must never reach
    // slice::from_raw_parts, and the pinned-initrd profile refuses an absent
    // initrd outright rather than booting with an empty one.
    static KERNEL: [u8; 4] = [1, 2, 3, 4];
    static INITRD: [u8; 4] = [5, 6, 7, 8];

    #[test]
    fn null_kernel_rejected() {
        assert_eq!(
            validate_boot_buffers(std::ptr::null(), 0, INITRD.as_ptr(), INITRD.len()),
            Err("null kernel buffer")
        );
        assert_eq!(
            validate_boot_buffers(std::ptr::null(), 16, INITRD.as_ptr(), INITRD.len()),
            Err("null kernel buffer")
        );
    }

    #[test]
    fn empty_kernel_rejected() {
        assert_eq!(
            validate_boot_buffers(KERNEL.as_ptr(), 0, INITRD.as_ptr(), INITRD.len()),
            Err("empty kernel buffer")
        );
    }

    #[test]
    fn null_initrd_rejected_even_with_zero_len() {
        // The exact A6 case: initrd=NULL, initrd_len=0 previously passed the
        // guard and constructed a zero-length slice from a null pointer.
        assert!(validate_boot_buffers(KERNEL.as_ptr(), KERNEL.len(), std::ptr::null(), 0).is_err());
        assert!(
            validate_boot_buffers(KERNEL.as_ptr(), KERNEL.len(), std::ptr::null(), 16).is_err()
        );
    }

    #[test]
    fn zero_len_non_null_initrd_rejected() {
        // Pinned-initrd profile: empty initrd is a refusal, not an empty boot
        // (the compiled-in pins verify Some(INITRD_SHA256)).
        assert!(validate_boot_buffers(KERNEL.as_ptr(), KERNEL.len(), INITRD.as_ptr(), 0).is_err());
    }

    #[test]
    fn non_null_non_empty_buffers_accepted() {
        assert_eq!(
            validate_boot_buffers(KERNEL.as_ptr(), KERNEL.len(), INITRD.as_ptr(), INITRD.len()),
            Ok(())
        );
    }
}
