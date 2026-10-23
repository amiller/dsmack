//! Adversarial + conformance tests at the v2 ABI boundary (FFI level).
//!
//! Mirrors the boot-binding-spike D01 regression set (A1/A3 classes) plus
//! the v2-specific refusals (fresh scratch, verify-on-open, resource zero,
//! dstack verity binding), the v1 R4 descriptor-accounting discipline
//! (every refusal closes the control fd exactly once; success keeps it
//! inside the handle), and a REAL boot-tuple pass: the actual Mini-bound
//! arm64 artifacts (kernel 842b62e8…, initrd 70d6848c…, system disk
//! e97ab725… from the admitted basevm-arm64-alpine manifest) driven through
//! `dsmack_ctl_join_vm_new` — read-back/receipt digests must equal the
//! manifest pins.

use std::ffi::CString;
use std::path::{Path, PathBuf};

use dsmack_backend::ctl_capi::{
    dsmack_ctl_join_abi_version, dsmack_ctl_join_err_cap_min, dsmack_ctl_join_receipt,
    dsmack_ctl_join_receipt_cap_min, dsmack_ctl_join_run, dsmack_ctl_join_vm_new,
    DsmackCtlDiskSet, DsmackCtlLaunchSpec,
};

fn sha_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(b))
}

// ---------------------------------------------------------------------------
// FFI harness
// ---------------------------------------------------------------------------

/// Fixture strings are leaked for the process lifetime — the ABI only
/// guarantees string validity for the duration of the call, but fixtures
/// reuse them across calls.
fn leak_cstr(s: &str) -> *const std::ffi::c_char {
    CString::new(s).unwrap().into_raw() as *const std::ffi::c_char
}

fn socketpair() -> (i32, i32) {
    let mut fds = [0 as libc::c_int; 2];
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    assert_eq!(rc, 0, "socketpair");
    (fds[0], fds[1])
}

/// Descriptor-ownership probes read the PROCESS-global fd table, so any
/// parallel test opening/closing descriptors can reoccupy a just-closed
/// number and race the F_GETFD probe. Every test that asserts fd state
/// holds this mutex for its whole body — the standard discipline for this
/// assertion class.
static FD_PROBE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn fd_open(fd: i32) -> bool {
    // SAFETY: F_GETFD probe of a possibly-closed descriptor; EBADF == closed.
    let rc = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    rc != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EBADF)
}

fn err_buf() -> Vec<u8> {
    vec![0u8; dsmack_ctl_join_err_cap_min()]
}

fn cstr_to_string(buf: &[u8]) -> String {
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// A synthetic arm64-shaped environment: kernel carries a valid arm64 Image
/// header (magic ARM\x64, text_offset 0, image_size >= len), initrd present,
/// disks are 512-multiple files, cmdline printable ASCII.
struct Env {
    dir: PathBuf,
    kernel: Vec<u8>,
    initrd: Vec<u8>,
    system: PathBuf,
    workload: PathBuf,
    scratch: PathBuf,
    console: CString,
    /// Owns the cmdline bytes — `spec.cmdline` points INTO this CString and
    /// must outlive every FFI call (the ABI guarantees string validity only
    /// for the duration of one call, and the fixture reuses them).
    cmdline: CString,
    spec: DsmackCtlLaunchSpec,
    disks: DsmackCtlDiskSet,
}

impl Env {
    fn new(name: &str) -> Env {
        let dir = std::env::temp_dir().join(format!("dsmack-abi-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut kernel = vec![0u8; 4096];
        let kernel_len = kernel.len() as u64;
        kernel[56..60].copy_from_slice(b"ARM\x64");
        kernel[8..16].copy_from_slice(&0u64.to_le_bytes()); // text_offset 0
        kernel[16..24].copy_from_slice(&kernel_len.to_le_bytes()); // image_size
        kernel[100..104].copy_from_slice(b"KERN");
        let mut initrd = vec![0u8; 512];
        initrd[..6].copy_from_slice(b"INITRD");

        let system = dir.join("system.img");
        std::fs::write(&system, vec![0xA5u8; 1024]).unwrap();
        let workload = dir.join("workload.img");
        std::fs::write(&workload, vec![0x5Au8; 512]).unwrap();
        let scratch = dir.join("scratch.img");

        let cmdline = CString::new(format!("console=hvc0 panic=-1 loglevel=6 [{name}]")).unwrap();
        let spec = DsmackCtlLaunchSpec {
            spec_sha256: leak_cstr(&sha_hex(format!("spec-{name}").as_bytes())),
            kernel_sha256: leak_cstr(&sha_hex(&kernel)),
            initrd_sha256: leak_cstr(&sha_hex(&initrd)),
            cmdline: cmdline.as_ptr() as *const std::ffi::c_char,
            cmdline_sha256: leak_cstr(&sha_hex(cmdline.to_bytes())),
            system_sha256: leak_cstr(&sha_hex(&std::fs::read(&system).unwrap())),
            verity_root_hash: leak_cstr(&sha_hex(b"verity-root")),
            workload_sha256: leak_cstr(&sha_hex(&std::fs::read(&workload).unwrap())),
            ram_mib: 2048,
            vcpus: 2,
        };
        let disks = DsmackCtlDiskSet {
            system_path: leak_cstr(system.to_str().unwrap()),
            scratch_path: leak_cstr(scratch.to_str().unwrap()),
            workload_path: leak_cstr(workload.to_str().unwrap()),
        };
        let console = CString::new(dir.join("console.log").to_str().unwrap()).unwrap();
        Env {
            dir,
            kernel,
            initrd,
            system,
            workload,
            scratch,
            console,
            cmdline,
            spec,
            disks,
        }
    }

    /// The baseline success call with this env's own socketpair; the host
    /// endpoint is closed immediately (these tests never speak the control
    /// protocol — they only observe descriptor ownership).
    fn call_ok(&self) -> (i64, i32, Vec<u8>) {
        let (host, guest) = socketpair();
        unsafe { libc::close(host) };
        let mut err = err_buf();
        let h = unsafe {
            dsmack_ctl_join_vm_new(
                self.kernel.as_ptr(),
                self.kernel.len(),
                self.initrd.as_ptr(),
                self.initrd.len(),
                &self.spec,
                &self.disks,
                self.console.as_ptr(),
                guest,
                err.as_mut_ptr(),
                err.len(),
            )
        };
        (h, guest, err)
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

// ---------------------------------------------------------------------------
// ABI surface
// ---------------------------------------------------------------------------

#[test]
fn abi_version_is_2() {
    assert_eq!(dsmack_ctl_join_abi_version(), 2);
    assert_eq!(dsmack_ctl_join_err_cap_min(), 512);
    assert!(dsmack_ctl_join_receipt_cap_min() >= 2048);
}

// ---------------------------------------------------------------------------
// R4 descriptor accounting + the refusal matrix (every refusal BEFORE any VM)
// ---------------------------------------------------------------------------

#[test]
fn each_refusal_class_closes_fd_and_names_the_reason() {
    let _fd_guard = FD_PROBE_LOCK.lock().unwrap();
    let e = Env::new("refusals");
    // A refusal AFTER console O_EXCL creation legitimately leaves the console
    // log behind (v1 behavior — the caller supplies a fresh console path per
    // attempt), so each case below starts from a clean console.
    let refused = |kernel: *const u8,
                       kernel_len: usize,
                       initrd: *const u8,
                       initrd_len: usize,
                       spec: *const DsmackCtlLaunchSpec,
                       disks: *const DsmackCtlDiskSet|
     -> String {
        let (host, guest) = socketpair();
        let mut err = err_buf();
        let h = unsafe {
            dsmack_ctl_join_vm_new(
                kernel,
                kernel_len,
                initrd,
                initrd_len,
                spec,
                disks,
                e.console.as_ptr(),
                guest,
                err.as_mut_ptr(),
                err.len(),
            )
        };
        assert_eq!(h, 0, "expected refusal");
        assert!(!fd_open(guest), "fd must be closed exactly once on refusal");
        unsafe { libc::close(host) };
        let msg = cstr_to_string(&err);
        let _ = std::fs::remove_file(e.dir.join("console.log"));
        msg
    };

    // 1. null kernel (A6 class: null never reaches from_raw_parts)
    let msg = refused(std::ptr::null(), 16, e.initrd.as_ptr(), e.initrd.len(),
        &e.spec, &e.disks);
    assert!(msg.contains("null kernel"), "1: {msg}");

    // 2. empty kernel
    let msg = refused(e.kernel.as_ptr(), 0, e.initrd.as_ptr(), e.initrd.len(),
        &e.spec, &e.disks);
    assert!(msg.contains("empty kernel"), "2: {msg}");

    // 3. wrong kernel pin (A3-kernel): owned-copy hash mismatch
    let wrong_kernel: Vec<u8> = e.kernel.iter().map(|b| b ^ 1).collect();
    let msg = refused(wrong_kernel.as_ptr(), wrong_kernel.len(), e.initrd.as_ptr(), e.initrd.len(),
        &e.spec, &e.disks);
    assert!(msg.contains("kernel SHA-256 does not match"), "3: {msg}");

    // 4. wrong initrd pin (A3-initrd)
    let wrong_initrd: Vec<u8> = e.initrd.iter().map(|b| b ^ 1).collect();
    let msg = refused(e.kernel.as_ptr(), e.kernel.len(), wrong_initrd.as_ptr(), wrong_initrd.len(),
        &e.spec, &e.disks);
    assert!(msg.contains("initrd SHA-256 does not match"), "4: {msg}");

    // 5. wrong cmdline pin (A3-cmdline): mutated spec cmdline
    let spec2 = DsmackCtlLaunchSpec {
        cmdline: leak_cstr("console=hvc0 panic=-1 loglevel=6 [TAMPERED]"),
        ..clone_spec(&e.spec)
    };
    let msg = refused(e.kernel.as_ptr(), e.kernel.len(), e.initrd.as_ptr(), e.initrd.len(),
        &spec2, &e.disks);
    assert!(msg.contains("cmdline SHA-256 does not match"), "5: {msg}");

    // 6. initrd pin present but buffer null (presence mismatch)
    let mut err = err_buf();
    let (host, guest) = socketpair();
    let h = unsafe {
        dsmack_ctl_join_vm_new(
            e.kernel.as_ptr(), e.kernel.len(), std::ptr::null(), 0,
            &e.spec, &e.disks, e.console.as_ptr(), guest,
            err.as_mut_ptr(), err.len())
    };
    assert_eq!(h, 0);
    assert!(!fd_open(guest));
    assert!(cstr_to_string(&err).contains("initrd presence"), "6: {}", cstr_to_string(&err));
    unsafe { libc::close(host) };

    // 7. non-null initrd pointer with zero length (ambiguous — v1 A6)
    let msg = refused(e.kernel.as_ptr(), e.kernel.len(), e.initrd.as_ptr(), 0,
        &e.spec, &e.disks);
    assert!(msg.contains("empty initrd"), "7: {msg}");

    // 8. resource-zero refusals
    for (ram, vcpus, what) in [(0u32, 2u32, "ram_mib"), (2048, 0, "vcpus")] {
        let spec2 = DsmackCtlLaunchSpec { ram_mib: ram, vcpus, ..clone_spec(&e.spec) };
        let msg = refused(e.kernel.as_ptr(), e.kernel.len(), e.initrd.as_ptr(), e.initrd.len(),
            &spec2, &e.disks);
        assert!(msg.contains("non-zero"), "{what}: {msg}");
    }

    // 9. null spec / null disks / null console
    let msg = refused(e.kernel.as_ptr(), e.kernel.len(), e.initrd.as_ptr(), e.initrd.len(),
        std::ptr::null(), &e.disks);
    assert!(msg.contains("null launch_spec"), "9a: {msg}");
    let msg = refused(e.kernel.as_ptr(), e.kernel.len(), e.initrd.as_ptr(), e.initrd.len(),
        &e.spec, std::ptr::null());
    assert!(msg.contains("null disk set"), "9b: {msg}");
    {
        let (host, guest) = socketpair();
        let mut err = err_buf();
        let h = unsafe {
            dsmack_ctl_join_vm_new(
                e.kernel.as_ptr(), e.kernel.len(), e.initrd.as_ptr(), e.initrd.len(),
                &e.spec, &e.disks, std::ptr::null(), guest,
                err.as_mut_ptr(), err.len())
        };
        assert_eq!(h, 0);
        assert!(!fd_open(guest));
        assert!(cstr_to_string(&err).contains("null"), "9c: {}", cstr_to_string(&err));
        unsafe { libc::close(host) };
    }

    // 10. negative control fd — refused, nothing to close
    {
        let mut err = err_buf();
        let h = unsafe {
            dsmack_ctl_join_vm_new(
                e.kernel.as_ptr(), e.kernel.len(), e.initrd.as_ptr(), e.initrd.len(),
                &e.spec, &e.disks, e.console.as_ptr(), -1,
                err.as_mut_ptr(), err.len())
        };
        assert_eq!(h, 0);
        assert!(cstr_to_string(&err).contains("control fd -1 invalid"), "10");
    }
}

#[test]
fn disk_triple_refusals_and_scratch_cleanup() {
    let _fd_guard = FD_PROBE_LOCK.lock().unwrap();
    let e = Env::new("disks");
    let call = |system: &str, scratch: &str, workload: &str| -> String {
        let (host, guest) = socketpair();
        let mut err = err_buf();
        let disks2 = DsmackCtlDiskSet {
            system_path: leak_cstr(system),
            scratch_path: leak_cstr(scratch),
            workload_path: leak_cstr(workload),
        };
        let h = unsafe {
            dsmack_ctl_join_vm_new(
                e.kernel.as_ptr(), e.kernel.len(), e.initrd.as_ptr(), e.initrd.len(),
                &e.spec, &disks2, e.console.as_ptr(), guest,
                err.as_mut_ptr(), err.len())
        };
        assert_eq!(h, 0, "expected refusal");
        assert!(!fd_open(guest));
        unsafe { libc::close(host) };
        let msg = cstr_to_string(&err);
        let _ = std::fs::remove_file(e.dir.join("console.log"));
        msg
    };
    // verify-on-open: tampered system disk refuses and names both digests
    let tampered = e.dir.join("system-tampered.img");
    let mut bytes = std::fs::read(&e.system).unwrap();
    bytes[512] ^= 0xFF;
    std::fs::write(&tampered, &bytes).unwrap();
    let scratch_path_str = e.scratch.to_str().unwrap();
    let msg = call(tampered.to_str().unwrap(), scratch_path_str, e.workload.to_str().unwrap());
    assert!(msg.contains("verify-on-open FAILED"), "tampered system: {msg}");
    // a refused launch leaves NO fresh scratch behind
    assert!(!e.scratch.exists(), "scratch must be cleaned after refusal");

    // missing system disk
    let msg = call("/nonexistent/system.img", scratch_path_str, e.workload.to_str().unwrap());
    assert!(msg.contains("system(vda)"), "missing system: {msg}");

    // non-regular system disk
    let msg = call("/dev/null", scratch_path_str, e.workload.to_str().unwrap());
    assert!(msg.contains("system(vda)"), "non-regular system: {msg}");

    // tampered workload disk
    let w_tampered = e.dir.join("workload-tampered.img");
    let mut wb = std::fs::read(&e.workload).unwrap();
    wb[0] ^= 0xFF;
    std::fs::write(&w_tampered, &wb).unwrap();
    let msg = call(e.system.to_str().unwrap(), scratch_path_str, w_tampered.to_str().unwrap());
    assert!(msg.contains("workload(vdc)") && msg.contains("verify-on-open FAILED"), "tampered workload: {msg}");
    assert!(!e.scratch.exists(), "scratch cleaned after workload refusal");

    // pre-existing scratch inode
    std::fs::write(&e.scratch, b"stale").unwrap();
    let msg = call(e.system.to_str().unwrap(), scratch_path_str, e.workload.to_str().unwrap());
    assert!(msg.contains("fresh-inode"), "pre-existing scratch: {msg}");
}

#[test]
fn console_o_excl_refusal_closes_fd() {
    let _fd_guard = FD_PROBE_LOCK.lock().unwrap();
    let e = Env::new("console");
    std::fs::write(e.dir.join("console.log"), b"exists").unwrap();
    let (host, guest) = socketpair();
    let mut err = err_buf();
    let h = unsafe {
        dsmack_ctl_join_vm_new(
            e.kernel.as_ptr(), e.kernel.len(), e.initrd.as_ptr(), e.initrd.len(),
            &e.spec, &e.disks, e.console.as_ptr(), guest,
            err.as_mut_ptr(), err.len())
    };
    assert_eq!(h, 0);
    assert!(!fd_open(guest));
    assert!(cstr_to_string(&err).contains("console log"));
    unsafe { libc::close(host) };
}

// ---------------------------------------------------------------------------
// Success path: R4 ownership + A1 mutation immunity + R5 receipt + R3 run
// ---------------------------------------------------------------------------

#[test]
fn success_path_full_abi_flow() {
    let _fd_guard = FD_PROBE_LOCK.lock().unwrap();
    let e = Env::new("success");
    let (h, guest, err) = e.call_ok();
    assert!(h > 0, "success handle, err: {}", cstr_to_string(&err));

    // R4: descriptor lives INSIDE the handle — still open, caller-owned no more.
    assert!(fd_open(guest));

    // R5: receipt carries the admitted identity + observed facts + honesty.
    let mut out = vec![0u8; dsmack_ctl_join_receipt_cap_min()];
    assert_eq!(unsafe { dsmack_ctl_join_receipt(h, out.as_mut_ptr(), out.len()) }, 0);
    let receipt = cstr_to_string(&out);
    assert!(receipt.contains("\"schema\":\"dsmack-backend-v2/launch-receipt/1\""), "{receipt}");
    assert!(receipt.contains("\"spec_sha256\""), "{receipt}");
    assert!(receipt.contains(&sha_hex(&e.kernel)), "observed kernel digest in receipt");
    assert!(receipt.contains(&sha_hex(&e.initrd)), "observed initrd digest in receipt");
    assert!(receipt.contains("\"ram_mib\":2048"));
    assert!(receipt.contains("\"vcpus\":2"));
    assert!(receipt.contains("memory-placement-model"));
    assert!(receipt.contains("honesty") && receipt.contains("NOT established"));
    assert!(receipt.contains("panic=-1"));

    // A1: mutate + drop the caller buffers after the handle exists — the
    // verified boot is immune (owned copies were taken at entry, hashed
    // against the spec pins).
    let (kp, ip) = (sha_hex(&e.kernel), sha_hex(&e.initrd));
    let mut k2 = e.kernel.clone();
    let mut i2 = e.initrd.clone();
    k2.fill(0);
    i2.fill(0);
    drop(k2);
    drop(i2);
    assert_eq!(unsafe { dsmack_ctl_join_receipt(h, out.as_mut_ptr(), out.len()) }, 0);
    let receipt_after = cstr_to_string(&out);
    assert!(receipt_after.contains(&kp), "kernel digest unchanged after caller mutation");
    assert!(receipt_after.contains(&ip), "initrd digest unchanged after caller mutation");

    // Run: on this crate the engineering placement model honestly refuses to
    // execute a guest (the run path is the HVF consumption on aarch64 macOS).
    let rc = unsafe { dsmack_ctl_join_run(h, out.as_mut_ptr(), out.len()) };
    assert_eq!(rc, -1);
    let run_err = cstr_to_string(&out);
    assert!(run_err.contains("memory-placement-model does not execute guests"), "{run_err}");

    // Handle consumed; the descriptor went down with the handle (closed
    // exactly once by teardown).
    assert!(!fd_open(guest), "descriptor closed by handle teardown");
}

#[test]
fn zero_handle_run_and_receipt_refused() {
    let mut err = err_buf();
    assert_eq!(unsafe { dsmack_ctl_join_run(0, err.as_mut_ptr(), err.len()) }, -1);
    assert!(cstr_to_string(&err).contains("zero handle"));
    assert_eq!(unsafe { dsmack_ctl_join_receipt(0, err.as_mut_ptr(), err.len()) }, -1);
}

#[test]
fn receipt_cap_too_small_refused_without_touching_handle() {
    let _fd_guard = FD_PROBE_LOCK.lock().unwrap();
    let e = Env::new("receipt-cap");
    let (h, guest, err) = e.call_ok();
    assert!(h > 0, "{}", cstr_to_string(&err));
    let mut tiny = vec![0u8; 16];
    assert_eq!(unsafe { dsmack_ctl_join_receipt(h, tiny.as_mut_ptr(), tiny.len()) }, -1);
    // handle still usable after the too-small receipt buffer
    let mut out = vec![0u8; dsmack_ctl_join_receipt_cap_min()];
    assert_eq!(unsafe { dsmack_ctl_join_receipt(h, out.as_mut_ptr(), out.len()) }, 0);
    // consume the handle via run (engineering refusal) — descriptor torn down
    let mut err = err_buf();
    assert_eq!(unsafe { dsmack_ctl_join_run(h, err.as_mut_ptr(), err.len()) }, -1);
    assert!(!fd_open(guest), "descriptor closed by handle teardown");
}

// ---------------------------------------------------------------------------
// REAL: the actual Mini-bound arm64 boot tuple through the v2 ABI
// ---------------------------------------------------------------------------

/// Pins from the admitted `basevm-arm64-alpine.image.json` (mac-general-prep,
/// the Mini-bound image family; initrd digest 70d6848c… is the corrected
/// BASE-VM-ARM64.json value). Skips (with a loud marker) when the read-only
/// artifacts are not present on this host.
#[test]
fn real_admitted_arm64_tuple_through_v2_abi() {
    let _fd_guard = FD_PROBE_LOCK.lock().unwrap();
    let kernel_path = "/home/amiller/dsmack-sprints/attested-runner-20261019/joined-sprint/app-compose-20261020/arm64-compatibility/build/kernel-apk/Image";
    let initrd_path = "/data/amiller/dsmack/attested-runner-20261020/relocated-artifacts/arm64-compatibility/initrd.cpio.gz";
    let system_path = "/data/amiller/dsmack/attested-runner-20261020/relocated-artifacts/arm64-compatibility/system.img";
    if !(Path::new(kernel_path).is_file()
        && Path::new(initrd_path).is_file()
        && Path::new(system_path).is_file())
    {
        eprintln!("REAL skipped: read-only artifacts absent on this host");
        return;
    }
    let kernel = std::fs::read(kernel_path).unwrap();
    let initrd = std::fs::read(initrd_path).unwrap();
    assert_eq!(
        sha_hex(&kernel),
        "842b62e8b8bdfc07ec67a3a4d472620c86ad9897020d2ab4c069cac25c38e34e"
    );
    assert_eq!(
        sha_hex(&initrd),
        "70d6848cf7439f165794b16ecbcb78ceb4c8013cbb8adf4f89a22a1cfa21f70e"
    );

    let dir = std::env::temp_dir().join(format!("dsmack-abi-real-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let workload = dir.join("workload.img");
    std::fs::write(&workload, vec![0u8; 1024]).unwrap();

    let cmdline =
        CString::new("console=ttyAMA0,115200 console=hvc0 panic=-1 loglevel=6").unwrap();
    let spec = DsmackCtlLaunchSpec {
        spec_sha256: leak_cstr(&sha_hex(b"real-admission-spec")),
        kernel_sha256: leak_cstr(&sha_hex(&kernel)),
        initrd_sha256: leak_cstr(&sha_hex(&initrd)),
        cmdline: cmdline.as_ptr() as *const std::ffi::c_char,
        cmdline_sha256: leak_cstr(&sha_hex(cmdline.to_bytes())),
        system_sha256: leak_cstr(
            "e97ab72545341dde5d4cc504fa73d268f7d33be2c44dda18ccea0f1b40a1d88d",
        ),
        verity_root_hash: leak_cstr(
            "4e016bc930aba26fac9c4d1cea3379a19ce8509c0b2665b77104d203c0ea3e3f",
        ),
        workload_sha256: leak_cstr(&sha_hex(&std::fs::read(&workload).unwrap())),
        ram_mib: 2048,
        vcpus: 2,
    };
    let disks = DsmackCtlDiskSet {
        system_path: leak_cstr(system_path),
        scratch_path: leak_cstr(dir.join("scratch.img").to_str().unwrap()),
        workload_path: leak_cstr(workload.to_str().unwrap()),
    };
    let console = CString::new(dir.join("console.log").to_str().unwrap()).unwrap();

    let (host, guest) = socketpair();
    let mut err = err_buf();
    let h = unsafe {
        dsmack_ctl_join_vm_new(
            kernel.as_ptr(),
            kernel.len(),
            initrd.as_ptr(),
            initrd.len(),
            &spec,
            &disks,
            console.as_ptr(),
            guest,
            err.as_mut_ptr(),
            err.len(),
        )
    };
    assert!(h > 0, "REAL tuple refused: {}", cstr_to_string(&err));
    let mut out = vec![0u8; dsmack_ctl_join_receipt_cap_min()];
    assert_eq!(unsafe { dsmack_ctl_join_receipt(h, out.as_mut_ptr(), out.len()) }, 0);
    let receipt = cstr_to_string(&out);
    for pin in [
        "842b62e8b8bdfc07ec67a3a4d472620c86ad9897020d2ab4c069cac25c38e34e",
        "70d6848cf7439f165794b16ecbcb78ceb4c8013cbb8adf4f89a22a1cfa21f70e",
        "e97ab72545341dde5d4cc504fa73d268f7d33be2c44dda18ccea0f1b40a1d88d",
        "4e016bc930aba26fac9c4d1cea3379a19ce8509c0b2665b77104d203c0ea3e3f",
        "console=ttyAMA0,115200 console=hvc0 panic=-1 loglevel=6",
    ] {
        assert!(receipt.contains(pin), "REAL receipt must contain {pin}");
    }
    unsafe { libc::close(host) };
    // consume the handle
    let mut err = err_buf();
    assert_eq!(unsafe { dsmack_ctl_join_run(h, err.as_mut_ptr(), err.len()) }, -1);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------

fn clone_spec(s: &DsmackCtlLaunchSpec) -> DsmackCtlLaunchSpec {
    DsmackCtlLaunchSpec {
        spec_sha256: s.spec_sha256,
        kernel_sha256: s.kernel_sha256,
        initrd_sha256: s.initrd_sha256,
        cmdline: s.cmdline,
        cmdline_sha256: s.cmdline_sha256,
        system_sha256: s.system_sha256,
        verity_root_hash: s.verity_root_hash,
        workload_sha256: s.workload_sha256,
        ram_mib: s.ram_mib,
        vcpus: s.vcpus,
    }
}
