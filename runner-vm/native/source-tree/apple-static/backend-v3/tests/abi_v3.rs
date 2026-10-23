//! Full ABI v3 FFI tests on the mock platform. Proves the end-to-end device/FD
//! mechanism: five-device build, checked finalization, run-result + receipt
//! evidence, control/net FD ownership on success AND refusal, and the
//! PRIVATE-INPUT HASHING ABSENCE invariant (vde content never appears in any
//! evidence surface).

use std::ffi::CString;
use std::io::Write;

use dsmack_backend_v3::ctl_capi_v3::{
    dsmack_ctl_join_abi_version_v3, dsmack_ctl_join_err_cap_min_v3, dsmack_ctl_join_finalize_v3,
    dsmack_ctl_join_free_v3, dsmack_ctl_join_receipt_v3, dsmack_ctl_join_result_v3,
    dsmack_ctl_join_run_v3, dsmack_ctl_join_vm_new_v3, DsmackCtlDiskSetV3, DsmackCtlLaunchSpecV3,
    ERR_CAP_MIN,
};
use sha2::{Digest, Sha256};

fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}
fn write_file(p: &std::path::Path, b: &[u8]) {
    let mut f = std::fs::File::create(p).unwrap();
    f.write_all(b).unwrap();
    f.flush().unwrap();
}
fn fd_open(fd: libc::c_int) -> bool {
    let rc = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    rc != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EBADF)
}
fn connected_pair() -> (libc::c_int, libc::c_int) {
    let mut fds = [0 as libc::c_int; 2];
    assert_eq!(
        unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) },
        0
    );
    (fds[0], fds[1])
}

/// Holds every CString alive for the duration of a vm_new_v3 call.
struct SpecStrings {
    _keep: Vec<CString>,
}

struct Fixture {
    dir: std::path::PathBuf,
    kernel: Vec<u8>,
    result_content: Vec<u8>,
    private_content: Vec<u8>,
}

impl Fixture {
    fn new(tag: &str, with_private: bool) -> Self {
        let dir = std::env::temp_dir().join(format!("dsmack-v3-abi-{}-{}", tag, std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut kernel = vec![0u8; 512];
        kernel[56..60].copy_from_slice(b"ARM\x64");
        let system = vec![0x10u8; 512];
        let workload = vec![0x20u8; 1024];
        let scratch_tmpl = vec![0u8; 2048];
        let result_content = vec![0u8; 4096];
        write_file(&dir.join("system.img"), &system);
        write_file(&dir.join("workload.img"), &workload);
        write_file(&dir.join("scratch-template.img"), &scratch_tmpl);
        write_file(&dir.join("result-template.img"), &result_content);
        let private_content = vec![0x7Eu8; 8192];
        if with_private {
            write_file(&dir.join("private.img"), &private_content);
        }
        Fixture { dir, kernel, result_content, private_content }
    }
}

/// Build a fully valid spec+diskset for the fixture, returning the raw structs
/// plus the strings that must outlive the call.
fn build_raw(
    f: &Fixture,
    with_private: bool,
    system_hash_override: Option<&str>,
) -> (DsmackCtlLaunchSpecV3, DsmackCtlDiskSetV3, SpecStrings) {
    let cmdline = "console=hvc0 panic=-1";
    let system = vec![0x10u8; 512];
    let workload = vec![0x20u8; 1024];
    let scratch_tmpl = vec![0u8; 2048];
    let result_tmpl = f.result_content.clone();

    let spec_sha = c(&sha(b"admitted-spec-v3"));
    let kernel_sha = c(&sha(&f.kernel));
    let cmdline_c = c(cmdline);
    let cmdline_sha = c(&sha(cmdline.as_bytes()));
    let system_sha = c(system_hash_override.map(|s| s.to_string()).unwrap_or_else(|| sha(&system)).as_str());
    let verity = c(&sha(b"verity-root"));
    let workload_sha = c(&sha(&workload));
    let scratch_tmpl_sha = c(&sha(&scratch_tmpl));
    let result_tmpl_sha = c(&sha(&result_tmpl));

    let system_path = c(f.dir.join("system.img").to_str().unwrap());
    let scratch_tmpl_path = c(f.dir.join("scratch-template.img").to_str().unwrap());
    let scratch_path = c(f.dir.join("vdb-scratch.img").to_str().unwrap());
    let workload_path = c(f.dir.join("workload.img").to_str().unwrap());
    let result_tmpl_path = c(f.dir.join("result-template.img").to_str().unwrap());
    let result_path = c(f.dir.join("vdd-result.img").to_str().unwrap());
    let private_path = c(f.dir.join("private.img").to_str().unwrap());

    let spec = DsmackCtlLaunchSpecV3 {
        spec_sha256: spec_sha.as_ptr(),
        kernel_sha256: kernel_sha.as_ptr(),
        initrd_sha256: std::ptr::null(),
        cmdline: cmdline_c.as_ptr(),
        cmdline_sha256: cmdline_sha.as_ptr(),
        system_sha256: system_sha.as_ptr(),
        verity_root_hash: verity.as_ptr(),
        workload_sha256: workload_sha.as_ptr(),
        scratch_template_sha256: scratch_tmpl_sha.as_ptr(),
        scratch_template_bytes: 2048,
        result_template_sha256: result_tmpl_sha.as_ptr(),
        result_template_bytes: result_tmpl.len() as u64,
        ram_mib: 512,
        vcpus: 1,
    };
    let disks = DsmackCtlDiskSetV3 {
        system_path: system_path.as_ptr(),
        scratch_template_path: scratch_tmpl_path.as_ptr(),
        scratch_path: scratch_path.as_ptr(),
        workload_path: workload_path.as_ptr(),
        result_template_path: result_tmpl_path.as_ptr(),
        result_path: result_path.as_ptr(),
        private_path: if with_private { private_path.as_ptr() } else { std::ptr::null() },
    };
    let keep = vec![
        spec_sha, kernel_sha, cmdline_c, cmdline_sha, system_sha, verity, workload_sha,
        scratch_tmpl_sha, result_tmpl_sha, system_path, scratch_tmpl_path, scratch_path,
        workload_path, result_tmpl_path, result_path, private_path,
    ];
    (spec, disks, SpecStrings { _keep: keep })
}

#[test]
fn abi_version_is_three() {
    assert_eq!(dsmack_ctl_join_abi_version_v3(), 3);
    assert_eq!(dsmack_ctl_join_err_cap_min_v3(), ERR_CAP_MIN);
}

/// Full success path WITH vde: build, finalize, read result + receipt, and
/// prove the vde content hash NEVER appears in any evidence surface.
#[test]
fn full_build_finalize_private_input_never_hashed() {
    // F01: the mock is test-only; opt in explicitly before any build.
    dsmack_backend_v3::install_mock_for_test();
    let f = Fixture::new("full", true);
    let (spec, disks, _keep) = build_raw(&f, true, None);
    let console = c(f.dir.join("console.log").to_str().unwrap());
    let (ctl_a, ctl_b) = connected_pair();
    let (net_a, net_b) = connected_pair();
    let mut err = [0u8; ERR_CAP_MIN];

    // SAFETY: fully initialized fixture; valid strings/buffers; fds handed over.
    let h = unsafe {
        dsmack_ctl_join_vm_new_v3(
            f.kernel.as_ptr(),
            f.kernel.len(),
            std::ptr::null(),
            0,
            &spec,
            &disks,
            console.as_ptr(),
            ctl_b,
            net_b,
            err.as_mut_ptr(),
            err.len(),
        )
    };
    let msg = {
        let end = err.iter().position(|b| *b == 0).unwrap_or(err.len());
        String::from_utf8_lossy(&err[..end]).into_owned()
    };
    assert!(h > 0, "vm_new_v3 failed: {msg}");

    // F07: finalize is REFUSED before the lifecycle reaches a proven halt, and
    // no result may be readable before a successful finalize.
    let mut e0 = [0u8; ERR_CAP_MIN];
    let pre = unsafe { dsmack_ctl_join_finalize_v3(h, e0.as_mut_ptr(), e0.len()) };
    assert_eq!(pre, -1, "finalize before run must refuse");
    assert_eq!(
        unsafe { dsmack_ctl_join_result_v3(h, [0u8; 64].as_mut_ptr(), 64) },
        -1,
        "no result readable before a successful finalize"
    );

    // run the (mock) returning lifecycle to a halt, then finalize
    let mut rerr = [0u8; ERR_CAP_MIN];
    let rc = unsafe { dsmack_ctl_join_run_v3(h, rerr.as_mut_ptr(), rerr.len()) };
    assert_eq!(rc, 0, "mock run (quiescence) returns the halt code");

    // finalize (checked R06 over retained descriptors)
    let mut ferr = [0u8; ERR_CAP_MIN];
    let fr = unsafe { dsmack_ctl_join_finalize_v3(h, ferr.as_mut_ptr(), ferr.len()) };
    assert_eq!(fr, 0, "finalize failed");

    let mut residue = [0u8; 4096];
    assert_eq!(unsafe { dsmack_backend_v3::ctl_capi_v3::dsmack_ctl_join_residue_status_v1(h, residue.as_mut_ptr(), residue.len()) }, 0);
    let status = cbuf(&residue);
    assert!(status.contains("host cleanup deferred") && status.contains("console.log") && status.contains("vdb") && status.contains("vdd"), "{status}");
    let mut short = [0x55u8; 4];
    assert_eq!(unsafe { dsmack_backend_v3::ctl_capi_v3::dsmack_ctl_join_residue_status_v1(h, short.as_mut_ptr(), short.len()) }, -1);
    assert_eq!(short, [0x55; 4]);

    // read result + receipt
    let mut out = vec![0u8; 8192];
    assert_eq!(unsafe { dsmack_ctl_join_result_v3(h, out.as_mut_ptr(), out.len()) }, 0);
    let result_json = cbuf(&out);
    let mut rout = vec![0u8; 8192];
    assert_eq!(unsafe { dsmack_ctl_join_receipt_v3(h, rout.as_mut_ptr(), rout.len()) }, 0);
    let receipt_json = cbuf(&rout);

    // result_disk.sha256 == the fresh copy's bytes == result template content
    assert!(result_json.contains(&format!("\"sha256\":\"{}\"", sha(&f.result_content))), "{result_json}");
    assert!(result_json.contains("\"runtime_input\":{\"present\":true"), "{result_json}");
    assert!(receipt_json.contains("\"runtime_input_present\":true"), "{receipt_json}");

    // PRIVATE-INPUT HASHING ABSENCE: the vde content digest appears NOWHERE.
    let vde_hash = sha(&f.private_content);
    assert!(!result_json.contains(&vde_hash), "vde content hash leaked into run-result");
    assert!(!receipt_json.contains(&vde_hash), "vde content hash leaked into receipt");
    // and the private image's exact byte length (8192) appears in NO surface:
    // only presence, the policy cap (max_bytes), and an opaque claim may show.
    assert!(!receipt_json.contains("8192"), "vde byte length leaked into receipt");
    assert!(!result_json.contains("8192"), "vde byte length leaked into run-result");

    // teardown closes control + net exactly once
    unsafe { dsmack_ctl_join_free_v3(h) };
    assert!(!fd_open(ctl_b), "control fd must be closed once at free");
    assert!(!fd_open(net_b), "net fd must be closed once at free");
    unsafe { libc::close(ctl_a) };
    unsafe { libc::close(net_a) };
    let _ = std::fs::remove_dir_all(&f.dir);
}

/// Refusal path: a wrong vda hash refuses AFTER the control + net fds were
/// taken; both must be closed exactly once and no fresh scratch/result remain.
#[test]
fn refusal_closes_control_and_net_fds_once() {
    let f = Fixture::new("refuse", false);
    let (spec, disks, _keep) = build_raw(&f, false, Some(&"0".repeat(64)));
    let console = c(f.dir.join("console.log").to_str().unwrap());
    let (ctl_a, ctl_b) = connected_pair();
    let (net_a, net_b) = connected_pair();
    let mut err = [0u8; ERR_CAP_MIN];
    let h = unsafe {
        dsmack_ctl_join_vm_new_v3(
            f.kernel.as_ptr(),
            f.kernel.len(),
            std::ptr::null(),
            0,
            &spec,
            &disks,
            console.as_ptr(),
            ctl_b,
            net_b,
            err.as_mut_ptr(),
            err.len(),
        )
    };
    assert_eq!(h, 0, "wrong vda hash must refuse");
    assert!(!fd_open(ctl_b), "control fd closed once on refusal");
    assert!(!fd_open(net_b), "net fd closed once on refusal");
    // no fresh scratch/result left behind (fresh is per attempt)
    assert!(!f.dir.join("vdb-scratch.img").exists());
    assert!(!f.dir.join("vdd-result.img").exists());
    unsafe { libc::close(ctl_a) };
    unsafe { libc::close(net_a) };
    let _ = std::fs::remove_dir_all(&f.dir);
}

/// Invalid control fd: nothing is claimed/closed, net fd (if any) is still
/// consumed. Here with no net.
#[test]
fn invalid_control_fd_refuses() {
    let f = Fixture::new("badctl", false);
    let (spec, disks, _keep) = build_raw(&f, false, None);
    let console = c(f.dir.join("console.log").to_str().unwrap());
    let mut err = [0u8; ERR_CAP_MIN];
    let h = unsafe {
        dsmack_ctl_join_vm_new_v3(
            f.kernel.as_ptr(),
            f.kernel.len(),
            std::ptr::null(),
            0,
            &spec,
            &disks,
            console.as_ptr(),
            -1,
            -1,
            err.as_mut_ptr(),
            err.len(),
        )
    };
    assert_eq!(h, 0);
    let _ = std::fs::remove_dir_all(&f.dir);
}

/// F07: a repeated finalize (single-shot result) refuses AND invalidates the
/// previously produced result so no stale result_json remains readable.
#[test]
fn double_finalize_invalidates_result() {
    // F01: the mock is test-only; opt in explicitly before any build.
    dsmack_backend_v3::install_mock_for_test();
    let f = Fixture::new("double", false);
    let (spec, disks, _keep) = build_raw(&f, false, None);
    let console = c(f.dir.join("console.log").to_str().unwrap());
    let (ctl_a, ctl_b) = connected_pair();
    let mut err = [0u8; ERR_CAP_MIN];
    let h = unsafe {
        dsmack_ctl_join_vm_new_v3(
            f.kernel.as_ptr(), f.kernel.len(), std::ptr::null(), 0, &spec, &disks,
            console.as_ptr(), ctl_b, -1, err.as_mut_ptr(), err.len(),
        )
    };
    assert!(h > 0, "{}", cbuf(&err));
    assert_eq!(unsafe { dsmack_ctl_join_run_v3(h, err.as_mut_ptr(), err.len()) }, 0);
    // first finalize succeeds; result is readable
    assert_eq!(unsafe { dsmack_ctl_join_finalize_v3(h, err.as_mut_ptr(), err.len()) }, 0);
    let mut out = vec![0u8; 8192];
    assert_eq!(unsafe { dsmack_ctl_join_result_v3(h, out.as_mut_ptr(), out.len()) }, 0);
    // second finalize refuses (single-shot) and INVALIDATES the stored result
    assert_eq!(unsafe { dsmack_ctl_join_finalize_v3(h, err.as_mut_ptr(), err.len()) }, -1);
    assert_eq!(
        unsafe { dsmack_ctl_join_result_v3(h, out.as_mut_ptr(), out.len()) },
        -1,
        "a failed repeated finalize must leave NO readable result"
    );
    unsafe { dsmack_ctl_join_free_v3(h) };
    unsafe { libc::close(ctl_a) };
    let _ = std::fs::remove_dir_all(&f.dir);
}

/// F10: an aliased control/net descriptor (same raw fd handed as both) is
/// refused and the fd is closed exactly once (never owned — and closed — twice).
#[test]
fn aliased_control_net_fd_refused_and_closed_once() {
    let f = Fixture::new("alias", false);
    let (spec, disks, _keep) = build_raw(&f, false, None);
    let console = c(f.dir.join("console.log").to_str().unwrap());
    let (ctl_a, ctl_b) = connected_pair();
    let mut err = [0u8; ERR_CAP_MIN];
    let h = unsafe {
        dsmack_ctl_join_vm_new_v3(
            f.kernel.as_ptr(), f.kernel.len(), std::ptr::null(), 0, &spec, &disks,
            console.as_ptr(), ctl_b, ctl_b /* SAME fd */, err.as_mut_ptr(), err.len(),
        )
    };
    assert_eq!(h, 0, "aliased control/net must refuse");
    assert!(cbuf(&err).contains("distinct"), "{}", cbuf(&err));
    assert!(!fd_open(ctl_b), "aliased fd must be closed exactly once");
    // no fresh scratch/result/console remain (console attempt-owned cleanup)
    assert!(!f.dir.join("vdb-scratch.img").exists());
    assert!(!f.dir.join("vdd-result.img").exists());
    assert!(!f.dir.join("console.log").exists());
    unsafe { libc::close(ctl_a) };
    let _ = std::fs::remove_dir_all(&f.dir);
}

/// F10: a control fd that is not a socket/pipe transport (a regular file) is
/// refused; its descriptor is closed exactly once.
#[test]
fn non_transport_control_fd_refused() {
    let f = Fixture::new("ctltype", false);
    let (spec, disks, _keep) = build_raw(&f, false, None);
    let console = c(f.dir.join("console.log").to_str().unwrap());
    let reg = f.dir.join("regular-ctl");
    write_file(&reg, b"not a socket");
    let rf = std::fs::OpenOptions::new().read(true).open(&reg).unwrap();
    use std::os::fd::IntoRawFd;
    let raw = rf.into_raw_fd();
    let mut err = [0u8; ERR_CAP_MIN];
    let h = unsafe {
        dsmack_ctl_join_vm_new_v3(
            f.kernel.as_ptr(), f.kernel.len(), std::ptr::null(), 0, &spec, &disks,
            console.as_ptr(), raw, -1, err.as_mut_ptr(), err.len(),
        )
    };
    assert_eq!(h, 0, "regular-file control fd must refuse");
    assert!(cbuf(&err).contains("transport"), "{}", cbuf(&err));
    assert!(!fd_open(raw), "refused control fd closed exactly once");
    assert!(!f.dir.join("console.log").exists(), "console cleaned on refusal");
    let _ = std::fs::remove_dir_all(&f.dir);
}

fn cbuf(buf: &[u8]) -> String {
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

#[test]
fn residue_free_policy_refuses_before_any_output_or_launch() {
    use dsmack_backend_v3::ctl_capi_v3::dsmack_ctl_join_vm_new_with_policy_v1;
    for policy in [1, 99] {
        let (a, b) = connected_pair();
        let mut err = [0u8; ERR_CAP_MIN];
        // Null inputs deliberately prove policy refusal precedes preparation.
        let h = unsafe { dsmack_ctl_join_vm_new_with_policy_v1(
            std::ptr::null(), 0, std::ptr::null(), 0, std::ptr::null(),
            std::ptr::null(), std::ptr::null(), b, -1, policy,
            err.as_mut_ptr(), err.len()) };
        assert_eq!(h, 0);
        assert!(cbuf(&err).contains("residue policy refused before launch"));
        assert!(!fd_open(b));
        unsafe { libc::close(a); }
    }
}
