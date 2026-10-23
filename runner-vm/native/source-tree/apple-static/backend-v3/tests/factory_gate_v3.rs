//! F01 — fail-closed native-factory gate. This test binary NEVER installs a
//! consumption factory (no `dsmack_ctl_v3_init`, no `install_mock_for_test`), so
//! the one-way FACTORY stays uninstalled for the whole process. It proves that
//! `dsmack_ctl_join_vm_new_v3` REFUSES to create a VM when no native factory is
//! present — i.e. the mock is NOT a production fallback and VM creation before
//! initialization fails closed. It also proves the refusal still closes the
//! handed control/net descriptors exactly once and removes only the fresh
//! inodes this attempt created (the console), never the base templates.
//!
//! Kept in its own integration binary ON PURPOSE: the mock-driven abi_v3 tests
//! install the mock process-globally, which would mask this gate if they shared
//! a process.

use std::ffi::CString;
use std::io::Write;

use dsmack_backend_v3::ctl_capi_v3::{
    dsmack_ctl_join_vm_new_v3, DsmackCtlDiskSetV3, DsmackCtlLaunchSpecV3, ERR_CAP_MIN,
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
fn cbuf(buf: &[u8]) -> String {
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// Build a fully valid spec+diskset in `dir`. Mirrors the abi_v3 fixture so the
/// refusal is attributable ONLY to the missing factory, not to bad inputs.
fn valid_inputs(
    dir: &std::path::Path,
) -> (
    Vec<u8>,
    DsmackCtlLaunchSpecV3,
    DsmackCtlDiskSetV3,
    Vec<CString>,
) {
    std::fs::create_dir_all(dir).unwrap();
    let mut kernel = vec![0u8; 512];
    kernel[56..60].copy_from_slice(b"ARM\x64");
    let system = vec![0x10u8; 512];
    let workload = vec![0x20u8; 1024];
    let scratch_tmpl = vec![0u8; 2048];
    let result_tmpl = vec![0u8; 4096];
    write_file(&dir.join("system.img"), &system);
    write_file(&dir.join("workload.img"), &workload);
    write_file(&dir.join("scratch-template.img"), &scratch_tmpl);
    write_file(&dir.join("result-template.img"), &result_tmpl);

    let cmdline = "console=hvc0 panic=-1";
    let spec_sha = c(&sha(b"admitted-spec-v3"));
    let kernel_sha = c(&sha(&kernel));
    let cmdline_c = c(cmdline);
    let cmdline_sha = c(&sha(cmdline.as_bytes()));
    let system_sha = c(&sha(&system));
    let verity = c(&sha(b"verity-root"));
    let workload_sha = c(&sha(&workload));
    let scratch_tmpl_sha = c(&sha(&scratch_tmpl));
    let result_tmpl_sha = c(&sha(&result_tmpl));
    let system_path = c(dir.join("system.img").to_str().unwrap());
    let scratch_tmpl_path = c(dir.join("scratch-template.img").to_str().unwrap());
    let scratch_path = c(dir.join("vdb-scratch.img").to_str().unwrap());
    let workload_path = c(dir.join("workload.img").to_str().unwrap());
    let result_tmpl_path = c(dir.join("result-template.img").to_str().unwrap());
    let result_path = c(dir.join("vdd-result.img").to_str().unwrap());

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
        private_path: std::ptr::null(),
    };
    let keep = vec![
        spec_sha,
        kernel_sha,
        cmdline_c,
        cmdline_sha,
        system_sha,
        verity,
        workload_sha,
        scratch_tmpl_sha,
        result_tmpl_sha,
        system_path,
        scratch_tmpl_path,
        scratch_path,
        workload_path,
        result_tmpl_path,
        result_path,
    ];
    (kernel, spec, disks, keep)
}

/// With valid inputs but NO factory installed, vm_new_v3 must refuse with the
/// fail-closed message, closing the handed control + net fds exactly once and
/// removing the fresh console it created — without touching the base templates.
#[test]
fn vm_creation_refused_without_native_factory() {
    let dir = std::env::temp_dir().join(format!("dsmack-v3-gate-{}", std::process::id()));
    let (kernel, spec, disks, _keep) = valid_inputs(&dir);
    let console = c(dir.join("console.log").to_str().unwrap());
    let (ctl_a, ctl_b) = connected_pair();
    let (net_a, net_b) = connected_pair();
    let mut err = [0u8; ERR_CAP_MIN];

    // SAFETY: fully initialized fixture; valid strings/buffers; fds handed over.
    let h = unsafe {
        dsmack_ctl_join_vm_new_v3(
            kernel.as_ptr(),
            kernel.len(),
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
    let msg = cbuf(&err);
    assert_eq!(
        h, 0,
        "VM creation must FAIL CLOSED without a native factory"
    );
    assert!(
        msg.contains("no native consumption factory installed"),
        "refusal must name the missing factory, got: {msg}"
    );
    // control + net closed exactly once on this refusal
    assert!(
        !fd_open(ctl_b),
        "control fd must be closed once on factory refusal"
    );
    assert!(
        !fd_open(net_b),
        "net fd must be closed once on factory refusal"
    );
    assert!(msg.contains("host cleanup deferred"), "{msg}");
    // Fresh inodes and templates remain; FD closure remains mandatory.
    assert!(
        dir.join("console.log").exists(),
        "fresh console retained with deferred cleanup"
    );
    assert!(
        dir.join("vdb-scratch.img").exists(),
        "fresh scratch retained with deferred cleanup"
    );
    assert!(
        dir.join("vdd-result.img").exists(),
        "fresh result retained with deferred cleanup"
    );
    assert!(dir.join("system.img").exists(), "base template preserved");
    assert!(
        dir.join("result-template.img").exists(),
        "base template preserved"
    );

    unsafe { libc::close(ctl_a) };
    unsafe { libc::close(net_a) };
    let _ = std::fs::remove_dir_all(&dir);
}
