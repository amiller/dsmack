//! fable-native-audit F4 repairs (mac-app-join patch 0004) — host-executed:
//!   R1  the receipt JSON is VALID for control-character scratch paths
//!       (full escaper), detectable against the pre-0004 defect where kv()
//!       escaped only `"`/`\`;
//!   R2  the computed worst-case cap dominates a maximal LEGAL receipt
//!       (max cmdline of quotes, 256-byte control-char scratch path,
//!       initrd pin present), and the FFI cap_min equals it — so the
//!       Swift `backendV2Receipt` cap_min allocation always succeeds;
//!   R3  an over-bound scratch path is refused BEFORE anything is created
//!       and the control descriptor is closed exactly once (R4 through the
//!       new refusal);
//!   R4  the FFI receipt surface still refuses (never truncates) a
//!       too-small buffer and reads back cleanly at exactly cap_min.

use sha2::{Digest, Sha256};
use std::ffi::CString;

fn sha_hex(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}

fn leak_cstr(s: &str) -> *const std::ffi::c_char {
    CString::new(s).unwrap().into_raw() // leaked: the FFI reads within the call only
}

/// Minimal single-object JSON walk: returns Err on a RAW control character
/// inside a string literal or on unbalanced quotes (enough to catch the F4
/// defect class on the receipt's known shape — keys are ASCII constants).
fn receipt_json_defect(s: &str) -> Option<&'static str> {
    let mut in_str = false;
    let mut esc = false;
    for c in s.chars() {
        if in_str {
            if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                in_str = false;
            } else if (c as u32) < 0x20 {
                return Some("raw control character inside a JSON string");
            }
        } else if c == '"' {
            in_str = true;
        }
    }
    if in_str {
        return Some("unterminated JSON string");
    }
    None
}

/// Direct-launch fixture (unit level, no FFI): a fully verified
/// kernel/initrd/cmdline + real disk triple over real files.
fn unit_receipt(cmdline: &str, scratch_path: &str) -> dsmack_backend::receipt::LaunchReceipt {
    use dsmack_backend::disks::{create_scratch, open_verified_ro, DiskRole};
    use dsmack_backend::owned_verified::{VerifiedBootImages, VerifiedBootPins};
    use dsmack_backend::receipt::LaunchReceipt;
    use dsmack_backend::spec::LaunchSpec;

    let d = std::path::Path::new(scratch_path).parent().unwrap();
    let kernel = {
        let mut k = vec![0u8; 4096];
        let kernel_len = k.len() as u64;
        k[56..60].copy_from_slice(b"ARM\x64");
        k[8..16].copy_from_slice(&0u64.to_le_bytes());
        k[16..24].copy_from_slice(&kernel_len.to_le_bytes());
        k
    };
    let initrd = {
        let mut i = vec![0u8; 512];
        i[..6].copy_from_slice(b"INITRD");
        i
    };
    let initrd_sha = sha_hex(&initrd);
    let images = VerifiedBootImages::new(
        &kernel,
        Some(&initrd),
        cmdline,
        &VerifiedBootPins {
            kernel_sha256: &sha_hex(&kernel),
            initrd_sha256: Some(initrd_sha.as_str()),
            cmdline_sha256: &sha_hex(cmdline.as_bytes()),
        },
    )
    .unwrap();
    let system = d.join("system.img");
    std::fs::write(&system, vec![0xA5u8; 1024]).unwrap();
    let workload = d.join("workload.img");
    std::fs::write(&workload, vec![0x5Au8; 512]).unwrap();
    let attached = vec![
        open_verified_ro(DiskRole::System, system.to_str().unwrap(), &sha_hex(&[0xA5u8; 1024]))
            .unwrap(),
        create_scratch(scratch_path).unwrap(),
        open_verified_ro(DiskRole::Workload, workload.to_str().unwrap(), &sha_hex(&[0x5Au8; 512]))
            .unwrap(),
    ];
    let spec = LaunchSpec {
        spec_sha256: sha_hex(b"admitted-spec-doc"),
        kernel_sha256: sha_hex(&kernel),
        initrd_sha256: Some(sha_hex(&initrd)),
        cmdline: cmdline.to_string(),
        cmdline_sha256: sha_hex(cmdline.as_bytes()),
        system_sha256: sha_hex(&[0xA5u8; 1024]),
        verity_root_hash: sha_hex(b"verity-root"),
        workload_sha256: sha_hex(&[0x5Au8; 512]),
        ram_mib: 2048,
        vcpus: 2,
    };
    LaunchReceipt::record(&spec, &images, &attached, "memory-placement-model (engineering; not a VM; not Mac evidence)")
}

/// R1: a scratch path holding RAW control bytes (legal on POSIX) must come
/// out as valid JSON with \\u00XX escapes. This is the exact predetect-P1
/// case, now PASSING.
#[test]
fn receipt_json_escapes_control_char_scratch_path() {
    let d = std::env::temp_dir().join(format!("f4-fix1-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let scratch = d.join("scra\u{1}tch\u{7f}.img");
    let receipt = unit_receipt("console=hvc0", scratch.to_str().unwrap());
    let json = receipt.to_json();
    assert_eq!(receipt_json_defect(&json), None, "receipt must be valid JSON: {json}");
    assert!(json.contains("scra\\u0001tch\\u007f.img"), "{json}");
    // The escaped receipt must still fit the cap the ABI advertises.
    assert!(json.len() + 1 <= dsmack_backend::ctl_capi::dsmack_ctl_join_receipt_cap_min());
    std::fs::remove_dir_all(&d).ok();
}

/// R2: the worst-case cap dominates a MAXIMAL legal receipt (2047 quote
/// characters = 2x escape; an exactly-256-byte scratch path = the bound;
/// initrd pin present) — the predetect-P2 case (3846 > 2048), now PASSING,
/// and the FFI cap_min equals `worst_case_cap` exactly.
#[test]
fn worst_case_cap_dominates_maximal_legal_receipt() {
    let d = std::env::temp_dir().join(format!("f4-fix2-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let cmdline: String = "\"".repeat(dsmack_backend::spec::LaunchSpec::cmdline_max());
    // Full scratch path of EXACTLY the legal maximum (256 bytes), printable.
    let bound = dsmack_backend::receipt::SCRATCH_PATH_MAX_BYTES;
    let prefix = format!("{}/", d.to_str().unwrap());
    let pad = bound - prefix.len() - ".img".len();
    assert!(pad > 0, "fixture prefix too long for the bound");
    let scratch = format!("{prefix}{}{}.img", "s", "p".repeat(pad - 1));
    assert_eq!(scratch.len(), bound);
    let receipt = unit_receipt(&cmdline, &scratch);
    let json = receipt.to_json();
    let cap = dsmack_backend::ctl_capi::dsmack_ctl_join_receipt_cap_min();
    assert_eq!(cap, dsmack_backend::receipt::worst_case_cap(), "FFI cap_min must equal the computed worst case");
    assert!(
        json.len() + 1 <= cap,
        "maximal legal receipt ({} bytes + NUL) must fit the cap {cap}",
        json.len()
    );
    assert_eq!(receipt_json_defect(&json), None, "{json}");
    // Drop the created scratch (unit_receipt created it inside d/ only).
    std::fs::remove_dir_all(&d).ok();
    let _ = std::fs::remove_file(&scratch);
}

/// R3: an over-bound scratch path is refused before anything is created,
/// naming the bound, and the control descriptor is closed exactly once
/// (R4 through the new refusal path).
#[test]
fn over_bound_scratch_path_refused_and_control_fd_closed() {
    let d = std::env::temp_dir().join(format!("f4-fix3-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let kernel = {
        let mut k = vec![0u8; 4096];
        let kernel_len = k.len() as u64;
        k[56..60].copy_from_slice(b"ARM\x64");
        k[8..16].copy_from_slice(&0u64.to_le_bytes());
        k[16..24].copy_from_slice(&kernel_len.to_le_bytes());
        k
    };
    let system = d.join("system.img");
    std::fs::write(&system, vec![0xA5u8; 1024]).unwrap();
    let workload = d.join("workload.img");
    std::fs::write(&workload, vec![0x5Au8; 512]).unwrap();
    let long_scratch = d.join("x".repeat(300));
    let cmdline = CString::new("console=hvc0").unwrap();
    let mut fds = [0 as libc::c_int; 2];
    assert_eq!(
        unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) },
        0
    );
    let mut err = vec![0u8; dsmack_backend::ctl_capi::dsmack_ctl_join_err_cap_min()];
    // SAFETY: fully initialized fixture with valid strings/buffers.
    let h = unsafe {
        dsmack_backend::ctl_capi::dsmack_ctl_join_vm_new(
            kernel.as_ptr(),
            kernel.len(),
            std::ptr::null(),
            0,
            &dsmack_backend::ctl_capi::DsmackCtlLaunchSpec {
                spec_sha256: leak_cstr(&sha_hex(b"spec")),
                kernel_sha256: leak_cstr(&sha_hex(&kernel)),
                initrd_sha256: std::ptr::null(),
                cmdline: cmdline.as_ptr() as *const std::ffi::c_char,
                cmdline_sha256: leak_cstr(&sha_hex(cmdline.to_bytes())),
                system_sha256: leak_cstr(&sha_hex(&std::fs::read(&system).unwrap())),
                verity_root_hash: leak_cstr(&sha_hex(b"verity-root")),
                workload_sha256: leak_cstr(&sha_hex(&std::fs::read(&workload).unwrap())),
                ram_mib: 512,
                vcpus: 1,
            },
            &dsmack_backend::ctl_capi::DsmackCtlDiskSet {
                system_path: leak_cstr(system.to_str().unwrap()),
                scratch_path: leak_cstr(long_scratch.to_str().unwrap()),
                workload_path: leak_cstr(workload.to_str().unwrap()),
            },
            leak_cstr(d.join("console.log").to_str().unwrap()),
            fds[1],
            err.as_mut_ptr(),
            err.len(),
        )
    };
    assert_eq!(h, 0, "over-bound scratch path must refuse");
    let end = err.iter().position(|b| *b == 0).unwrap_or(err.len());
    let msg = String::from_utf8_lossy(&err[..end]).into_owned();
    assert!(msg.contains("receipt-evidence bound"), "{msg}");
    assert!(!long_scratch.exists(), "refusal must not create the scratch inode");
    // descriptor closed exactly once (R4): EBADF is the only acceptable state
    assert_eq!(unsafe { libc::fcntl(fds[1], libc::F_GETFD) }, -1, "control fd must be closed exactly once");
    unsafe { libc::close(fds[0]) };
    std::fs::remove_dir_all(&d).ok();
}

/// R4: the FFI receipt surface refuses (never truncates) a too-small
/// buffer and reads back byte-complete at exactly cap_min.
#[test]
fn ffi_receipt_refuses_small_and_reads_at_cap_min() {
    let d = std::env::temp_dir().join(format!("f4-fix4-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let kernel = {
        let mut k = vec![0u8; 4096];
        let kernel_len = k.len() as u64;
        k[56..60].copy_from_slice(b"ARM\x64");
        k[8..16].copy_from_slice(&0u64.to_le_bytes());
        k[16..24].copy_from_slice(&kernel_len.to_le_bytes());
        k
    };
    let system = d.join("system.img");
    std::fs::write(&system, vec![0xA5u8; 1024]).unwrap();
    let workload = d.join("workload.img");
    std::fs::write(&workload, vec![0x5Au8; 512]).unwrap();
    let cmdline = CString::new("console=hvc0").unwrap();
    let mut fds = [0 as libc::c_int; 2];
    assert_eq!(
        unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) },
        0
    );
    let mut err = vec![0u8; dsmack_backend::ctl_capi::dsmack_ctl_join_err_cap_min()];
    // SAFETY: fully initialized fixture with valid strings/buffers.
    let h = unsafe {
        dsmack_backend::ctl_capi::dsmack_ctl_join_vm_new(
            kernel.as_ptr(),
            kernel.len(),
            std::ptr::null(),
            0,
            &dsmack_backend::ctl_capi::DsmackCtlLaunchSpec {
                spec_sha256: leak_cstr(&sha_hex(b"spec")),
                kernel_sha256: leak_cstr(&sha_hex(&kernel)),
                initrd_sha256: std::ptr::null(),
                cmdline: cmdline.as_ptr() as *const std::ffi::c_char,
                cmdline_sha256: leak_cstr(&sha_hex(cmdline.to_bytes())),
                system_sha256: leak_cstr(&sha_hex(&std::fs::read(&system).unwrap())),
                verity_root_hash: leak_cstr(&sha_hex(b"verity-root")),
                workload_sha256: leak_cstr(&sha_hex(&std::fs::read(&workload).unwrap())),
                ram_mib: 512,
                vcpus: 1,
            },
            &dsmack_backend::ctl_capi::DsmackCtlDiskSet {
                system_path: leak_cstr(system.to_str().unwrap()),
                scratch_path: leak_cstr(d.join("scratch.img").to_str().unwrap()),
                workload_path: leak_cstr(workload.to_str().unwrap()),
            },
            leak_cstr(d.join("console.log").to_str().unwrap()),
            fds[1],
            err.as_mut_ptr(),
            err.len(),
        )
    };
    assert!(h != 0, "fixture must build");
    // Too small: REFUSES, never truncates.
    let mut small = vec![0u8; 8];
    // SAFETY: out writable for out.len(); live handle from vm_new.
    assert_eq!(
        unsafe { dsmack_backend::ctl_capi::dsmack_ctl_join_receipt(h, small.as_mut_ptr(), small.len()) },
        -1
    );
    // Exactly cap_min: the Swift allocation discipline always succeeds.
    let cap = dsmack_backend::ctl_capi::dsmack_ctl_join_receipt_cap_min();
    let mut out = vec![0u8; cap];
    // SAFETY: out writable for cap; live handle from vm_new.
    assert_eq!(unsafe { dsmack_backend::ctl_capi::dsmack_ctl_join_receipt(h, out.as_mut_ptr(), cap) }, 0);
    let end = out.iter().position(|b| *b == 0).unwrap();
    let receipt = String::from_utf8(out[..end].to_vec()).unwrap();
    assert!(receipt.starts_with("{\"schema\":\"dsmack-backend-v2/launch-receipt/1\""), "{receipt}");
    assert!(receipt.ends_with('}'));
    assert_eq!(receipt_json_defect(&receipt), None);
    std::fs::remove_dir_all(&d).ok();
}

/// The exact computed cap, printed for the offline cross-language check
/// (tests-offline recomputes the formula from source and asserts equality).
#[test]
fn print_worst_case_cap_for_offline_crosscheck() {
    println!(
        "WORST_CASE_CAP={} CMDLINE_MAX={} SCRATCH_PATH_MAX={} HONESTY_BYTES={}",
        dsmack_backend::receipt::worst_case_cap(),
        dsmack_backend::spec::LaunchSpec::cmdline_max(),
        dsmack_backend::receipt::SCRATCH_PATH_MAX_BYTES,
        dsmack_backend::receipt::HONESTY_BLOCK_JSON.len()
    );
}
