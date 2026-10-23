//! vda/vdb/vdc/vdd/vde device-set tests — ACTUAL files/inodes on host Linux.
//! Proves: measured verify-on-open; fresh template-copy is a distinct inode
//! that never hardlinks/mutates the base; vdd verified inode is the one
//! transferred into I/O; vde is genuinely unmeasured (never hashed).

use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;

use dsmack_backend_v3::disks_v3::{self, AdmittedTemplate, DiskError, DiskRole, PrivateInputError};
use sha2::{Digest, Sha256};

fn tmp(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("dsmack-v3-disk-{}-{}", name, std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}

fn write_file(p: &std::path::Path, bytes: &[u8]) {
    let mut f = std::fs::File::create(p).unwrap();
    f.write_all(bytes).unwrap();
    f.flush().unwrap();
}

#[test]
fn measured_ro_verify_on_open_accepts_and_refuses() {
    let d = tmp("ro");
    let p = d.join("system.img");
    let content = vec![0x11u8; 1024];
    write_file(&p, &content);
    // accept
    let disk =
        disks_v3::open_verified_ro(DiskRole::System, p.to_str().unwrap(), &sha(&content)).unwrap();
    assert!(disk.read_only);
    assert!(disk.measured);
    assert_eq!(
        disk.observed_sha256.as_deref(),
        Some(sha(&content).as_str())
    );
    // refuse on tamper
    let e = disks_v3::open_verified_ro(DiskRole::System, p.to_str().unwrap(), &"0".repeat(64))
        .unwrap_err();
    assert!(matches!(e, DiskError::HashMismatch { .. }));
    let _ = std::fs::remove_dir_all(&d);
}

/// FRESH TEMPLATE COPY (vdb/vdd): a distinct fresh inode, content == template,
/// and the base template asset is never hardlinked nor mutated.
#[test]
fn fresh_copy_is_distinct_inode_and_does_not_mutate_base() {
    let d = tmp("freshcopy");
    let tmpl = d.join("result-template.img");
    let tcontent = vec![0x00u8; 8192]; // blank result template, 512-multiple
    write_file(&tmpl, &tcontent);
    let tmeta_before = std::fs::metadata(&tmpl).unwrap();
    let template = AdmittedTemplate {
        path: tmpl.to_str().unwrap().to_string(),
        template_sha256: sha(&tcontent),
        template_bytes: tcontent.len() as u64,
    };
    let dest = d.join("vdd-result.img");
    let (mut disk, _handle) =
        disks_v3::create_fresh_from_template(DiskRole::Result, dest.to_str().unwrap(), &template)
            .unwrap();
    assert!(!disk.read_only);
    assert_eq!(
        disk.template_sha256.as_deref(),
        Some(sha(&tcontent).as_str())
    );
    assert_eq!(disk.template_bytes, Some(tcontent.len() as u64));

    // distinct inode from the base template
    let dest_meta = std::fs::metadata(&dest).unwrap();
    assert_ne!(
        (dest_meta.dev(), dest_meta.ino()),
        (tmeta_before.dev(), tmeta_before.ino()),
        "fresh copy must be a distinct inode (no hardlink/alias)"
    );
    // link count 1 on both (no hardlink was created)
    assert_eq!(dest_meta.nlink(), 1);
    assert_eq!(std::fs::metadata(&tmpl).unwrap().nlink(), 1);

    // dest content equals the template content at creation
    let mut buf = Vec::new();
    std::fs::File::open(&dest)
        .unwrap()
        .read_to_end(&mut buf)
        .unwrap();
    assert_eq!(sha(&buf), sha(&tcontent));

    // now MUTATE the fresh copy through its retained descriptor and prove the
    // base template is byte-for-byte unchanged (never aliased/mutated).
    use std::io::{Seek, SeekFrom};
    disk.file.seek(SeekFrom::Start(0)).unwrap();
    disk.file.write_all(&[0xFFu8; 512]).unwrap();
    disk.file.flush().unwrap();
    let mut tbuf = Vec::new();
    std::fs::File::open(&tmpl)
        .unwrap()
        .read_to_end(&mut tbuf)
        .unwrap();
    assert_eq!(
        sha(&tbuf),
        sha(&tcontent),
        "base template must be untouched"
    );
    let tmeta_after = std::fs::metadata(&tmpl).unwrap();
    assert_eq!(
        (tmeta_after.dev(), tmeta_after.ino()),
        (tmeta_before.dev(), tmeta_before.ino())
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn fresh_target_preexisting_refused() {
    let d = tmp("preexist");
    let tmpl = d.join("tmpl.img");
    let tcontent = vec![0u8; 1024];
    write_file(&tmpl, &tcontent);
    let template = AdmittedTemplate {
        path: tmpl.to_str().unwrap().to_string(),
        template_sha256: sha(&tcontent),
        template_bytes: 1024,
    };
    let dest = d.join("dest.img");
    write_file(&dest, b"stale");
    let e =
        disks_v3::create_fresh_from_template(DiskRole::Scratch, dest.to_str().unwrap(), &template)
            .unwrap_err();
    assert!(
        matches!(&e, DiskError::DeferredCleanup { cause, .. } if matches!(**cause, DiskError::FreshPreExisting { .. }))
    );
    assert!(e.to_string().contains("cleanup deferred"));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn template_hash_or_size_mismatch_refused() {
    let d = tmp("tmplbad");
    let tmpl = d.join("tmpl.img");
    let tcontent = vec![0x22u8; 1024];
    write_file(&tmpl, &tcontent);
    // wrong hash
    let bad_hash = AdmittedTemplate {
        path: tmpl.to_str().unwrap().to_string(),
        template_sha256: "0".repeat(64),
        template_bytes: 1024,
    };
    assert!(matches!(
        disks_v3::create_fresh_from_template(
            DiskRole::Result,
            d.join("a.img").to_str().unwrap(),
            &bad_hash
        ),
        Err(DiskError::TemplateHashMismatch { .. })
    ));
    // wrong size
    let bad_size = AdmittedTemplate {
        path: tmpl.to_str().unwrap().to_string(),
        template_sha256: sha(&tcontent),
        template_bytes: 2048,
    };
    assert!(matches!(
        disks_v3::create_fresh_from_template(
            DiskRole::Result,
            d.join("b.img").to_str().unwrap(),
            &bad_size
        ),
        Err(DiskError::TemplateSizeMismatch { .. })
    ));
    let _ = std::fs::remove_dir_all(&d);
}

/// vdd: the VERIFIED/created inode is the one transferred into I/O — finalizing
/// through a dup of that exact descriptor hashes the fresh copy's bytes.
#[test]
fn result_inode_is_transferred_into_finalization() {
    use dsmack_backend_v3::consumption_v3::FdStorage;
    use dsmack_backend_v3::finalize;
    use std::os::fd::{AsFd, AsRawFd};

    let d = tmp("transfer");
    let tmpl = d.join("tmpl.img");
    let tcontent = vec![0x33u8; 4096];
    write_file(&tmpl, &tcontent);
    let template = AdmittedTemplate {
        path: tmpl.to_str().unwrap().to_string(),
        template_sha256: sha(&tcontent),
        template_bytes: 4096,
    };
    let dest = d.join("vdd.img");
    let (disk, _handle) =
        disks_v3::create_fresh_from_template(DiskRole::Result, dest.to_str().unwrap(), &template)
            .unwrap();
    let retained = finalize::dup_retained(disk.file.as_fd()).unwrap();
    let mut storage = FdStorage::new(disk.file.as_raw_fd());
    let r = finalize::finalize_result(&mut storage, &retained, 4096, || false, None).unwrap();
    // fresh copy content == template content
    assert_eq!(r.result_sha256, sha(&tcontent));
    let _ = std::fs::remove_dir_all(&d);
}

/// vde: genuinely UNMEASURED. The opener never computes a content hash; the
/// attached disk carries no observed digest and is marked unmeasured.
#[test]
fn private_input_is_unmeasured() {
    let d = tmp("vde");
    let p = d.join("private.img");
    write_file(&p, &vec![0x44u8; 2048]);
    let disk = disks_v3::open_private_unmeasured(p.to_str().unwrap()).unwrap();
    assert!(disk.read_only);
    assert!(!disk.measured, "vde must be unmeasured");
    assert!(
        disk.observed_sha256.is_none(),
        "vde must never carry a content digest"
    );
    assert!(disk.template_sha256.is_none());
    // bounds enforced — and the rejection is the REDACTED private error
    let big = d.join("odd.img");
    write_file(&big, &vec![0u8; 513]); // not 512-aligned
    let e = disks_v3::open_private_unmeasured(big.to_str().unwrap()).unwrap_err();
    assert_eq!(e, PrivateInputError::BadSize);
    // the diagnostic exposes no size/path (F05)
    let msg = format!("{e}");
    assert!(!msg.contains("513") && !msg.contains('/'));
    let _ = std::fs::remove_dir_all(&d);
}
