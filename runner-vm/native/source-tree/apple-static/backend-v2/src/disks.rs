//! The vda/vdb/vdc disk triple of the pinned guest contract (v2).
//!
//! v1 had a single compiled-in-pinned system disk. v2 (mac-general-prep v2
//! proposal + admission-policy device_contract) carries three devices, all
//! handled by THIS backend before any VM exists:
//!
//! - **vda system**  read-only; verify-on-open: opened here, fstat'd a
//!   regular file, full content hashed, refused unless it equals the spec
//!   digest. This is the engineering narrowing (fast wrong-disk refusal) —
//!   per boot-binding-spike DESIGN R4 the SECURITY binding for the rootfs
//!   is the verified initrd's pinned in-guest dm-verity table plus the
//!   fail-closed cmdline (`panic=-1`); host-side hashing is NOT the
//!   boundary and closes nothing against host root.
//! - **vdb scratch** read-write; FRESH per launch: created here O_EXCL
//!   (mode 0600); a pre-existing scratch inode is a REFUSAL, never a reuse
//!   (guest docker/container state must not survive or observe a previous
//!   launch; it dies with this file at poweroff).
//! - **vdc workload** read-only; verify-on-open like system. The workload
//!   tar's deep binding stays guest-side (pinned supervisor re-verifies
//!   SHA256SUMS before use — dual control, unchanged); this host-side hash
//!   only narrows the staging window. The backend learns NOTHING about
//!   workload semantics from this digest.

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;

use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum DiskError {
    #[error("{0} path: null")]
    NullPath(DiskRole),
    #[error("{0} path not UTF-8")]
    NotUtf8(DiskRole),
    #[error("{role} disk {path}: unreadable ({source})")]
    Unreadable {
        role: DiskRole,
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{role} disk {path} is not a regular file")]
    NotRegularFile { role: DiskRole, path: String },
    #[error("{role} disk {path}: size {size} is zero or not a 512-byte multiple")]
    BadSize { role: DiskRole, path: String, size: u64 },
    #[error("{role} disk verify-on-open FAILED: content sha256 {actual} != spec {expected}")]
    HashMismatch {
        role: DiskRole,
        path: String,
        actual: String,
        expected: String,
    },
    #[error("scratch disk {path} already exists — refusing (fresh-inode requirement)")]
    ScratchPreExisting { path: String },
    #[error("scratch disk {path}: create failed ({source})")]
    ScratchCreateFailed {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("scratch disk {path} created but is not a regular file")]
    ScratchNotRegular { path: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskRole {
    System,
    Scratch,
    Workload,
}

impl DiskRole {
    pub fn name(self) -> &'static str {
        match self {
            DiskRole::System => "system(vda)",
            DiskRole::Scratch => "scratch(vdb)",
            DiskRole::Workload => "workload(vdc)",
        }
    }
}

impl std::fmt::Display for DiskRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// One verified-attached disk: held open from HERE (the attach step) so the
/// consumption layer attaches the descriptor we verified, never a re-opened
/// path (closes the verify→attach re-open window inside the backend).
#[derive(Debug)]
pub struct AttachedDisk {
    pub role: DiskRole,
    pub path: String,
    pub observed_sha256: String,
    pub bytes: u64,
    pub read_only: bool,
    pub file: File,
}

fn sha256_stream(file: &mut File) -> Result<(String, u64), std::io::Error> {
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((format!("{:x}", hasher.finalize()), total))
}

/// Verify-on-open for a read-only disk (system vda / workload vdc):
/// regular file, non-zero 512-multiple size, full content equals the spec
/// digest. Modeled on source3's `verify_disk_pin` (api/vmm_builder.rs:620)
/// but caller-supplied-pin and held-open.
pub fn open_verified_ro(
    role: DiskRole,
    path: &str,
    expected_sha256: &str,
) -> Result<AttachedDisk, DiskError> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(false)
        .open(path)
        .map_err(|source| DiskError::Unreadable {
            role,
            path: path.to_string(),
            source,
        })?;
    let meta = file
        .metadata()
        .map_err(|source| DiskError::Unreadable {
            role,
            path: path.to_string(),
            source,
        })?;
    if !meta.is_file() {
        return Err(DiskError::NotRegularFile {
            role,
            path: path.to_string(),
        });
    }
    let size = meta.len();
    if size == 0 || size % 512 != 0 {
        return Err(DiskError::BadSize {
            role,
            path: path.to_string(),
            size,
        });
    }
    let (actual, bytes) = sha256_stream(&mut file).map_err(|source| DiskError::Unreadable {
        role,
        path: path.to_string(),
        source,
    })?;
    if actual != expected_sha256 {
        return Err(DiskError::HashMismatch {
            role,
            path: path.to_string(),
            actual,
            expected: expected_sha256.to_string(),
        });
    }
    Ok(AttachedDisk {
        role,
        path: path.to_string(),
        observed_sha256: actual,
        bytes,
        read_only: true,
        file,
    })
}

/// Fresh scratch (vdb): O_EXCL create at 0600 — a pre-existing inode is a
/// refusal, not a reuse. The file stays EMPTY here; the guest-side
/// bootstrap formats it (the pinned supervisor owns the ext4 setup, as in
/// every Zed boot); the backend only guarantees the inode is fresh and
/// private to this launch.
pub fn create_scratch(path: &str) -> Result<AttachedDisk, DiskError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|source| {
            if source.kind() == std::io::ErrorKind::AlreadyExists {
                DiskError::ScratchPreExisting {
                    path: path.to_string(),
                }
            } else {
                DiskError::ScratchCreateFailed {
                    path: path.to_string(),
                    source,
                }
            }
        })?;
    let meta = file.metadata().map_err(|source| DiskError::Unreadable {
        role: DiskRole::Scratch,
        path: path.to_string(),
        source,
    })?;
    if !meta.is_file() {
        return Err(DiskError::ScratchNotRegular {
            path: path.to_string(),
        });
    }
    Ok(AttachedDisk {
        role: DiskRole::Scratch,
        path: path.to_string(),
        observed_sha256: String::new(), // empty fresh scratch: nothing pinned
        bytes: 0,
        read_only: false,
        file,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("dsmack-disks-{}-{}", name, std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn verify_on_open_accepts_matching_disk() {
        let dir = tmpdir("ok");
        let p = dir.join("system.img");
        std::fs::write(&p, vec![0u8; 1024]).unwrap();
        let want = {
            let mut f = File::open(&p).unwrap();
            sha256_stream(&mut f).unwrap().0
        };
        let d = open_verified_ro(DiskRole::System, p.to_str().unwrap(), &want).unwrap();
        assert_eq!(d.bytes, 1024);
        assert!(d.read_only);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tampered_disk_refused() {
        let dir = tmpdir("tampered");
        let p = dir.join("system.img");
        std::fs::write(&p, vec![1u8; 512]).unwrap();
        let e = open_verified_ro(DiskRole::System, p.to_str().unwrap(), &"a".repeat(64))
            .unwrap_err();
        assert!(matches!(e, DiskError::HashMismatch { .. }));
        // and the honest refusal names BOTH digests (evidence value).
        assert!(e.to_string().contains("verify-on-open FAILED"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bad_size_and_non_regular_refused() {
        let dir = tmpdir("size");
        let p = dir.join("odd.img");
        std::fs::write(&p, vec![1u8; 513]).unwrap();
        let want = {
            let mut f = File::open(&p).unwrap();
            sha256_stream(&mut f).unwrap().0
        };
        assert!(matches!(
            open_verified_ro(DiskRole::Workload, p.to_str().unwrap(), &want),
            Err(DiskError::BadSize { .. })
        ));
        assert!(matches!(
            open_verified_ro(DiskRole::Workload, "/dev/null", &want),
            Err(DiskError::BadSize { .. }) | Err(DiskError::NotRegularFile { .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scratch_fresh_inode_discipline() {
        let dir = tmpdir("scratch");
        let p = dir.join("scratch.img");
        let s = create_scratch(p.to_str().unwrap()).unwrap();
        assert!(!s.read_only);
        // mode 0600
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // second create on the SAME inode refuses (fresh-inode requirement)
        assert!(matches!(
            create_scratch(p.to_str().unwrap()),
            Err(DiskError::ScratchPreExisting { .. })
        ));
        drop(s);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
