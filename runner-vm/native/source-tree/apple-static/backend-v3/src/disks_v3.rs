//! The vda/vdb/vdc/vdd/vde device set of the v3 generic native backend.
//!
//! v2 (disks.rs) carried a vda/vdb/vdc triple: measured RO system, fresh EMPTY
//! O_EXCL scratch, measured RO workload. v3 adds the OUTPUT path required by
//! the output-continuity contract (astra-gate device_roles):
//!
//! - **vda system**  measured RO, verify-on-open (unchanged from v2).
//! - **vdb scratch** fresh RW, now INITIALIZED from an admitted blank
//!   filesystem template (not merely an empty O_EXCL inode): a distinct fresh
//!   inode, byte-copied from the measured template, never a hardlink and never
//!   a mutation of the base asset.
//! - **vdc workload** measured RO, verify-on-open (unchanged from v2).
//! - **vdd result**  fresh RW, initialized from an admitted blank result
//!   template; the VERIFIED inode itself is retained and transferred into the
//!   storage I/O layer; it is finalized (checked flush/sync) and hashed through
//!   the retained descriptor at teardown (see `finalize.rs`).
//! - **vde private** OPTIONAL, genuinely UNMEASURED RO private-input transport:
//!   opened and bounded, inode retained, but NO content hash is ever computed
//!   or recorded — not in the spec, receipt, trace or diagnostics. Its presence
//!   (not its content) is all the public evidence may carry.
//!
//! Every disk here holds its descriptor open from the moment it is verified or
//! created, so the consumption layer attaches the inode this module verified —
//! never a re-opened path (closes the verify→attach re-open window).

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use sha2::{Digest, Sha256};

/// vde image bounds (protocol.PT_IMAGE_*): 512-aligned, <= 1 GiB.
pub const PRIVATE_IMAGE_ALIGN: u64 = 512;
pub const PRIVATE_IMAGE_BYTES_MAX: u64 = 1 << 30;
/// Result remains the existing result protocol limit. Scratch is an independent ceiling.
pub const TEMPLATE_BYTES_MAX: u64 = 1 << 30;
pub const SCRATCH_TEMPLATE_BYTES_MAX: u64 = 4 << 30;

/// Only scratch/result may be initialized from blank templates.
pub fn template_bytes_max(role: DiskRole) -> Option<u64> {
    match role {
        DiskRole::Scratch => Some(SCRATCH_TEMPLATE_BYTES_MAX),
        DiskRole::Result => Some(TEMPLATE_BYTES_MAX),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskRole {
    System,
    Scratch,
    Workload,
    Result,
    PrivateInput,
}

impl DiskRole {
    pub fn name(self) -> &'static str {
        match self {
            DiskRole::System => "system(vda)",
            DiskRole::Scratch => "scratch(vdb)",
            DiskRole::Workload => "workload(vdc)",
            DiskRole::Result => "result(vdd)",
            DiskRole::PrivateInput => "private(vde)",
        }
    }
    /// The guest enumeration device node (attach order IS the guest contract).
    pub fn dev(self) -> &'static str {
        match self {
            DiskRole::System => "vda",
            DiskRole::Scratch => "vdb",
            DiskRole::Workload => "vdc",
            DiskRole::Result => "vdd",
            DiskRole::PrivateInput => "vde",
        }
    }
}

impl std::fmt::Display for DiskRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DiskError {
    #[error("{role} is not a scratch/result template role")]
    InvalidTemplateRole { role: DiskRole },
    #[error("{cause}; {residue}")]
    DeferredCleanup {
        #[source]
        cause: Box<DiskError>,
        residue: DeferredResidue,
    },
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
    BadSize {
        role: DiskRole,
        path: String,
        size: u64,
    },
    #[error("{role} disk {path}: size {size} exceeds cap {cap}")]
    TooLarge {
        role: DiskRole,
        path: String,
        size: u64,
        cap: u64,
    },
    #[error("{role} verify-on-open FAILED: content sha256 {actual} != spec {expected}")]
    HashMismatch {
        role: DiskRole,
        actual: String,
        expected: String,
    },
    #[error("{role} template {path}: content sha256 {actual} != admitted {expected}")]
    TemplateHashMismatch {
        role: DiskRole,
        path: String,
        actual: String,
        expected: String,
    },
    #[error("{role} template {path}: admitted {expected} bytes, actual {actual}")]
    TemplateSizeMismatch {
        role: DiskRole,
        path: String,
        expected: u64,
        actual: u64,
    },
    #[error("{role} fresh target {path} already exists — refusing (fresh-inode requirement)")]
    FreshPreExisting { role: DiskRole, path: String },
    #[error(
        "{role} fresh output {path}: parent directory is not a controlled same-uid private \
             directory (must be owned by this euid with no group/other write) — refusing to \
             create or clean a fresh inode where another principal could swap entries"
    )]
    UncontrolledOutputDir { role: DiskRole, path: String },
    #[error("{role} fresh target {path}: create failed ({source})")]
    FreshCreateFailed {
        role: DiskRole,
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{role} template copy {path}: {source}")]
    CopyFailed {
        role: DiskRole,
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "{role} fresh copy {dest} shares inode with base template {template} — refusing \
             (fresh copy must not hardlink/alias the base asset)"
    )]
    FreshAliasesTemplate {
        role: DiskRole,
        dest: String,
        template: String,
    },
    #[error(
        "{role} template {path}: copied content sha256 {actual} != admitted {expected} \
             (replacement/anomaly between verification and copy)"
    )]
    CopiedContentMismatch {
        role: DiskRole,
        path: String,
        actual: String,
        expected: String,
    },
    #[error("{role} template {path}: copied {copied} bytes, admitted {expected} ({kind})")]
    CopiedLengthMismatch {
        role: DiskRole,
        path: String,
        copied: u64,
        expected: u64,
        kind: &'static str,
    },
    #[error(
        "{role} template {path}: source grew past the admitted {expected} bytes during copy \
             (trailing bytes present after the admitted length — replacement/growth)"
    )]
    SourceGrewDuringCopy {
        role: DiskRole,
        path: String,
        expected: u64,
    },
}

/// F05 — REDACTED private-input (vde) rejection diagnostics. The vde image is
/// genuinely UNMEASURED and PRIVATE: a rejection must expose ONLY the failed
/// policy RULE, never the image's byte size and never its path (both private
/// facts a relying party could otherwise learn from a crafted refusal). The
/// Display text is intentionally free of any size, path, errno or byte-length.
/// The size/alignment/cap thresholds are PUBLIC policy constants; the rejected
/// image's own size is never echoed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PrivateInputError {
    #[error("private(vde) input rejected: unreadable")]
    Unreadable,
    #[error("private(vde) input rejected: not a regular file")]
    NotRegularFile,
    #[error("private(vde) input rejected: size is not a positive multiple of the 512-byte alignment policy")]
    BadSize,
    #[error("private(vde) input rejected: exceeds the maximum private-image size policy")]
    TooLarge,
}

/// F04 — ENFORCED controlled-directory boundary. Open `dir_path` as a directory
/// WITHOUT following a terminal symlink and verify it is a *private, same-uid*
/// directory: owned by this effective uid and with NO group/other WRITE bit
/// (`mode & 0o022 == 0`), so no other principal can create, rename or swap
/// entries inside it. Returns the pinned directory descriptor on success. This
/// turns the previously comment-only "controlled 0700 parent directory"
/// assumption into an actual runtime precondition that FAILS CLOSED: a
/// world-/group-writable output directory (the real replacement-attack surface,
/// e.g. a sticky 1777 tmp) is refused rather than trusted.
///
/// The returned descriptor is RETAINED by the caller and is the ONLY handle
/// through which the output is created and published
/// — the full path is never re-resolved after this point, so a parent
/// substitution between validation and creation cannot redirect it (the
/// held `dirfd` pins the directory inode regardless of what the pathname later
/// resolves to).
fn open_private_dir(dir_path: &std::path::Path) -> std::io::Result<File> {
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir_path)?;
    // SAFETY: fstat over the owned directory fd.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(dir.as_raw_fd(), &mut st) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: geteuid is always safe.
    let euid = unsafe { libc::geteuid() };
    let is_dir = (st.st_mode & libc::S_IFMT) == libc::S_IFDIR;
    let no_foreign_write = (st.st_mode & 0o022) == 0;
    if is_dir && st.st_uid == euid && no_foreign_write {
        Ok(dir)
    } else {
        Err(std::io::Error::from_raw_os_error(libc::EPERM))
    }
}

/// Generate a staging basename; O_EXCL enforces creation uniqueness.
fn unique_staging_name(base: &std::ffi::OsStr) -> std::ffi::CString {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    let n = CTR.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    // Keep the original basename as a prefix (bounded) so the staging entry is
    // recognisable, but guarantee uniqueness through pid/counter/nanos.
    let b = base.to_string_lossy();
    let b = &b[..b.len().min(80)];
    std::ffi::CString::new(format!(".{b}.dsmack-attempt.{pid}.{n}.{nanos}.partial")).unwrap_or_else(
        |_| std::ffi::CString::new(format!(".dsmack-attempt.{pid}.{n}.{nanos}")).unwrap(),
    )
}

/// Atomic, fail-if-destination-exists rename WITHIN the retained private
/// directory (`dirfd`): publishes the attempt's staging inode to its admitted
/// name without ever clobbering a pre-existing object (the fresh-inode
/// requirement). Linux uses `renameat2(RENAME_NOREPLACE)`; Darwin (the actual
/// aarch64-apple-darwin target) uses `renameatx_np(RENAME_EXCL)`.
fn rename_noreplace_at(
    dirfd: RawFd,
    from: &std::ffi::CStr,
    to: &std::ffi::CStr,
) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    let rc = unsafe {
        libc::renameat2(
            dirfd,
            from.as_ptr(),
            dirfd,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    #[cfg(target_os = "macos")]
    let rc =
        unsafe { libc::renameatx_np(dirfd, from.as_ptr(), dirfd, to.as_ptr(), libc::RENAME_EXCL) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

use std::os::fd::RawFd;

/// Namespace cleanup is deferred: same-UID namespace exclusion is unproven.
/// Closing descriptors is independent of garbage collection.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("host cleanup deferred; residue retained at {name} (inode {dev}:{ino}); residue-free policy refused")]
pub struct DeferredResidue {
    pub name: String,
    pub dev: u64,
    pub ino: u64,
}

/// Holds the parent descriptor for creation/publication. Drop only closes it.
#[derive(Debug)]
pub struct OutputHandle {
    dir: File,
    /// The CURRENT on-disk basename (staging before publish, admitted after).
    name: std::ffi::CString,
    admitted: std::ffi::CString,
    dev: u64,
    ino: u64,
    role: DiskRole,
    admitted_display: String,
}

impl OutputHandle {
    /// Atomically publish the staging inode to its admitted basename. A
    /// pre-existing admitted object is refused (`FreshPreExisting`) rather than
    /// clobbered. After a successful publish the handle's cleanup target becomes
    /// the admitted name. Cleanup remains deferred.
    pub(crate) fn publish(&mut self) -> Result<(), DiskError> {
        if self.name == self.admitted {
            return Ok(());
        }
        match rename_noreplace_at(self.dir.as_raw_fd(), &self.name, &self.admitted) {
            Ok(()) => {
                self.name = self.admitted.clone();
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(DiskError::FreshPreExisting {
                    role: self.role,
                    path: self.admitted_display.clone(),
                })
            }
            Err(source) => Err(DiskError::FreshCreateFailed {
                role: self.role,
                path: self.admitted_display.clone(),
                source,
            }),
        }
    }

    /// A residue-free request always refuses without namespace exclusion.
    pub fn require_residue_free(&self) -> Result<(), DeferredResidue> {
        Err(self.deferred_residue())
    }

    pub fn deferred_residue(&self) -> DeferredResidue {
        DeferredResidue {
            name: self.name.to_string_lossy().into_owned(),
            dev: self.dev,
            ino: self.ino,
        }
    }

    fn failure(&self, cause: DiskError) -> DiskError {
        DiskError::DeferredCleanup {
            cause: Box::new(cause),
            residue: self.deferred_residue(),
        }
    }
}

/// F04 — create a fresh, attempt-owned output inode under a UNIQUE staging name
/// inside the verified-private parent of `admitted_path`, returning the open
/// file (positioned for writing) and the retained [`OutputHandle`]. The parent
/// descriptor is opened ONCE and threaded through the handle for publish and
/// cleanup; the staging inode is created O_EXCL relative to it (no full-path
/// re-resolution, so no parent-substitution window).
pub(crate) fn create_attempt_output(
    role: DiskRole,
    admitted_path: &str,
) -> Result<(File, OutputHandle), DiskError> {
    let p = std::path::Path::new(admitted_path);
    let base = p
        .file_name()
        .ok_or_else(|| DiskError::UncontrolledOutputDir {
            role,
            path: admitted_path.to_string(),
        })?;
    let admitted_c = std::ffi::CString::new(base.as_encoded_bytes()).map_err(|_| {
        DiskError::UncontrolledOutputDir {
            role,
            path: admitted_path.to_string(),
        }
    })?;
    let parent = match p.parent() {
        Some(par) if !par.as_os_str().is_empty() => par,
        _ => std::path::Path::new("."),
    };
    // Open AND verify the private parent ONCE; retain the descriptor.
    let dir = open_private_dir(parent).map_err(|_| DiskError::UncontrolledOutputDir {
        role,
        path: admitted_path.to_string(),
    })?;
    let staging = unique_staging_name(base);
    // Create the fresh inode O_EXCL relative to the retained dirfd.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            staging.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(DiskError::FreshCreateFailed {
            role,
            path: admitted_path.to_string(),
            source: std::io::Error::last_os_error(),
        });
    }
    // SAFETY: fd is a fresh descriptor we exclusively own.
    let file = unsafe { File::from_raw_fd(fd) };
    let meta = file.metadata().map_err(|source| DiskError::Unreadable {
        role,
        path: admitted_path.to_string(),
        source,
    })?;
    let handle = OutputHandle {
        dir,
        name: staging,
        admitted: admitted_c,
        dev: meta.dev(),
        ino: meta.ino(),
        role,
        admitted_display: admitted_path.to_string(),
    };
    Ok((file, handle))
}

/// An admitted blank template for a fresh RW disk (vdb/vdd): its content is
/// MEASURED (template_sha256) and sized exactly (template_bytes). The admitted
/// identity travels in the run-result envelope; the FRESH COPY the guest writes
/// is a distinct inode.
#[derive(Debug, Clone)]
pub struct AdmittedTemplate {
    pub path: String,
    pub template_sha256: String,
    pub template_bytes: u64,
}

/// One verified/created disk, holding its descriptor open from HERE.
#[derive(Debug)]
pub struct AttachedDiskV3 {
    pub role: DiskRole,
    pub path: String,
    pub read_only: bool,
    /// False ONLY for vde: a genuinely unmeasured private input.
    pub measured: bool,
    /// Observed content digest. `None` for vde (never hashed) and for a fresh
    /// RW copy (its content is the template; see `template_sha256`).
    pub observed_sha256: Option<String>,
    /// The admitted template identity for vdb/vdd (the base that was copied).
    pub template_sha256: Option<String>,
    pub template_bytes: Option<u64>,
    pub bytes: u64,
    /// The VERIFIED/created inode itself — transferred into storage I/O, never
    /// re-opened from the path.
    pub file: File,
}

impl AttachedDiskV3 {
    pub fn dev_ino(&self) -> std::io::Result<(u64, u64)> {
        let m = self.file.metadata()?;
        Ok((m.dev(), m.ino()))
    }
}

fn sha256_stream(file: &mut File) -> std::io::Result<(String, u64)> {
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

/// vda/vdc: measured RO. Opened O_RDONLY, regular, non-zero 512-multiple,
/// full content equals the admitted digest. The verified inode is retained.
pub fn open_verified_ro(
    role: DiskRole,
    path: &str,
    expected_sha256: &str,
) -> Result<AttachedDiskV3, DiskError> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(false)
        .open(path)
        .map_err(|source| DiskError::Unreadable {
            role,
            path: path.to_string(),
            source,
        })?;
    let meta = file.metadata().map_err(|source| DiskError::Unreadable {
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
            actual,
            expected: expected_sha256.to_string(),
        });
    }
    Ok(AttachedDiskV3 {
        role,
        path: path.to_string(),
        read_only: true,
        measured: true,
        observed_sha256: Some(actual),
        template_sha256: None,
        template_bytes: None,
        bytes,
        file,
    })
}

/// F03 — copy EXACTLY `want` bytes from the ALREADY-VERIFIED source descriptor
/// `src` into `dest`, re-hashing during the copy and refusing any deviation
/// from the admitted identity:
///   * reads through `src` (an open fd pinned to the verified inode) so a path
///     replacement between verification and copy cannot swap the bytes;
///   * EOF before `want` bytes -> refusal (truncation/replacement);
///   * copied digest != `admitted_sha256` -> refusal (a content swap, e.g. a
///     bytes-for-bytes replacement after the admitted identity was fixed);
///   * final on-disk `dest` size != `want` -> refusal (growth).
pub(crate) fn copy_exact_verified(
    src: &mut File,
    dest: &mut File,
    want: u64,
    admitted_sha256: &str,
    role: DiskRole,
    src_path: &str,
    dest_path: &str,
) -> Result<(), DiskError> {
    src.seek(SeekFrom::Start(0))
        .map_err(|source| DiskError::CopyFailed {
            role,
            path: src_path.to_string(),
            source,
        })?;
    let mut copied: u64 = 0;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    while copied < want {
        let chunk = std::cmp::min(buf.len() as u64, want - copied) as usize;
        let n = src
            .read(&mut buf[..chunk])
            .map_err(|source| DiskError::CopyFailed {
                role,
                path: src_path.to_string(),
                source,
            })?;
        if n == 0 {
            return Err(DiskError::CopiedLengthMismatch {
                role,
                path: src_path.to_string(),
                copied,
                expected: want,
                kind: "truncated before admitted length",
            });
        }
        hasher.update(&buf[..n]);
        dest.write_all(&buf[..n])
            .map_err(|source| DiskError::CopyFailed {
                role,
                path: dest_path.to_string(),
                source,
            })?;
        copied += n as u64;
    }
    dest.flush().map_err(|source| DiskError::CopyFailed {
        role,
        path: dest_path.to_string(),
        source,
    })?;
    // F03: enforce the admitted SOURCE length THROUGH completion. Reading
    // exactly `want` bytes and checking the destination size does not detect a
    // source that GREW past the admitted length (trailing bytes after the
    // admitted identity was fixed). One more read on the verified descriptor —
    // which is pinned to the inode we hashed — must observe a clean EOF; any
    // byte beyond the admitted length is a refusal (growth/replacement). EINTR
    // is retried; a nonzero read is the growth signal.
    loop {
        match src.read(&mut buf[..1]) {
            Ok(0) => break, // clean EOF at exactly `want` — admitted length holds
            Ok(_) => {
                return Err(DiskError::SourceGrewDuringCopy {
                    role,
                    path: src_path.to_string(),
                    expected: want,
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(source) => {
                return Err(DiskError::CopyFailed {
                    role,
                    path: src_path.to_string(),
                    source,
                });
            }
        }
    }
    let copied_sha = format!("{:x}", hasher.finalize());
    if copied_sha != admitted_sha256 {
        return Err(DiskError::CopiedContentMismatch {
            role,
            path: src_path.to_string(),
            actual: copied_sha,
            expected: admitted_sha256.to_string(),
        });
    }
    let dsize = dest
        .metadata()
        .map_err(|source| DiskError::Unreadable {
            role,
            path: dest_path.to_string(),
            source,
        })?
        .len();
    if dsize != want {
        return Err(DiskError::CopiedLengthMismatch {
            role,
            path: dest_path.to_string(),
            copied: dsize,
            expected: want,
            kind: "final size differs from admitted length",
        });
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    static COPY_FAILURE_HOOK: std::cell::RefCell<Option<Box<dyn FnMut()>>> = const { std::cell::RefCell::new(None) };
}

/// vdb/vdd: fresh RW initialized from an admitted blank template.
///
/// 1. open+verify the template (content digest and size match the admitted
///    identity); 2. create a fresh attempt-owned inode at a UNIQUE staging name
///    inside the verified-private parent (via [`create_attempt_output`], which
///    retains the parent descriptor); 3. BYTE-COPY template→inode (never a
///    hardlink/reflink alias); 4. assert the inode is DISTINCT from the base;
///    5. PUBLISH atomically to the admitted name with no-replace semantics (a
///    pre-existing admitted object is a refusal — fresh per launch); 6. return
///    the retained inode plus the [`OutputHandle`] whose descriptor the caller
///    uses to report deferred residue if a later launch step refuses.
pub fn create_fresh_from_template(
    role: DiskRole,
    dest_path: &str,
    template: &AdmittedTemplate,
) -> Result<(AttachedDiskV3, OutputHandle), DiskError> {
    let cap = template_bytes_max(role).ok_or(DiskError::InvalidTemplateRole { role })?;
    // (1) verify the admitted template content + size.
    let mut tfile = OpenOptions::new()
        .read(true)
        .write(false)
        .open(&template.path)
        .map_err(|source| DiskError::Unreadable {
            role,
            path: template.path.clone(),
            source,
        })?;
    let tmeta = tfile.metadata().map_err(|source| DiskError::Unreadable {
        role,
        path: template.path.clone(),
        source,
    })?;
    if !tmeta.is_file() {
        return Err(DiskError::NotRegularFile {
            role,
            path: template.path.clone(),
        });
    }
    let tsize = tmeta.len();
    if tsize == 0 || tsize % 512 != 0 {
        return Err(DiskError::BadSize {
            role,
            path: template.path.clone(),
            size: tsize,
        });
    }
    if tsize > cap {
        return Err(DiskError::TooLarge {
            role,
            path: template.path.clone(),
            size: tsize,
            cap,
        });
    }
    if tsize != template.template_bytes {
        return Err(DiskError::TemplateSizeMismatch {
            role,
            path: template.path.clone(),
            expected: template.template_bytes,
            actual: tsize,
        });
    }
    let (tactual, _) = sha256_stream(&mut tfile).map_err(|source| DiskError::Unreadable {
        role,
        path: template.path.clone(),
        source,
    })?;
    if tactual != template.template_sha256 {
        return Err(DiskError::TemplateHashMismatch {
            role,
            path: template.path.clone(),
            actual: tactual,
            expected: template.template_sha256.clone(),
        });
    }
    let template_dev_ino = (tmeta.dev(), tmeta.ino());

    // (2) F04: create the fresh inode at a UNIQUE attempt-exclusive staging name
    // inside the verified-private parent, keeping the parent descriptor in the
    // returned handle. A world-/group-writable output directory is refused here
    // (fail closed). Early returns close descriptors,
    // preserving its namespace entries and closing only owned descriptors.
    let (mut dest, mut handle) = create_attempt_output(role, dest_path)?;
    let dest_dev_ino = (handle.dev, handle.ino);

    // (4a) a distinct inode is required BEFORE we write a byte: if the staging
    // inode somehow coincided with the template inode (e.g. a pathological
    // same-inode template), refuse rather than mutate the base. On this early
    // return closes the handle and preserves staging residue.
    if dest_dev_ino == template_dev_ino {
        return Err(handle.failure(DiskError::FreshAliasesTemplate {
            role,
            dest: dest_path.to_string(),
            template: template.path.clone(),
        }));
    }

    #[cfg(test)]
    COPY_FAILURE_HOOK.with(|h| {
        if let Some(f) = h.borrow_mut().as_mut() {
            f();
        }
    });

    // (3) F03: copy through the ALREADY-VERIFIED descriptor `tfile`, NOT a
    // path re-open. An open descriptor is pinned to the inode we hashed, so a
    // path replacement (rename/unlink+create) between verification and copy
    // cannot swap in different bytes — the replacement window is closed. The
    // helper rewinds the verified descriptor, copies EXACTLY `template_bytes`,
    // and verifies both the copied digest and the final on-disk size against
    // the admitted identity (refusing truncation, growth and content swap).
    copy_exact_verified(
        &mut tfile,
        &mut dest,
        template.template_bytes,
        &template.template_sha256,
        role,
        &template.path,
        dest_path,
    )
    .map_err(|cause| handle.failure(cause))?;

    // Publication refuses a pre-existing destination; failures preserve staging.
    handle.publish().map_err(|cause| handle.failure(cause))?;

    Ok((
        AttachedDiskV3 {
            role,
            path: dest_path.to_string(),
            read_only: false,
            measured: true, // the ADMITTED TEMPLATE is measured; the copy is fresh
            observed_sha256: None, // the fresh RW content is the template; see template_sha256
            template_sha256: Some(template.template_sha256.clone()),
            template_bytes: Some(template.template_bytes),
            bytes: tsize,
            file: dest,
        },
        handle,
    ))
}

/// F04 — create the attempt-owned CONSOLE output (a fresh empty file) under the
/// same enforced private-directory boundary as the disk outputs: a unique
/// staging inode in the verified-private parent, published atomically to the
/// admitted name, with the retained [`OutputHandle`] returned for explicit
/// deferred residue reporting on a later refusal. Returns file and handle.
pub fn create_console_output(path: &str) -> Result<(File, OutputHandle), DiskError> {
    let (file, mut handle) = create_attempt_output(DiskRole::Result, path)?;
    handle.publish().map_err(|cause| handle.failure(cause))?;
    Ok((file, handle))
}

/// vde: OPTIONAL genuinely UNMEASURED read-only private input. Opened O_RDONLY,
/// bounded (regular, non-zero 512-multiple, <= 1 GiB), inode retained — but its
/// content is NEVER hashed. No digest is produced here, and the caller MUST NOT
/// place any vde content digest in the spec, receipt, trace or diagnostics.
pub fn open_private_unmeasured(path: &str) -> Result<AttachedDiskV3, PrivateInputError> {
    let role = DiskRole::PrivateInput;
    // F05: every failure below maps to a REDACTED PrivateInputError carrying
    // only the failed policy rule — never the image's path, size or errno.
    let file = OpenOptions::new()
        .read(true)
        .write(false)
        .open(path)
        .map_err(|_| PrivateInputError::Unreadable)?;
    let meta = file.metadata().map_err(|_| PrivateInputError::Unreadable)?;
    if !meta.is_file() {
        return Err(PrivateInputError::NotRegularFile);
    }
    let size = meta.len();
    if size == 0 || size % PRIVATE_IMAGE_ALIGN != 0 {
        return Err(PrivateInputError::BadSize);
    }
    if size > PRIVATE_IMAGE_BYTES_MAX {
        return Err(PrivateInputError::TooLarge);
    }
    Ok(AttachedDiskV3 {
        role,
        path: path.to_string(),
        read_only: true,
        measured: false,
        observed_sha256: None, // NEVER hashed — unmeasured by construction
        template_sha256: None,
        template_bytes: None,
        bytes: size,
        file,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn sha(b: &[u8]) -> String {
        format!("{:x}", Sha256::digest(b))
    }

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "dsmack-v3-disks-unit-{}-{}",
            tag,
            std::process::id()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn new_file(p: &std::path::Path, bytes: &[u8]) -> File {
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(p)
            .unwrap();
        f.write_all(bytes).unwrap();
        f.flush().unwrap();
        f
    }

    // F03: copying through the verified descriptor produces the admitted bytes,
    // and rewinds the source itself (even if its cursor was at EOF).
    #[test]
    fn copy_exact_verified_happy_path_rewinds_and_matches() {
        let d = tmpdir("copy-ok");
        let content = vec![0xABu8; 4096];
        let mut src = new_file(&d.join("src"), &content); // cursor at EOF
        let mut dest = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(d.join("dest"))
            .unwrap();
        copy_exact_verified(
            &mut src,
            &mut dest,
            content.len() as u64,
            &sha(&content),
            DiskRole::Result,
            "src",
            "dest",
        )
        .expect("verified copy");
        let mut got = Vec::new();
        src.seek(SeekFrom::Start(0)).unwrap();
        let mut back = OpenOptions::new().read(true).open(d.join("dest")).unwrap();
        back.read_to_end(&mut got).unwrap();
        assert_eq!(sha(&got), sha(&content));
        let _ = std::fs::remove_dir_all(&d);
    }

    // F03 replacement coverage: if the bytes read differ from the admitted
    // identity (as a bytes-for-bytes replacement after admission would make
    // them), the copy is refused — the copied content is checked, not trusted.
    #[test]
    fn copy_exact_verified_refuses_content_swap() {
        let d = tmpdir("copy-swap");
        let actual = vec![0x01u8; 2048];
        let admitted_other = sha(&vec![0x02u8; 2048]); // same length, different bytes
        let mut src = new_file(&d.join("src"), &actual);
        let mut dest = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(d.join("dest"))
            .unwrap();
        let e = copy_exact_verified(
            &mut src,
            &mut dest,
            actual.len() as u64,
            &admitted_other,
            DiskRole::Scratch,
            "src",
            "dest",
        )
        .unwrap_err();
        assert!(matches!(e, DiskError::CopiedContentMismatch { .. }));
        let _ = std::fs::remove_dir_all(&d);
    }

    // F03: a source shorter than the admitted length is a truncation refusal.
    #[test]
    fn copy_exact_verified_refuses_truncation() {
        let d = tmpdir("copy-trunc");
        let actual = vec![0x7u8; 1024];
        let mut src = new_file(&d.join("src"), &actual);
        let mut dest = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(d.join("dest"))
            .unwrap();
        let e = copy_exact_verified(
            &mut src,
            &mut dest,
            2048, // want more than src holds
            &sha(&actual),
            DiskRole::Result,
            "src",
            "dest",
        )
        .unwrap_err();
        assert!(matches!(
            e,
            DiskError::CopiedLengthMismatch {
                kind: "truncated before admitted length",
                ..
            }
        ));
        let _ = std::fs::remove_dir_all(&d);
    }

    // F03: a source that GREW past the admitted length (trailing bytes after
    // the admitted identity was fixed) is refused — the admitted source length
    // is enforced THROUGH completion, not only across the first `want` bytes.
    // The first `want` bytes hash correctly, so the refusal is specifically the
    // trailing-growth check, not a content mismatch.
    #[test]
    fn copy_exact_verified_refuses_source_growth_past_admitted_length() {
        let d = tmpdir("copy-grow");
        let admitted = vec![0x5Au8; 2048];
        let mut full = admitted.clone();
        full.extend_from_slice(&[0x5Au8; 512]); // source grew by 512 trailing bytes
        let mut src = new_file(&d.join("src"), &full);
        let mut dest = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(d.join("dest"))
            .unwrap();
        let e = copy_exact_verified(
            &mut src,
            &mut dest,
            admitted.len() as u64,
            &sha(&admitted), // first `want` bytes hash correctly
            DiskRole::Result,
            "src",
            "dest",
        )
        .unwrap_err();
        assert!(
            matches!(e, DiskError::SourceGrewDuringCopy { .. }),
            "expected SourceGrewDuringCopy, got {e:?}"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    // F03: the exact-length happy path still accepts a source that is EXACTLY
    // the admitted length (clean EOF right at `want`): the growth guard must not
    // reject a correctly-sized source.
    #[test]
    fn copy_exact_verified_accepts_exact_length_source() {
        let d = tmpdir("copy-exact");
        let content = vec![0x33u8; 4096];
        let mut src = new_file(&d.join("src"), &content);
        let mut dest = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(d.join("dest"))
            .unwrap();
        copy_exact_verified(
            &mut src,
            &mut dest,
            content.len() as u64,
            &sha(&content),
            DiskRole::Result,
            "src",
            "dest",
        )
        .expect("exact-length source accepted");
        let _ = std::fs::remove_dir_all(&d);
    }

    use std::ffi::CString;

    fn cname(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    #[test]
    fn deferred_cleanup_preserves_foreign_tomb_and_original() {
        let d = tmpdir("deferred-foreign");
        let (_file, h) =
            create_attempt_output(DiskRole::Result, d.join("slot").to_str().unwrap()).unwrap();
        let staging = d.join(h.name.to_str().unwrap());
        let tomb = d.join(".tomb.foreign");
        new_file(&tomb, b"foreign-tomb");
        new_file(&d.join("slot"), b"foreign-original");
        assert!(h.require_residue_free().is_err());
        drop(h);
        assert_eq!(std::fs::read(&tomb).unwrap(), b"foreign-tomb");
        assert_eq!(std::fs::read(d.join("slot")).unwrap(), b"foreign-original");
        assert!(staging.exists());
    }

    // F04 — PARENT SUBSTITUTION defeated by the RETAINED directory descriptor.
    // After the private parent is validated and its descriptor retained, the
    // pathname is repointed at a DECOY directory. The retained-dirfd create/clean
    // follows the real (now-moved) directory inode; a path-re-resolving operation
    // (the rejected baseline, which "creates outputs through their full paths")
    // would instead act inside the attacker's decoy. Both are shown.
    #[test]
    fn parent_substitution_is_defeated_by_retained_dirfd() {
        let d = tmpdir("parent-sub");
        let real = d.join("real-parent");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        // Retain the verified-private parent descriptor (as create_attempt_output does).
        let dir = open_private_dir(&real).unwrap();
        // Parent substitution: move the real dir aside and drop a DECOY at its path.
        let moved = d.join("real-parent-moved");
        std::fs::rename(&real, &moved).unwrap();
        let decoy = &real; // same path, attacker-controlled dir
        std::fs::create_dir_all(decoy).unwrap();
        std::fs::set_permissions(decoy, std::fs::Permissions::from_mode(0o700)).unwrap();

        // RETAINED dirfd: openat creates inside the REAL (moved) directory inode.
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                cname("via-dirfd").as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
                0o600,
            )
        };
        assert!(fd >= 0);
        unsafe { libc::close(fd) };
        assert!(
            moved.join("via-dirfd").exists(),
            "retained dirfd follows the real moved directory"
        );
        assert!(
            !decoy.join("via-dirfd").exists(),
            "retained dirfd never writes into the decoy"
        );

        // PATH re-resolution (the rejected baseline behaviour): lands in the DECOY.
        let _ = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(real.join("via-path"))
            .unwrap();
        assert!(
            decoy.join("via-path").exists(),
            "path re-resolution lands in the attacker decoy"
        );
        assert!(!moved.join("via-path").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    // F04: ADMISSION failure — a fresh output whose parent directory is
    // group/other-writable (the replacement-attack surface) is refused BEFORE
    // any inode is created, and the base template is never touched.
    #[test]
    fn fresh_copy_refuses_uncontrolled_output_dir() {
        let d = tmpdir("uncontrolled");
        // A deliberately world-writable output directory (sticky-tmp-like).
        let out = d.join("world-writable-out");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o777)).unwrap();
        let tmpl_bytes = vec![0u8; 2048];
        let tmpl = d.join("result-template.img");
        new_file(&tmpl, &tmpl_bytes);
        let template = AdmittedTemplate {
            path: tmpl.to_str().unwrap().to_string(),
            template_sha256: sha(&tmpl_bytes),
            template_bytes: 2048,
        };
        let dest = out.join("vdd-result.img");
        let e = create_fresh_from_template(DiskRole::Result, dest.to_str().unwrap(), &template)
            .err()
            .expect("world-writable output dir must be refused");
        assert!(
            matches!(e, DiskError::UncontrolledOutputDir { .. }),
            "world-writable output dir must be refused, got {e}"
        );
        assert!(
            !dest.exists(),
            "no fresh inode may be created in an uncontrolled dir"
        );
        assert!(tmpl.exists(), "base template must be preserved");
        // create_console_output refuses identically (same boundary).
        assert!(matches!(
            create_console_output(dest.to_str().unwrap()).err(),
            Some(DiskError::UncontrolledOutputDir { .. })
        ));
        let _ = std::fs::remove_dir_all(&d);
    }

    // Dropping a failed partial copy retains its namespace entry.
    #[test]
    fn partial_copy_abort_defers_residue_preserves_base() {
        let d = tmpdir("partial-abort");
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        let base = d.join("base-template.img");
        new_file(&base, &vec![0u8; 512]);
        let staging_name;
        {
            // A dropped handle closes descriptors without deleting partial output.
            let (file, handle) = create_attempt_output(
                DiskRole::Result,
                d.join("vdd-partial.img").to_str().unwrap(),
            )
            .unwrap();
            staging_name = handle.name.clone();
            drop(file);
            // the staging inode exists under its unique name right now
            let sp = d.join(staging_name.to_str().unwrap());
            assert!(sp.exists(), "staging inode present before abort");
            drop(handle);
            assert!(
                sp.exists(),
                "Drop defers residue without destructive namespace operations"
            );
        }
        assert!(base.exists(), "base asset is never touched by cleanup");
        // the admitted name was never published on the abort path
        assert!(!d.join("vdd-partial.img").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    // F04: publish lands at the admitted name and refuses a pre-existing object
    // (fresh-inode requirement) without clobbering it.
    #[test]
    fn publish_is_atomic_and_refuses_preexisting() {
        let d = tmpdir("publish");
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        // happy publish
        {
            let (mut f, mut h) =
                create_attempt_output(DiskRole::Scratch, d.join("out.img").to_str().unwrap())
                    .unwrap();
            f.write_all(b"fresh").unwrap();
            h.publish().expect("publish");
            assert!(d.join("out.img").exists(), "published at the admitted name");
        }
        // pre-existing admitted object: publish refuses, never clobbers.
        {
            let pre = d.join("taken.img");
            new_file(&pre, b"PRE-EXISTING MUST SURVIVE");
            let (_f, mut h) =
                create_attempt_output(DiskRole::Scratch, pre.to_str().unwrap()).unwrap();
            let e = h
                .publish()
                .err()
                .expect("pre-existing admitted object refused");
            assert!(matches!(e, DiskError::FreshPreExisting { .. }), "got {e}");
            drop(h); // staging retained
            let mut got = String::new();
            OpenOptions::new()
                .read(true)
                .open(&pre)
                .unwrap()
                .read_to_string(&mut got)
                .unwrap();
            assert_eq!(
                got, "PRE-EXISTING MUST SURVIVE",
                "pre-existing object never clobbered"
            );
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    // F05: vde rejection diagnostics expose ONLY the failed policy rule — never
    // the image's size, path, or errno across every rejection surface.
    #[test]
    fn private_input_rejections_are_redacted() {
        let d = tmpdir("vde-redact");
        // odd size (not 512-aligned)
        let odd = d.join("odd-7919-bytes.img");
        new_file(&odd, &vec![0u8; 7919]);
        let e = open_private_unmeasured(odd.to_str().unwrap()).unwrap_err();
        assert_eq!(e, PrivateInputError::BadSize);
        // nonregular (a directory)
        let dir = d.join("adir");
        std::fs::create_dir_all(&dir).unwrap();
        let e2 = open_private_unmeasured(dir.to_str().unwrap()).unwrap_err();
        assert_eq!(e2, PrivateInputError::NotRegularFile);
        // unreadable (absent path)
        let e3 = open_private_unmeasured(d.join("nope.img").to_str().unwrap()).unwrap_err();
        assert_eq!(e3, PrivateInputError::Unreadable);

        // Across EVERY rejection: the PRIVATE image's own size and path never
        // appear. Public policy constants (e.g. the "512" alignment) MAY appear
        // — they are not private facts. The rejected image's size (7919) and
        // any path separator must not.
        for e in [
            PrivateInputError::Unreadable,
            PrivateInputError::NotRegularFile,
            PrivateInputError::BadSize,
            PrivateInputError::TooLarge,
        ] {
            let msg = format!("{e}");
            assert!(
                !msg.contains("7919"),
                "the rejected image's own size must never appear: {msg}"
            );
            assert!(
                !msg.contains('/'),
                "redacted vde diagnostic must contain no path: {msg}"
            );
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn partial_copy_failure_reports_residue_from_actual_caller() {
        let d = tmpdir("partial-error");
        let template = d.join("template");
        new_file(&template, &vec![0; 1024]);
        let t2 = template.clone();
        COPY_FAILURE_HOOK.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                OpenOptions::new()
                    .write(true)
                    .open(&t2)
                    .unwrap()
                    .set_len(512)
                    .unwrap();
            }))
        });
        let result = create_fresh_from_template(
            DiskRole::Result,
            d.join("out").to_str().unwrap(),
            &AdmittedTemplate {
                path: template.to_str().unwrap().into(),
                template_sha256: sha(&vec![0; 1024]),
                template_bytes: 1024,
            },
        );
        COPY_FAILURE_HOOK.with(|h| *h.borrow_mut() = None);
        match result.unwrap_err() {
            DiskError::DeferredCleanup { cause, residue } => {
                assert!(matches!(*cause, DiskError::CopiedLengthMismatch { .. }));
                assert_eq!(std::fs::read(d.join(residue.name)).unwrap().len(), 512);
            }
            other => panic!("missing explicit residue: {other}"),
        }
    }
    #[test]
    fn deferred_cleanup_preserves_both_foreign_restore_occupants() {
        let d = tmpdir("deferred-restore");
        let (_file, h) =
            create_attempt_output(DiskRole::Result, d.join("slot").to_str().unwrap()).unwrap();
        new_file(&d.join(".foreign-A-at-tomb"), b"foreign-A");
        new_file(&d.join("slot"), b"foreign-B");
        let outcome = h.require_residue_free().unwrap_err();
        assert!(d.join(&outcome.name).exists());
        drop(h);
        assert_eq!(
            std::fs::read(d.join(".foreign-A-at-tomb")).unwrap(),
            b"foreign-A"
        );
        assert_eq!(std::fs::read(d.join("slot")).unwrap(), b"foreign-B");
    }
}

#[cfg(test)]
mod template_role_capacity_tests {
    use super::*;
    #[test]
    fn only_scratch_has_expanded_capacity() {
        assert_eq!(template_bytes_max(DiskRole::Scratch), Some(4 << 30));
        assert_eq!(template_bytes_max(DiskRole::Result), Some(1 << 30));
        for role in [DiskRole::System, DiskRole::Workload, DiskRole::PrivateInput] {
            assert_eq!(template_bytes_max(role), None);
            let template = AdmittedTemplate { path: "/absent-template".into(), template_sha256: "0".repeat(64), template_bytes: 512 };
            assert!(matches!(create_fresh_from_template(role, "/absent-output", &template), Err(DiskError::InvalidTemplateRole { .. })));
        }
        assert_eq!(PRIVATE_IMAGE_BYTES_MAX, 1 << 30);
    }
}
