//! R06 — checked result/console finalization primitives (ACTUAL Rust).
//!
//! This module is the concrete Rust realization of the normative executable
//! model `io-contract-reference/candidate/runresult_ref/finalize.py`. It is
//! the code that the libkrun block/HVF source changes lift verbatim (see
//! `source-changes/`): the ordered finalization state machine, the retained
//! descriptor dup/identity rules, the bounded chunked pread, and the exact
//! console cap. It is EXERCISED on host Linux against real descriptors and a
//! mock storage layer (no VM/HVF), so every R06 invariant is unit-proven.
//!
//! Actual Rust layers named by the source-change contract (SPEC §4/§10):
//!   (1) imago `FormatAccess` flush()/sync() — OWNS the I/O descriptor; its
//!       results MUST be propagated (not logged-and-dropped as
//!       `DiskProperties::drop` does today).
//!   (2) a new `DiskProperties::finalize_checked()` runs that checked flush +
//!       sync BEFORE any drop and returns `Result`.
//!   (3) `Block::on_vmm_exit_checked` calls it and propagates the error.
//!   (4) the HVF consumption then syncs the RETAINED descriptor and hashes it
//!       — ONLY after the storage layer reported success (a host fsync cannot
//!       retroactively prove a failed userspace flush wrote anything).
//!   (5) the fstat (st_dev, st_ino) of the descriptor the device ACTUALLY
//!       performs I/O through must equal the retained/hash descriptor; a
//!       matching digest over a path RE-OPEN is NOT acceptance.
//!   (6) F_DUPFD_CLOEXEC duplicates PRESERVE the access mode (one shared
//!       open-file description); a retained duplicate of a read-write result
//!       file is READ-WRITE — stated honestly, relied on via pread only.

use std::io::Write;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

/// pread chunk size — matches finalize.py `_CHUNK`.
pub const RESULT_CHUNK_BYTES: usize = 1 << 20;
/// Console writer hard cap (protocol.MAX_CONSOLE_BYTES). Exact; see slack.
pub const MAX_CONSOLE_BYTES: u64 = 16 * 1024 * 1024;
/// CONSOLE_SLACK_BYTES == 0: the limiter truncates the final write, so the
/// final console size is <= MAX_CONSOLE_BYTES EXACTLY — no undefined
/// write-granularity slack (closes astra-gate R06 console wording).
pub const CONSOLE_SLACK_BYTES: u64 = 0;
/// Upper bound on an admitted result template (protocol.RESULT_TEMPLATE_BYTES_MAX).
pub const RESULT_TEMPLATE_BYTES_MAX: u64 = 1 << 30;
/// Whole-finalization deadline (protocol.FINALIZE_DEADLINE_SECONDS). This bounds
/// when the finalize CALL returns — it is ENFORCED by an independent watchdog
/// thread (see [`supervise_finalize`]), not by cooperative checks a blocked
/// syscall could never observe.
pub const FINALIZE_DEADLINE_SECONDS: u64 = 600;
/// Cadence at which the supervisor re-checks the external cancel flag while
/// waiting on the finalize worker. The deadline itself is the hard bound; this
/// only governs cancel-responsiveness, so it is a small fixed slice.
pub const SUPERVISE_POLL_MILLIS: u64 = 50;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum FinalizeError {
    #[error("dup preserved-access-mode check failed: original {orig:#o} != dup {dup:#o}")]
    DupAccessModeChanged { orig: i32, dup: i32 },
    #[error("fcntl {op} failed: errno {errno}")]
    Fcntl { op: &'static str, errno: i32 },
    #[error("storage-layer flush failed before destruction: {0}")]
    StorageFlushFailed(String),
    #[error("storage-layer sync failed before destruction: {0}")]
    StorageSyncFailed(String),
    #[error("retained-descriptor fsync failed: {0}")]
    RetainedSyncFailed(String),
    #[error("result size mismatch: fstat {size} != admitted template {template}")]
    ResultSizeMismatch { size: u64, template: u64 },
    #[error("result template {0} bytes exceeds cap {RESULT_TEMPLATE_BYTES_MAX}")]
    ResultTooLarge(u64),
    #[error(
        "descriptor identity mismatch: I/O fd ({io_dev},{io_ino}) != retained fd ({r_dev},{r_ino}) \
         — a path re-open is NOT the verified inode"
    )]
    DescriptorIdentityMismatch {
        io_dev: u64,
        io_ino: u64,
        r_dev: u64,
        r_ino: u64,
    },
    #[error("short read at offset {offset}: wanted {want} got {got}")]
    ShortRead {
        offset: u64,
        want: usize,
        got: usize,
    },
    #[error("pread failed at offset {offset}: errno {errno}")]
    Pread { offset: u64, errno: i32 },
    #[error("fstat failed: errno {0}")]
    Fstat(i32),
    #[error("finalization cancelled")]
    Cancelled,
    #[error("finalization exceeded the {FINALIZE_DEADLINE_SECONDS}s deadline")]
    DeadlineExceeded,
    #[error("finalize refused: the guest lifecycle has not reached a proven halt (run must complete first)")]
    NotHalted,
    #[error("finalize refused: the run already finalized; the result is single-shot and is now invalidated")]
    AlreadyFinalized,
    #[error("finalize refused: lifecycle latched a prior teardown fault: {0}")]
    LifecycleFault(String),
}

/// The storage layer the Imago `FormatAccess` presents: flush()/sync() must be
/// CHECKED and propagated, and it must report the descriptor it ACTUALLY
/// performs I/O through (R06 (1),(5)). On the real backend this is implemented
/// for the imago device; here it is a trait so the checked-before-destruction
/// contract is proven with injectable failures exactly as finalize.py models.
pub trait ResultStorage {
    fn flush_checked(&mut self) -> Result<(), FinalizeError>;
    fn sync_checked(&mut self) -> Result<(), FinalizeError>;
    /// The raw fd the storage ACTUALLY performs I/O through — the identity
    /// source the retained hash descriptor is checked against.
    fn io_fd(&self) -> RawFd;
}

fn accmode(fd: RawFd) -> Result<i32, FinalizeError> {
    // SAFETY: F_GETFL on a valid fd has no memory effects.
    let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if fl < 0 {
        return Err(FinalizeError::Fcntl {
            op: "F_GETFL",
            errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
        });
    }
    Ok(fl & libc::O_ACCMODE)
}

/// Retained duplicate via F_DUPFD_CLOEXEC (min fd 3). The duplicate SHARES the
/// open-file description, so the access mode is PRESERVED — this is verified,
/// and a read-write result file yields a read-write duplicate. We do NOT claim
/// an O_RDONLY reopen; the duplicate is used for pread only (R06 (6)).
pub fn dup_retained(fd: BorrowedFd<'_>) -> Result<OwnedFd, FinalizeError> {
    let raw = fd.as_raw_fd();
    let orig = accmode(raw)?;
    // SAFETY: F_DUPFD_CLOEXEC returns a fresh owned descriptor or -1.
    let dup = unsafe { libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, 3) };
    if dup < 0 {
        return Err(FinalizeError::Fcntl {
            op: "F_DUPFD_CLOEXEC",
            errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
        });
    }
    let dup_mode = match accmode(dup) {
        Ok(m) => m,
        Err(e) => {
            // SAFETY: dup is a fresh descriptor we own and are abandoning.
            unsafe { libc::close(dup) };
            return Err(e);
        }
    };
    if dup_mode != orig {
        // SAFETY: closing the fresh descriptor we just created.
        unsafe { libc::close(dup) };
        return Err(FinalizeError::DupAccessModeChanged {
            orig,
            dup: dup_mode,
        });
    }
    // SAFETY: `dup` is a fresh, valid, owned descriptor from F_DUPFD_CLOEXEC.
    Ok(unsafe { OwnedFd::from_raw_fd(dup) })
}

fn fstat_dev_ino(fd: RawFd) -> Result<(u64, u64), FinalizeError> {
    // SAFETY: fstat writes into a zeroed stat we own.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(FinalizeError::Fstat(
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
        ));
    }
    Ok((st.st_dev as u64, st.st_ino as u64))
}

fn fstat_size(fd: RawFd) -> Result<u64, FinalizeError> {
    // SAFETY: fstat writes into a zeroed stat we own.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(FinalizeError::Fstat(
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
        ));
    }
    Ok(st.st_size as u64)
}

/// True iff both descriptors resolve to the same (st_dev, st_ino) — i.e. the
/// retained descriptor is the verified inode, not a path re-open.
pub fn same_inode(a: RawFd, b: RawFd) -> Result<bool, FinalizeError> {
    Ok(fstat_dev_ino(a)? == fstat_dev_ino(b)?)
}

/// Offset-explicit chunked pread over EXACTLY `exact_bytes`; a short read is a
/// refusal (never a silent partial digest). `cancel` is polled each chunk so a
/// cooperative cancellation is observed within one chunk; the deadline is
/// checked each chunk as a best-effort cooperative stop. The ENFORCED whole-hash
/// bound is the watchdog in [`supervise_finalize`] — a chunk that blocks in
/// `pread` cannot observe these cooperative checks, so the watchdog (not this
/// loop) is what guarantees the call returns.
pub fn pread_sha256(
    fd: RawFd,
    exact_bytes: u64,
    mut cancel: impl FnMut() -> bool,
    deadline: Option<std::time::Instant>,
) -> Result<String, FinalizeError> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; RESULT_CHUNK_BYTES];
    let mut offset: u64 = 0;
    // F08: honor cancellation and the deadline even for an empty hash
    // (exact_bytes == 0), where the chunk loop body never runs.
    if cancel() {
        return Err(FinalizeError::Cancelled);
    }
    if let Some(d) = deadline {
        if std::time::Instant::now() >= d {
            return Err(FinalizeError::DeadlineExceeded);
        }
    }
    while offset < exact_bytes {
        if cancel() {
            return Err(FinalizeError::Cancelled);
        }
        if let Some(d) = deadline {
            if std::time::Instant::now() >= d {
                return Err(FinalizeError::DeadlineExceeded);
            }
        }
        let want = std::cmp::min(RESULT_CHUNK_BYTES as u64, exact_bytes - offset) as usize;
        // SAFETY: buf is at least `want` bytes; pread reads into it at the
        // explicit offset and touches no other memory.
        let got = unsafe {
            libc::pread(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                want,
                offset as libc::off_t,
            )
        };
        if got < 0 {
            return Err(FinalizeError::Pread {
                offset,
                errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            });
        }
        let got = got as usize;
        if got != want {
            return Err(FinalizeError::ShortRead { offset, want, got });
        }
        hasher.update(&buf[..want]);
        offset += want as u64;
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// The result of a successful finalization — the exact fields the run-result
/// envelope's `result_disk` carries (protocol.ENVELOPE_RESULT_DISK_KEYS:
/// sha256, bytes; template_sha256/template_bytes/role are set by the caller
/// from the admitted template).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultDigest {
    pub result_sha256: String,
    pub result_bytes: u64,
    /// Ordered step trail — the normative order is asserted in tests.
    pub steps: Vec<&'static str>,
}

/// Ordered checked finalization of the vdd result inode. Order is NORMATIVE
/// (matches finalize.py `FinalizeModel.run`):
///   stop_writers -> storage_flush_checked -> retained_sync ->
///   fstat_size_check -> identity_check -> hash -> outcome
/// A failure at ANY step is a refusal; no digest/outcome is produced. The
/// caller MUST have already stopped the writers (joined the block worker) —
/// that is step 0 and is the backend's `on_vmm_exit_checked` responsibility.
///
/// `retained` is the descriptor duplicated from the I/O descriptor at attach
/// time (via [`dup_retained`]); `template_bytes` is the admitted fixed size.
pub fn finalize_result<S: ResultStorage>(
    storage: &mut S,
    retained: &OwnedFd,
    template_bytes: u64,
    mut cancel: impl FnMut() -> bool,
    deadline: Option<std::time::Instant>,
) -> Result<ResultDigest, FinalizeError> {
    if template_bytes > RESULT_TEMPLATE_BYTES_MAX {
        return Err(FinalizeError::ResultTooLarge(template_bytes));
    }
    let mut steps: Vec<&'static str> = Vec::with_capacity(6);
    // (0) writers already stopped by the caller (bounded worker join).
    steps.push("stop_writers");
    if cancel() {
        return Err(FinalizeError::Cancelled);
    }
    // F08: the deadline is re-checked (cooperatively) immediately before the
    // blocking storage flush/sync and retained fsync — but a flush/sync/fsync
    // that BLOCKS cannot observe this check, which is exactly why this function
    // is driven under [`supervise_finalize`]: that watchdog bounds the whole
    // call from an INDEPENDENT thread and fails closed on timeout with safe
    // descriptor ownership. A cancellation requested while the writers were
    // stopping is observed here too.
    if let Some(d) = deadline {
        if std::time::Instant::now() >= d {
            return Err(FinalizeError::DeadlineExceeded);
        }
    }
    if cancel() {
        return Err(FinalizeError::Cancelled);
    }
    // (1)+(2)+(3) CHECKED storage-layer flush/sync BEFORE destruction. A
    // failure here is a refusal — never logged-and-dropped the way
    // DiskProperties::drop does. Drop logging is NOT success.
    storage.flush_checked()?;
    storage.sync_checked()?;
    steps.push("storage_flush_checked");
    // (4) retained-descriptor fsync, separately checked, AFTER the storage
    // layer reported success. Deadline re-checked around this blocking sync.
    if let Some(d) = deadline {
        if std::time::Instant::now() >= d {
            return Err(FinalizeError::DeadlineExceeded);
        }
    }
    let rfd = retained.as_raw_fd();
    if unsafe { libc::fsync(rfd) } != 0 {
        return Err(FinalizeError::RetainedSyncFailed(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    steps.push("retained_sync");
    // fixed-size check: the result inode is the template image written in
    // place, so its final size is exactly the admitted template size.
    let size = fstat_size(rfd)?;
    if size != template_bytes {
        return Err(FinalizeError::ResultSizeMismatch {
            size,
            template: template_bytes,
        });
    }
    steps.push("fstat_size_check");
    // (5) identity: the descriptor the device performed I/O through must be
    // the same inode as the retained hash descriptor. A path re-open with a
    // swapped inode is refused here — the matching-digest-over-reopen attack.
    let io = fstat_dev_ino(storage.io_fd())?;
    let r = fstat_dev_ino(rfd)?;
    if io != r {
        return Err(FinalizeError::DescriptorIdentityMismatch {
            io_dev: io.0,
            io_ino: io.1,
            r_dev: r.0,
            r_ino: r.1,
        });
    }
    steps.push("identity_check");
    // hash the EXACT template_bytes through the retained descriptor via
    // offset-explicit chunked pread (short read = refusal).
    let result_sha256 = pread_sha256(rfd, template_bytes, &mut cancel, deadline)?;
    steps.push("hash");
    Ok(ResultDigest {
        result_sha256,
        result_bytes: template_bytes,
        steps,
    })
}

/// F08 — INDEPENDENT whole-finalization watchdog. The reviewer's defect is that
/// `finalize_result`/`finalize_console` perform synchronous flush/sync/fsync and
/// reads between COOPERATIVE deadline checks, so a BLOCKED operation (stuck
/// storage, hung fsync, unresponsive device) can never observe the deadline and
/// the "hard ceiling" was therefore unsupported. This supervisor runs the whole
/// blocking finalization on a SEPARATE worker thread and bounds the CALL from an
/// independent thread:
///
///   * the worker OWNS everything it touches (the `work` closure moves in its
///     storage and its retained descriptors), so on timeout we can walk away
///     WITHOUT closing anything out from under a still-blocked syscall;
///   * the supervisor waits on a channel until the absolute `deadline`; it also
///     polls `external_cancel` every [`SUPERVISE_POLL_MILLIS`] so a cooperative
///     cancellation is honored promptly;
///   * on `deadline` expiry (or external cancel) it returns fail-closed
///     (`DeadlineExceeded`/`Cancelled`) and DETACHES the worker: dropping the
///     `JoinHandle` lets the thread run to completion still owning its
///     descriptors (SAFE OWNERSHIP on timeout — the fds are never freed into a
///     reuse race; they are released only when the blocked op finally returns).
///
/// The guarantee is therefore honest and enforceable: the finalize CALL returns
/// within `deadline` (+ one poll slice) regardless of a blocked operation, and
/// NO result is produced on timeout. It does not claim to abort an uninterruptible
/// kernel operation — it bounds the caller and quarantines the blocked work.
pub fn supervise_finalize<T, F>(
    deadline: std::time::Instant,
    mut external_cancel: impl FnMut() -> bool,
    work: F,
) -> Result<T, FinalizeError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, FinalizeError> + Send + 'static,
{
    use std::sync::mpsc::{self, RecvTimeoutError};
    let (tx, rx) = mpsc::channel::<Result<T, FinalizeError>>();
    // The worker owns `work` (and everything it captured). We retain its handle
    // ONLY so a timely completion can join cleanly; on timeout we drop it, which
    // detaches the thread — it keeps running and keeps owning its descriptors.
    let handle = std::thread::spawn(move || {
        let _ = tx.send(work());
    });
    loop {
        let now = std::time::Instant::now();
        if now >= deadline {
            drop(handle); // detach: worker keeps safe ownership of its fds
            return Err(FinalizeError::DeadlineExceeded);
        }
        if external_cancel() {
            drop(handle);
            return Err(FinalizeError::Cancelled);
        }
        let slice = std::time::Duration::from_millis(SUPERVISE_POLL_MILLIS)
            .min(deadline.saturating_duration_since(now));
        match rx.recv_timeout(slice) {
            Ok(result) => {
                // Worker finished within the bound; join it so no thread leaks.
                let _ = handle.join();
                return result;
            }
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => {
                // Worker panicked without sending; surface as a fault, join to
                // observe the panic and avoid a leak.
                let _ = handle.join();
                return Err(FinalizeError::RetainedSyncFailed(
                    "finalize worker terminated without a result".into(),
                ));
            }
        }
    }
}

/// Byte-exact executable model of the libkrun console write limiter (R06).
/// The final console file is <= MAX_CONSOLE_BYTES EXACTLY: the final write is
/// truncated to the remaining budget; once remaining == 0 every write is
/// dropped and `truncated` latches true. CONSOLE_SLACK_BYTES == 0.
#[derive(Debug)]
pub struct ConsoleLimiter {
    cap: u64,
    written: u64,
    truncated: bool,
}

impl ConsoleLimiter {
    pub fn new() -> Self {
        Self {
            cap: MAX_CONSOLE_BYTES,
            written: 0,
            truncated: false,
        }
    }
    pub fn with_cap(cap: u64) -> Self {
        Self {
            cap,
            written: 0,
            truncated: false,
        }
    }
    /// Admit the prefix of `chunk` that fits the remaining budget; returns the
    /// admitted length. Latches `truncated` if any byte was dropped.
    pub fn admit(&mut self, chunk_len: u64) -> u64 {
        let remaining = self.cap.saturating_sub(self.written);
        let kept = std::cmp::min(remaining, chunk_len);
        if kept < chunk_len {
            self.truncated = true;
        }
        self.written += kept;
        kept
    }
    pub fn written(&self) -> u64 {
        self.written
    }
    pub fn truncated(&self) -> bool {
        self.truncated
    }
    pub fn limit_bytes(&self) -> u64 {
        self.cap
    }
}

impl Default for ConsoleLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// F08 — the ONE `Write` every console byte must pass through. It enforces the
/// exact cap on EVERY write: bytes beyond the cap are dropped (the guest keeps
/// running — a full console is not an I/O error) and `truncated()` latches.
/// The on-disk console is therefore <= MAX_CONSOLE_BYTES EXACTLY (zero slack),
/// and the run-result's `truncated` flag is this writer's latched state — never
/// a hardcoded `false`. On the native backend the krun returning-console sink
/// is wrapped in exactly this writer; on the host mock the same type is used,
/// so the limiter is proven end-to-end on real file I/O.
pub struct LimitedConsoleWriter<W: Write> {
    inner: W,
    limiter: ConsoleLimiter,
}

impl<W: Write> LimitedConsoleWriter<W> {
    pub fn new(inner: W) -> Self {
        Self { inner, limiter: ConsoleLimiter::new() }
    }
    pub fn with_cap(inner: W, cap: u64) -> Self {
        Self { inner, limiter: ConsoleLimiter::with_cap(cap) }
    }
    pub fn truncated(&self) -> bool {
        self.limiter.truncated()
    }
    pub fn written(&self) -> u64 {
        self.limiter.written()
    }
    pub fn into_inner(self) -> W {
        self.inner
    }
    pub fn get_ref(&self) -> &W {
        &self.inner
    }
}

impl<W: Write> Write for LimitedConsoleWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let admit = self.limiter.admit(buf.len() as u64) as usize;
        if admit > 0 {
            self.inner.write_all(&buf[..admit])?;
        }
        // The dropped suffix is discarded by cap policy, not an I/O short write:
        // report the whole length as accepted so callers do not spin retrying.
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Final console fields (protocol.ENVELOPE_CONSOLE_KEYS): sha256, bytes,
/// truncated, limit_bytes. Hashes the EXACT final console bytes via chunked
/// pread (short read = refusal), bounded by the cap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsoleDigest {
    pub console_sha256: String,
    pub console_bytes: u64,
    pub truncated: bool,
    pub limit_bytes: u64,
}

/// Hash the final console file (a retained descriptor to the O_EXCL console
/// inode). `truncated` is carried from the limiter. Refuses if the final size
/// exceeds the cap (the limiter must have enforced it) or on a short read.
pub fn finalize_console(
    retained: &OwnedFd,
    truncated: bool,
    cancel: impl FnMut() -> bool,
    deadline: Option<std::time::Instant>,
) -> Result<ConsoleDigest, FinalizeError> {
    let fd = retained.as_raw_fd();
    let size = fstat_size(fd)?;
    if size > MAX_CONSOLE_BYTES + CONSOLE_SLACK_BYTES {
        return Err(FinalizeError::ResultTooLarge(size));
    }
    let console_sha256 = pread_sha256(fd, size, cancel, deadline)?;
    Ok(ConsoleDigest {
        console_sha256,
        console_bytes: size,
        truncated,
        limit_bytes: MAX_CONSOLE_BYTES,
    })
}
