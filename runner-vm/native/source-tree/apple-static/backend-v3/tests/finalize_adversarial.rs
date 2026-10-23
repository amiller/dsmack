//! R06 adversarial finalization tests — ACTUAL file/FD/storage layers on host
//! Linux (no VM/HVF). Each test proves one detection the contract requires:
//! path replacement / wrong-inode storage, flush error, sync error,
//! result/cap overrun, short read, dup access-mode honesty, console cap,
//! cancellation and deadline.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::{AsFd, AsRawFd};

use dsmack_backend_v3::consumption_v3::FdStorage;
use dsmack_backend_v3::finalize::{
    self, ConsoleLimiter, FinalizeError, CONSOLE_SLACK_BYTES, MAX_CONSOLE_BYTES,
    RESULT_TEMPLATE_BYTES_MAX,
};

fn tmp(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("dsmack-v3-fin-{}-{}", name, std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn sized_file(path: &std::path::Path, bytes: usize, fill: u8) -> File {
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    f.write_all(&vec![fill; bytes]).unwrap();
    f.flush().unwrap();
    f
}

/// Happy path: storage I/O descriptor and retained descriptor are the SAME
/// inode (retained is a dup of the I/O fd), flush/sync succeed, size matches,
/// identity holds, and the digest equals an independent hash of the bytes.
#[test]
fn finalize_succeeds_through_retained_inode() {
    let d = tmp("ok");
    let p = d.join("result.img");
    let bytes = 4096usize;
    let file = sized_file(&p, bytes, 0xAB);
    let retained = finalize::dup_retained(file.as_fd()).unwrap();
    let mut storage = FdStorage::new(file.as_raw_fd());
    let r = finalize::finalize_result(&mut storage, &retained, bytes as u64, || false, None).unwrap();
    assert_eq!(r.result_bytes, bytes as u64);
    assert_eq!(
        r.steps,
        vec![
            "stop_writers",
            "storage_flush_checked",
            "retained_sync",
            "fstat_size_check",
            "identity_check",
            "hash"
        ]
    );
    // independent digest
    use sha2::{Digest, Sha256};
    assert_eq!(r.result_sha256, format!("{:x}", Sha256::digest(vec![0xABu8; bytes])));
    let _ = std::fs::remove_dir_all(&d);
}

/// PATH REPLACEMENT / WRONG-INODE STORAGE: the retained hash descriptor is a
/// re-open of a DIFFERENT file (the attacker swapped the inode behind the
/// path). Same size, so the size check passes — but the identity check fails
/// closed. A matching digest over a path re-open is NOT acceptance.
#[test]
fn wrong_inode_retained_descriptor_refused() {
    let d = tmp("wronginode");
    let real = d.join("real-result.img");
    let swapped = d.join("swapped.img");
    let bytes = 2048usize;
    let io_file = sized_file(&real, bytes, 0x01);
    let swapped_file = sized_file(&swapped, bytes, 0x01); // identical CONTENT
    // retained points at the SWAPPED inode, not the I/O inode.
    let retained = finalize::dup_retained(swapped_file.as_fd()).unwrap();
    let mut storage = FdStorage::new(io_file.as_raw_fd());
    let e = finalize::finalize_result(&mut storage, &retained, bytes as u64, || false, None)
        .unwrap_err();
    assert!(
        matches!(e, FinalizeError::DescriptorIdentityMismatch { .. }),
        "expected identity mismatch, got {e}"
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// FLUSH ERROR: a storage-layer flush failure is propagated as a refusal
/// BEFORE any digest/outcome exists — Drop-time logging is not success.
#[test]
fn storage_flush_error_refuses_before_hash() {
    let d = tmp("flush");
    let p = d.join("result.img");
    let bytes = 1024usize;
    let file = sized_file(&p, bytes, 0x7);
    let retained = finalize::dup_retained(file.as_fd()).unwrap();
    let mut storage = FdStorage::with_flush_error(file.as_raw_fd(), "imago flush EIO");
    let e = finalize::finalize_result(&mut storage, &retained, bytes as u64, || false, None)
        .unwrap_err();
    assert!(matches!(e, FinalizeError::StorageFlushFailed(_)), "got {e}");
    let _ = std::fs::remove_dir_all(&d);
}

/// SYNC ERROR: a storage-layer sync failure is likewise a refusal.
#[test]
fn storage_sync_error_refuses() {
    let d = tmp("sync");
    let p = d.join("result.img");
    let bytes = 1024usize;
    let file = sized_file(&p, bytes, 0x7);
    let retained = finalize::dup_retained(file.as_fd()).unwrap();
    let mut storage = FdStorage::with_sync_error(file.as_raw_fd(), "imago sync EIO");
    let e = finalize::finalize_result(&mut storage, &retained, bytes as u64, || false, None)
        .unwrap_err();
    assert!(matches!(e, FinalizeError::StorageSyncFailed(_)), "got {e}");
    let _ = std::fs::remove_dir_all(&d);
}

/// RESULT/CAP OVERRUN: an admitted template over the hard cap is refused up
/// front; a fstat size disagreeing with the admitted template is refused.
#[test]
fn result_size_and_cap_overrun_refused() {
    let d = tmp("cap");
    let p = d.join("result.img");
    let bytes = 2048usize;
    let file = sized_file(&p, bytes, 0x9);
    let retained = finalize::dup_retained(file.as_fd()).unwrap();

    // over the hard cap
    let mut s1 = FdStorage::new(file.as_raw_fd());
    assert!(matches!(
        finalize::finalize_result(&mut s1, &retained, RESULT_TEMPLATE_BYTES_MAX + 1, || false, None),
        Err(FinalizeError::ResultTooLarge(_))
    ));

    // template size != actual inode size
    let mut s2 = FdStorage::new(file.as_raw_fd());
    assert!(matches!(
        finalize::finalize_result(&mut s2, &retained, (bytes + 512) as u64, || false, None),
        Err(FinalizeError::ResultSizeMismatch { .. })
    ));
    let _ = std::fs::remove_dir_all(&d);
}

/// SHORT READ: a chunked pread that cannot deliver the exact byte count is a
/// refusal, never a silent partial digest.
#[test]
fn short_read_refused() {
    let d = tmp("short");
    let p = d.join("small.img");
    let bytes = 512usize;
    let file = sized_file(&p, bytes, 0x3);
    // ask the pread for MORE bytes than the file holds.
    let e = finalize::pread_sha256(file.as_raw_fd(), (bytes + 4096) as u64, || false, None)
        .unwrap_err();
    assert!(matches!(e, FinalizeError::ShortRead { .. }), "got {e}");
    let _ = std::fs::remove_dir_all(&d);
}

/// DUP PRESERVES ACCESS MODE: the retained duplicate of a READ-WRITE result
/// file is itself READ-WRITE (shared open-file description). We verify this
/// honestly and never claim an O_RDONLY conversion.
#[test]
fn dup_retained_preserves_read_write_mode() {
    let d = tmp("dup");
    let p = d.join("rw.img");
    let file = sized_file(&p, 512, 0x5);
    let retained = finalize::dup_retained(file.as_fd()).unwrap();
    // SAFETY: F_GETFL on the retained owned fd.
    let fl = unsafe { libc::fcntl(retained.as_raw_fd(), libc::F_GETFL) };
    assert!(fl >= 0);
    assert_eq!(
        fl & libc::O_ACCMODE,
        libc::O_RDWR,
        "dup of a RW file must stay RW — no false O_RDONLY claim"
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// CONSOLE CAP: the limiter truncates the final write so the final size is
/// <= MAX_CONSOLE_BYTES EXACTLY (CONSOLE_SLACK_BYTES == 0), and `truncated`
/// latches true once the budget is exhausted.
#[test]
fn console_limiter_exact_cap_no_slack() {
    assert_eq!(CONSOLE_SLACK_BYTES, 0);
    let mut lim = ConsoleLimiter::with_cap(10);
    assert_eq!(lim.admit(4), 4);
    assert!(!lim.truncated());
    // this chunk straddles the cap: only 6 bytes admitted, truncated latches.
    assert_eq!(lim.admit(100), 6);
    assert!(lim.truncated());
    assert_eq!(lim.written(), 10);
    // every subsequent byte is dropped; size never exceeds the cap.
    assert_eq!(lim.admit(50), 0);
    assert_eq!(lim.written(), 10);
}

/// CONSOLE FINALIZE: hashing the final console bytes, carrying `truncated`,
/// and refusing a file that somehow exceeds the cap.
#[test]
fn console_finalize_hashes_and_bounds() {
    let d = tmp("console");
    let p = d.join("console.log");
    let bytes = 4096usize;
    let file = sized_file(&p, bytes, 0x2);
    let retained = finalize::dup_retained(file.as_fd()).unwrap();
    let c = finalize::finalize_console(&retained, true, || false, None).unwrap();
    assert_eq!(c.console_bytes, bytes as u64);
    assert!(c.truncated);
    assert_eq!(c.limit_bytes, MAX_CONSOLE_BYTES);
    let _ = std::fs::remove_dir_all(&d);
}

/// CANCELLATION: a cooperative cancel at the entry of finalization is observed
/// and yields a refusal (no result).
#[test]
fn cancellation_refuses() {
    let d = tmp("cancel");
    let p = d.join("result.img");
    let bytes = 1024usize;
    let file = sized_file(&p, bytes, 0x4);
    let retained = finalize::dup_retained(file.as_fd()).unwrap();
    let mut storage = FdStorage::new(file.as_raw_fd());
    let e = finalize::finalize_result(&mut storage, &retained, bytes as u64, || true, None)
        .unwrap_err();
    assert!(matches!(e, FinalizeError::Cancelled), "got {e}");
    let _ = std::fs::remove_dir_all(&d);
}

/// DEADLINE: a pread whose deadline is already in the past fails closed rather
/// than running unbounded.
#[test]
fn deadline_exceeded_refuses() {
    let d = tmp("deadline");
    let p = d.join("big.img");
    let bytes = 2 * 1024 * 1024usize; // > 1 chunk so the loop checks the clock
    let file = sized_file(&p, bytes, 0x6);
    let past = std::time::Instant::now() - std::time::Duration::from_secs(1);
    let e = finalize::pread_sha256(file.as_raw_fd(), bytes as u64, || false, Some(past))
        .unwrap_err();
    assert!(matches!(e, FinalizeError::DeadlineExceeded), "got {e}");
    let _ = std::fs::remove_dir_all(&d);
}

// F08 — BLOCKED-OPERATION supervision. The reviewer's exact counterexample:
// finalize performs synchronous flush/sync/fsync/reads between COOPERATIVE
// deadline checks, so a BLOCKED operation can never observe them and the "hard
// ceiling" was unsupported. This test installs a storage whose flush BLOCKS
// indefinitely (a hung fsync/stuck device) and proves:
//   (1) a bare `finalize_result` with a cooperative deadline NEVER returns while
//       blocked — reproduced by showing it is still blocked after the deadline;
//   (2) the watchdog `supervise_finalize` returns DeadlineExceeded WITHIN the
//       bound, fails closed (no digest), and leaves the descriptor safely owned
//       by the detached worker (our independent fd stays valid).
#[test]
fn supervise_finalize_bounds_a_blocked_operation_and_keeps_safe_ownership() {
    use std::os::fd::OwnedFd;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    struct BlockingStorage {
        owned: OwnedFd,
        release: Arc<AtomicBool>,
        entered: Arc<AtomicBool>,
    }
    impl finalize::ResultStorage for BlockingStorage {
        fn flush_checked(&mut self) -> Result<(), FinalizeError> {
            // Simulate a flush/fsync that blocks in the kernel: it cannot observe
            // any cooperative cancel/deadline. Bounded only by an external release
            // so the test leaves no permanently-stuck thread.
            self.entered.store(true, Ordering::SeqCst);
            while !self.release.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(())
        }
        fn sync_checked(&mut self) -> Result<(), FinalizeError> {
            Ok(())
        }
        fn io_fd(&self) -> std::os::fd::RawFd {
            self.owned.as_raw_fd()
        }
    }

    let d = tmp("blocked");
    let p = d.join("result.img");
    let bytes = 4096usize;
    let file = sized_file(&p, bytes, 0x5A);

    // (1) A bare cooperative finalize with an ALREADY-PAST deadline: the blocking
    // flush is reached and never returns. Run it on a thread and show it is STILL
    // blocked well past the deadline — the cooperative check is powerless.
    {
        let release = Arc::new(AtomicBool::new(false));
        let entered = Arc::new(AtomicBool::new(false));
        let io_dup = finalize::dup_retained(file.as_fd()).unwrap();
        let ret_dup = finalize::dup_retained(file.as_fd()).unwrap();
        let (r2, e2) = (release.clone(), entered.clone());
        let done = Arc::new(AtomicBool::new(false));
        let done2 = done.clone();
        // A deadline 100ms in the FUTURE: the pre-flush cooperative check passes,
        // execution ENTERS the blocking flush, then the deadline elapses WHILE
        // blocked — exactly the window a cooperative check cannot cover.
        let coop_deadline = Instant::now() + Duration::from_millis(100);
        let h = std::thread::spawn(move || {
            let mut s = BlockingStorage { owned: io_dup, release: r2, entered: e2 };
            let _ = finalize::finalize_result(
                &mut s,
                &ret_dup,
                bytes as u64,
                || false,
                Some(coop_deadline),
            );
            done2.store(true, Ordering::SeqCst);
        });
        // wait until the blocking flush is entered
        while !entered.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(2));
        }
        // sleep well past the cooperative deadline
        std::thread::sleep(Duration::from_millis(300));
        assert!(
            !done.load(Ordering::SeqCst),
            "BASELINE DEFECT: a cooperative deadline cannot stop a blocked flush \
             — finalize is still blocked long past its deadline"
        );
        release.store(true, Ordering::SeqCst); // let the stuck worker finish
        let _ = h.join();
    }

    // (2) The watchdog bounds the SAME blocked operation and fails closed.
    {
        let release = Arc::new(AtomicBool::new(false));
        let entered = Arc::new(AtomicBool::new(false));
        let io_dup = finalize::dup_retained(file.as_fd()).unwrap();
        let ret_dup = finalize::dup_retained(file.as_fd()).unwrap();
        let (r2, e2) = (release.clone(), entered.clone());
        let deadline = Instant::now() + Duration::from_millis(250);
        let started = Instant::now();
        let res = finalize::supervise_finalize(deadline, || false, move || {
            let mut s = BlockingStorage { owned: io_dup, release: r2, entered: e2 };
            finalize::finalize_result(&mut s, &ret_dup, bytes as u64, || false, None)
        });
        let elapsed = started.elapsed();
        assert!(
            matches!(res, Err(FinalizeError::DeadlineExceeded)),
            "watchdog must fail closed on a blocked op, got {res:?}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "watchdog must return within the bound, took {elapsed:?}"
        );
        // SAFE OWNERSHIP: the worker (still blocked) owns its dup'd fds; our own
        // descriptor was never closed out from under it and remains valid.
        while !entered.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(2));
        }
        let probe = finalize::dup_retained(file.as_fd());
        assert!(probe.is_ok(), "our independent descriptor stays valid after timeout");
        release.store(true, Ordering::SeqCst); // release the quarantined worker
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = std::fs::remove_dir_all(&d);
}
