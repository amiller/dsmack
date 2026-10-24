//! Result finalization over real files and descriptors on the host (no VM).

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::{AsFd, AsRawFd};

use dsmack_backend_v3::consumption_v3::FdStorage;
use dsmack_backend_v3::finalize::{self, FinalizeError};

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

#[test]
fn finalize_succeeds_through_retained_inode() {
    let d = tmp("ok");
    let p = d.join("result.img");
    let bytes = 4096usize;
    let file = sized_file(&p, bytes, 0xAB);
    let retained = finalize::dup_retained(file.as_fd()).unwrap();
    let mut storage = FdStorage::new(file.as_raw_fd());
    let r = finalize::finalize_result(&mut storage, &retained, bytes as u64, || false, None).unwrap();
    use sha2::{Digest, Sha256};
    assert_eq!(r.result_sha256, format!("{:x}", Sha256::digest(vec![0xABu8; bytes])));
    let _ = std::fs::remove_dir_all(&d);
}

/// A retained descriptor on a swapped inode with identical content is refused.
#[test]
fn wrong_inode_retained_descriptor_refused() {
    let d = tmp("wronginode");
    let real = d.join("real-result.img");
    let swapped = d.join("swapped.img");
    let bytes = 2048usize;
    let io_file = sized_file(&real, bytes, 0x01);
    let swapped_file = sized_file(&swapped, bytes, 0x01);
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

/// A storage flush that blocks forever is bounded by `supervise_finalize`, which
/// fails closed and leaves the descriptor owned by the detached worker.
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
