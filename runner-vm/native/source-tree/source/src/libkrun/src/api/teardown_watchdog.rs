use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// A process-fatal boundary: native HVF resources remain owned on the calling
/// thread until all checked teardown steps complete. No timeout unwinds them.
pub struct TeardownWatchdog {
    complete: Option<Sender<()>>,
    worker: Option<JoinHandle<()>>,
    deadline: Instant,
    cancel: Arc<AtomicBool>,
}

impl TeardownWatchdog {
    pub fn arm(deadline: Instant, cancel: Arc<AtomicBool>) -> std::io::Result<Self> {
        let (complete, completion) = mpsc::channel();
        let cancelled = cancel.clone();
        let worker = thread::Builder::new()
            .name("native-teardown-watchdog".into())
            .spawn(move || {
                loop {
                    if cancelled.load(Ordering::Acquire) {
                        fatal("caller cancelled");
                    }
                    let now = Instant::now();
                    if now >= deadline {
                        fatal("deadline exceeded");
                    }
                    match completion.recv_timeout((deadline - now).min(Duration::from_millis(5))) {
                        Ok(()) => return,
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => fatal("owner disconnected"),
                    }
                }
            })?;
        Ok(Self {
            complete: Some(complete),
            worker: Some(worker),
            deadline,
            cancel,
        })
    }

    /// Called only after observers, workers, HVF VM and descriptors are released.
    pub fn finish(mut self) {
        if self.cancel.load(Ordering::Acquire) || Instant::now() >= self.deadline {
            fatal("completion outside deadline or after cancellation");
        }
        if self.complete.take().unwrap().send(()).is_err() {
            fatal("watchdog exited without confirmation");
        }
        if self.worker.take().unwrap().join().is_err() {
            fatal("watchdog panicked");
        }
    }
}

impl Drop for TeardownWatchdog {
    fn drop(&mut self) {
        if self.worker.is_some() {
            fatal("teardown did not complete");
        }
    }
}

fn fatal(reason: &str) -> ! {
    // stderr may be a full pipe or have a poisoned/held Rust lock. Diagnostics
    // must not prevent process-fatal enforcement.
    unsafe {
        let flags = libc::fcntl(libc::STDERR_FILENO, libc::F_GETFL);
        if flags >= 0
            && libc::fcntl(libc::STDERR_FILENO, libc::F_SETFL, flags | libc::O_NONBLOCK) == 0
        {
            for bytes in [
                b"native teardown failed: ".as_slice(),
                reason.as_bytes(),
                b"; quiescence UNCONFIRMED; no result; terminating owning process\n".as_slice(),
            ] {
                let _ = libc::write(libc::STDERR_FILENO, bytes.as_ptr().cast(), bytes.len());
            }
        }
    }
    std::process::abort()
}
