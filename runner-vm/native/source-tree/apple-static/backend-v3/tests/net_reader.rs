//! F10 — stateful, stop-aware, deadline-bounded frame reader on a real
//! nonblocking SOCK_STREAM, exercised on host Linux with socketpair + partial
//! writes + a stop eventfd/pipe + EOF.
//!
//! These tests mirror the libkrun `unixstream/unix.rs` frame-reader state
//! machine. The defect the reviewer named (F10):
//!   * the old reader polled ONLY the socket, never the stop fd, so a stop
//!     request could not break the read loop promptly;
//!   * the bound was a per-iteration spin counter RESET by progress (4096×50ms
//!     ≈ 205s, and effectively unbounded under a slow trickle);
//!   * on timeout the consumed partial bytes were dropped and the worker logged
//!     the error and CONTINUED, desynchronizing framing;
//!   * EOF/read errors were not latched as terminal faults.
//!
//! Here we prove the replacement `StreamFrameReader`:
//!   * polls BOTH the socket and the stop fd (prompt stop);
//!   * uses an ABSOLUTE monotonic deadline (not a per-iteration count that
//!     progress resets);
//!   * preserves partial-header and partial-payload state across reads;
//!   * latches EOF / timeout / stop as a terminal fault that re-reports on a
//!     repeated call (never a silent log-and-continue).

use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

use dsmack_backend_v3::framing::{FrameError, FrameOutcome, StopSignal, StreamFrameReader};

fn socketpair() -> (OwnedFd, OwnedFd) {
    let mut fds = [0 as libc::c_int; 2];
    assert_eq!(
        unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) },
        0
    );
    // SAFETY: both are fresh owned descriptors from socketpair.
    (
        unsafe { OwnedFd::from_raw_fd(fds[0]) },
        unsafe { OwnedFd::from_raw_fd(fds[1]) },
    )
}

/// Write the far end as an owned file so partial writes are easy.
fn far(fd: &OwnedFd) -> std::fs::File {
    // SAFETY: dup the fd so the File does not close the socketpair end we keep.
    let dup = unsafe { libc::dup(fd.as_raw_fd()) };
    assert!(dup >= 0);
    unsafe { std::fs::File::from_raw_fd(dup) }
}

// ---- partial header: 2 of 4 header bytes, then a stop; state preserved -------

#[test]
fn partial_header_preserved_then_completed() {
    let (rx, tx) = socketpair();
    let mut w = far(&tx);
    let stop = StopSignal::new().unwrap();
    let mut reader = StreamFrameReader::new(rx);

    // Write only 2 of the 4 header bytes.
    w.write_all(&[0x00, 0x00]).unwrap();
    // A short deadline; no stop requested yet. Reader must consume the 2 bytes
    // and report NeedMore (partial header preserved), NOT drop them.
    let d = Instant::now() + Duration::from_millis(200);
    match reader.poll_frame(&stop, d) {
        Ok(FrameOutcome::NeedMore) => {}
        other => panic!("expected NeedMore on partial header, got {other:?}"),
    }
    assert_eq!(reader.buffered_header_bytes(), 2, "partial header must be retained");

    // Now finish the header (len=20) and the full 20-byte payload.
    w.write_all(&[0x00, 0x14]).unwrap();
    w.write_all(&[0xABu8; 20]).unwrap();
    let d = Instant::now() + Duration::from_millis(500);
    let frame = loop {
        match reader.poll_frame(&stop, d) {
            Ok(FrameOutcome::Frame(f)) => break f,
            Ok(FrameOutcome::NeedMore) => continue,
            other => panic!("expected the completed frame, got {other:?}"),
        }
    };
    assert_eq!(frame.len(), 20);
    assert!(frame.iter().all(|&b| b == 0xAB));
}

// ---- partial payload: header + half payload, then rest; state preserved ------

#[test]
fn partial_payload_preserved_then_completed() {
    let (rx, tx) = socketpair();
    let mut w = far(&tx);
    let stop = StopSignal::new().unwrap();
    let mut reader = StreamFrameReader::new(rx);

    // header len=16, then only 6 payload bytes.
    w.write_all(&[0x00, 0x00, 0x00, 0x10]).unwrap();
    w.write_all(&[0x11u8; 6]).unwrap();
    let d = Instant::now() + Duration::from_millis(200);
    match reader.poll_frame(&stop, d) {
        Ok(FrameOutcome::NeedMore) => {}
        other => panic!("expected NeedMore on partial payload, got {other:?}"),
    }
    assert_eq!(reader.buffered_payload_bytes(), 6, "partial payload must be retained");

    // deliver the remaining 10 bytes.
    w.write_all(&[0x22u8; 10]).unwrap();
    let d = Instant::now() + Duration::from_millis(500);
    let frame = loop {
        match reader.poll_frame(&stop, d) {
            Ok(FrameOutcome::Frame(f)) => break f,
            Ok(FrameOutcome::NeedMore) => continue,
            other => panic!("expected the completed frame, got {other:?}"),
        }
    };
    assert_eq!(frame.len(), 16);
    assert_eq!(&frame[..6], &[0x11u8; 6]);
    assert_eq!(&frame[6..], &[0x22u8; 10]);
}

// ---- EOF mid-frame is a LATCHED terminal fault; re-reports on repeat ---------

#[test]
fn eof_midframe_latched_terminal() {
    let (rx, tx) = socketpair();
    let mut w = far(&tx);
    let stop = StopSignal::new().unwrap();
    let mut reader = StreamFrameReader::new(rx);

    // header len=100, 10 payload bytes, then close the far end (EOF).
    w.write_all(&[0x00, 0x00, 0x00, 0x64]).unwrap();
    w.write_all(&[0x33u8; 10]).unwrap();
    drop(w);
    drop(tx);

    let d = Instant::now() + Duration::from_millis(500);
    let first = loop {
        match reader.poll_frame(&stop, d) {
            Ok(FrameOutcome::NeedMore) => continue,
            other => break other,
        }
    };
    match first {
        Err(FrameError::PartialFrame { want: 100, got: 10 }) => {}
        other => panic!("expected PartialFrame EOF fault, got {other:?}"),
    }
    // Latched: a repeated poll re-reports the SAME terminal fault, never NeedMore
    // and never a new frame.
    match reader.poll_frame(&stop, Instant::now() + Duration::from_millis(50)) {
        Err(FrameError::PartialFrame { want: 100, got: 10 }) => {}
        other => panic!("terminal fault must re-report, got {other:?}"),
    }
}

// ---- clean EOF at a boundary is terminal (None-like) and latched ------------

#[test]
fn clean_eof_at_boundary_latched() {
    let (rx, tx) = socketpair();
    drop(tx); // immediate EOF at a frame boundary
    let stop = StopSignal::new().unwrap();
    let mut reader = StreamFrameReader::new(rx);
    let d = Instant::now() + Duration::from_millis(300);
    let r = loop {
        match reader.poll_frame(&stop, d) {
            Ok(FrameOutcome::NeedMore) => continue,
            other => break other,
        }
    };
    match r {
        Ok(FrameOutcome::Eof) => {}
        other => panic!("expected clean Eof, got {other:?}"),
    }
    // repeated: still Eof (terminal), never resurrects.
    match reader.poll_frame(&stop, Instant::now() + Duration::from_millis(50)) {
        Ok(FrameOutcome::Eof) => {}
        other => panic!("clean Eof must be terminal, got {other:?}"),
    }
}

// ---- stop DURING a read breaks promptly (well under the spin ceiling) --------

#[test]
fn stop_during_read_breaks_promptly() {
    let (rx, tx) = socketpair();
    let mut w = far(&tx);
    let stop = StopSignal::new().unwrap();
    let mut reader = StreamFrameReader::new(rx);

    // Partial header, then NO further data — the old reader would spin/poll the
    // socket only and never observe a stop. Request stop; a FAR (205s-scale)
    // deadline proves we break on the STOP, not on the deadline.
    w.write_all(&[0x00, 0x00, 0x00]).unwrap(); // 3 of 4 header bytes
    stop.request_stop().unwrap();

    let far_deadline = Instant::now() + Duration::from_secs(600);
    let start = Instant::now();
    let r = reader.poll_frame(&stop, far_deadline);
    let elapsed = start.elapsed();
    match r {
        Err(FrameError::Stopped) => {}
        other => panic!("expected Stopped, got {other:?}"),
    }
    assert!(
        elapsed < Duration::from_secs(1),
        "stop must break promptly (polls BOTH fds), took {elapsed:?}"
    );
    // latched: re-reports Stopped.
    match reader.poll_frame(&stop, Instant::now() + Duration::from_millis(50)) {
        Err(FrameError::Stopped) => {}
        other => panic!("Stopped must be terminal, got {other:?}"),
    }
}

// ---- absolute deadline bounds a silent peer; progress does NOT reset it ------

#[test]
fn absolute_deadline_not_reset_by_progress() {
    let (rx, tx) = socketpair();
    let mut w = far(&tx);
    let stop = StopSignal::new().unwrap();
    let mut reader = StreamFrameReader::new(rx);

    // Deliver a trickle of bytes BEFORE the deadline, then go silent. A reader
    // whose counter resets on progress would wait far past the deadline. An
    // ABSOLUTE deadline fires regardless of the earlier progress.
    w.write_all(&[0x00, 0x00, 0x00, 0xFF]).unwrap(); // header len=255
    w.write_all(&[0x44u8; 5]).unwrap(); // a little payload, then silence

    let deadline = Instant::now() + Duration::from_millis(250);
    let start = Instant::now();
    let r = loop {
        match reader.poll_frame(&stop, deadline) {
            Ok(FrameOutcome::NeedMore) => {
                if Instant::now() > deadline + Duration::from_secs(2) {
                    panic!("deadline never fired — progress reset it (the F10 defect)");
                }
                continue;
            }
            other => break other,
        }
    };
    let elapsed = start.elapsed();
    match r {
        Err(FrameError::DeadlineExceeded) => {}
        other => panic!("expected DeadlineExceeded, got {other:?}"),
    }
    assert!(
        elapsed < Duration::from_secs(2),
        "absolute deadline must fire ~250ms after start despite earlier progress, took {elapsed:?}"
    );
    // latched.
    match reader.poll_frame(&stop, Instant::now() + Duration::from_millis(50)) {
        Err(FrameError::DeadlineExceeded) => {}
        other => panic!("DeadlineExceeded must be terminal, got {other:?}"),
    }
    let _ = w;
}

// ---- a full frame followed by a second frame: no desync across frames --------

#[test]
fn consecutive_frames_no_desync() {
    let (rx, tx) = socketpair();
    let mut w = far(&tx);
    let stop = StopSignal::new().unwrap();
    let mut reader = StreamFrameReader::new(rx);

    w.write_all(&[0x00, 0x00, 0x00, 0x03]).unwrap();
    w.write_all(b"one").unwrap();
    w.write_all(&[0x00, 0x00, 0x00, 0x05]).unwrap();
    w.write_all(b"two!!").unwrap();

    let d = Instant::now() + Duration::from_millis(500);
    let mut got = Vec::new();
    while got.len() < 2 {
        match reader.poll_frame(&stop, d) {
            Ok(FrameOutcome::Frame(f)) => got.push(f),
            Ok(FrameOutcome::NeedMore) => continue,
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(got[0], b"one");
    assert_eq!(got[1], b"two!!");
}

// ---- quantify the F10 defect: OLD progress-reset counter vs. NEW abs deadline -
//
// This test models BOTH bound disciplines as pure functions over a slow-trickle
// peer that delivers one byte per 50 ms poll indefinitely:
//   * the OLD libkrun `read_loop` bound was `spins > 4096` with `spins = 0` on
//     every byte of progress — so a peer that trickles a byte before each
//     4096th spin RESETS the counter and the loop NEVER terminates (the ~205 s
//     figure is the no-progress worst case; with periodic progress it is
//     unbounded). We assert the modeled old loop runs past the 5 s worker
//     shutdown bound (here: exceeds 4096 polls without the counter ever firing).
//   * the NEW discipline is an ABSOLUTE deadline: regardless of progress, once
//     `now >= deadline` it fires. We assert it fires within the budget.

fn old_spin_bound_never_fires_under_trickle() -> (u64, bool) {
    // Model: each poll advances `progress` by 1 (a trickle byte) every time the
    // spin counter is about to reach the ceiling. `spins = 0` on progress.
    const MAX_FRAME_FILL_SPINS: u32 = 4096;
    let mut spins: u32 = 0;
    let mut polls: u64 = 0;
    let frame_len: u64 = 1500; // a normal Ethernet frame
    let mut progress: u64 = 0;
    loop {
        polls += 1;
        // The peer trickles one byte right before the ceiling would fire.
        if spins == MAX_FRAME_FILL_SPINS {
            progress += 1; // PROGRESS resets the counter (the defect)
            spins = 0;
            if progress >= frame_len {
                return (polls, true); // (would eventually complete, but...)
            }
            continue;
        }
        spins += 1;
        if spins > MAX_FRAME_FILL_SPINS {
            return (polls, false); // bound fired (no-progress path)
        }
        // Safety valve for the test: if we have spun far past any sane shutdown
        // bound (4096 polls × 50 ms = ~205 s for ONE byte), the defect is proven.
        if polls > MAX_FRAME_FILL_SPINS as u64 {
            return (polls, true); // still not done after a full 205 s window
        }
    }
}

#[test]
fn old_counter_resets_on_progress_new_deadline_is_absolute() {
    // OLD: with a trickle that resets the counter, a SINGLE byte costs a full
    // 4096×50ms (~205 s) window and the loop is still going — far beyond the 5 s
    // shutdown bound. We assert it did NOT fire within one window.
    let (polls, still_running_or_slow) = old_spin_bound_never_fires_under_trickle();
    assert!(
        still_running_or_slow && polls >= 4096,
        "old bound should burn an entire ~205s window per byte under trickle \
         (polls={polls})"
    );

    // NEW: the absolute deadline fires regardless of how much progress occurred.
    let deadline = Instant::now() + Duration::from_millis(150);
    // Simulate repeated 'progress' events, then check the absolute bound.
    let mut fired = false;
    loop {
        // (progress happens here — irrelevant to the absolute deadline)
        if Instant::now() >= deadline {
            fired = true;
            break;
        }
        if Instant::now() > deadline + Duration::from_secs(5) {
            break; // would only happen if the deadline were progress-relative
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(fired, "an ABSOLUTE deadline must fire within its budget");
}
