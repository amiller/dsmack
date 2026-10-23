//! F08 (console limiter writer) and F10/F11 (bounded EOF-aware framing +
//! bounded net-worker shutdown) primitive tests on real file I/O and threads.

use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dsmack_backend_v3::finalize::LimitedConsoleWriter;
use dsmack_backend_v3::framing::{
    read_frame, reject_aliased, validate_control_transport, write_frame, BoundedNetWorker,
    ControlError, FrameError, MAX_ETHERNET_FRAME_BYTES,
};

// ---------------- F08: the console limiter is the console writer -------------

#[test]
fn console_writer_enforces_exact_cap_and_latches_truncation() {
    let d = std::env::temp_dir().join(format!("dsmack-v3-console-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let path = d.join("console.log");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    // cap 10; write 7 (ok, not truncated) then 8 more (only 3 admitted).
    let mut w = LimitedConsoleWriter::with_cap(file, 10);
    assert_eq!(w.write(b"abcdefg").unwrap(), 7);
    assert!(!w.truncated());
    assert_eq!(w.write(b"HIJKLMNO").unwrap(), 8); // reports full len; drops 5
    assert!(w.truncated(), "truncation must latch once the cap is hit");
    assert_eq!(w.written(), 10, "exactly cap bytes written; zero slack");
    w.flush().unwrap();
    // the on-disk file is EXACTLY the cap, and holds the admitted prefix.
    let mut got = Vec::new();
    std::fs::File::open(&path).unwrap().read_to_end(&mut got).unwrap();
    assert_eq!(got.len(), 10);
    assert_eq!(&got, b"abcdefgHIJ");
    let _ = std::fs::remove_dir_all(&d);
}

// ---------------- F10/F11: bounded, EOF-aware framing ------------------------

#[test]
fn frame_roundtrip() {
    let mut buf = Vec::new();
    write_frame(&mut buf, b"hello-ethernet-frame").unwrap();
    // 4-byte BE length prefix
    assert_eq!(&buf[..4], &(20u32).to_be_bytes());
    let mut cur = Cursor::new(buf);
    let f = read_frame(&mut cur).unwrap().unwrap();
    assert_eq!(f, b"hello-ethernet-frame");
    // next read at clean boundary → None (EOF, loop terminates, no block)
    assert_eq!(read_frame(&mut cur).unwrap(), None);
}

#[test]
fn clean_eof_at_boundary_is_none() {
    let mut cur = Cursor::new(Vec::<u8>::new());
    assert_eq!(read_frame(&mut cur).unwrap(), None);
}

#[test]
fn partial_header_at_eof_refused() {
    let mut cur = Cursor::new(vec![0x00, 0x00]); // 2 of 4 header bytes
    assert_eq!(read_frame(&mut cur), Err(FrameError::PartialHeader { got: 2 }));
}

#[test]
fn partial_frame_at_eof_refused() {
    let mut data = (10u32).to_be_bytes().to_vec();
    data.extend_from_slice(b"abc"); // only 3 of 10 payload bytes
    let mut cur = Cursor::new(data);
    assert_eq!(
        read_frame(&mut cur),
        Err(FrameError::PartialFrame { want: 10, got: 3 })
    );
}

#[test]
fn oversized_peer_length_refused_without_allocation() {
    // header claims ~4 GiB; the length is checked BEFORE any payload read.
    let data = (u32::MAX).to_be_bytes().to_vec();
    let mut cur = Cursor::new(data);
    assert_eq!(
        read_frame(&mut cur),
        Err(FrameError::Oversized { len: u32::MAX as usize })
    );
    // and the writer refuses the same bound.
    let big = vec![0u8; MAX_ETHERNET_FRAME_BYTES + 1];
    let mut out = Vec::new();
    assert!(matches!(write_frame(&mut out, &big), Err(FrameError::Oversized { .. })));
}

#[test]
fn zero_length_frame_refused() {
    let data = (0u32).to_be_bytes().to_vec();
    let mut cur = Cursor::new(data);
    assert_eq!(read_frame(&mut cur), Err(FrameError::ZeroLength));
    let mut out = Vec::new();
    assert_eq!(write_frame(&mut out, b""), Err(FrameError::ZeroLength));
}

// A frame whose declared length does not match a truncated stream never slices
// using the peer length: it returns PartialFrame rather than reading OOB.
#[test]
fn stream_of_frames_until_eof() {
    let mut buf = Vec::new();
    write_frame(&mut buf, b"one").unwrap();
    write_frame(&mut buf, b"two!!").unwrap();
    let mut cur = Cursor::new(buf);
    assert_eq!(read_frame(&mut cur).unwrap().unwrap(), b"one");
    assert_eq!(read_frame(&mut cur).unwrap().unwrap(), b"two!!");
    assert_eq!(read_frame(&mut cur).unwrap(), None);
    let _ = cur.seek(SeekFrom::Start(0));
}

// ---------------- F10: bounded net-worker shutdown ---------------------------

#[test]
fn bounded_worker_cooperative_stop_joins_ok() {
    let mut w = BoundedNetWorker::spawn(|stop: Arc<AtomicBool>| {
        while !stop.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(w.stop_join_within(Duration::from_secs(2)), Ok(()));
    // idempotent
    assert_eq!(w.stop_join(), Ok(()));
}

#[test]
fn bounded_worker_fault_propagates() {
    let mut w = BoundedNetWorker::spawn(|_stop| Err("wire fault".to_string())).unwrap();
    // give it a moment to finish
    std::thread::sleep(Duration::from_millis(20));
    assert_eq!(w.stop_join_within(Duration::from_secs(2)), Err("wire fault".into()));
}

#[test]
fn bounded_worker_stuck_times_out() {
    // a worker that ignores the stop flag must not hold teardown forever: the
    // bounded join returns a timeout fault and retains (does not free) state.
    let mut w = BoundedNetWorker::spawn(|_stop: Arc<AtomicBool>| {
        std::thread::sleep(Duration::from_secs(30));
        Ok(())
    })
    .unwrap();
    let r = w.stop_join_within(Duration::from_millis(150));
    assert!(r.is_err(), "stuck worker must time out");
    assert!(r.unwrap_err().contains("did not stop"));
}

#[test]
fn bounded_worker_fault_is_latched_on_repeated_teardown() {
    // F10: after a FAILED teardown, a repeated stop_join must RE-REPORT the
    // fault, never return Ok on the strength of the already-consumed handle
    // (the exact defect the gate named). A wire-fault worker:
    let mut w = BoundedNetWorker::spawn(|_stop| Err("permanent wire fault".to_string())).unwrap();
    std::thread::sleep(Duration::from_millis(20));
    let first = w.stop_join_within(Duration::from_secs(2));
    assert_eq!(first, Err("permanent wire fault".into()));
    // repeated teardown re-reports the SAME fault (not Ok)
    assert_eq!(w.stop_join(), Err("permanent wire fault".into()));
    assert_eq!(w.stop_join(), Err("permanent wire fault".into()));

    // A stuck worker that TIMES OUT also latches: the second call re-reports the
    // timeout fault, never Ok.
    let mut stuck = BoundedNetWorker::spawn(|_stop: Arc<AtomicBool>| {
        std::thread::sleep(Duration::from_secs(30));
        Ok(())
    })
    .unwrap();
    let r1 = stuck.stop_join_within(Duration::from_millis(120));
    assert!(r1.is_err() && r1.as_ref().unwrap_err().contains("did not stop"));
    let r2 = stuck.stop_join_within(Duration::from_millis(120));
    assert_eq!(r2, r1, "a repeated teardown after a timeout must re-report the fault, not Ok");
}

// ---------------- F10: control/net descriptor validation --------------------

#[test]
fn aliased_control_net_refused() {
    assert_eq!(reject_aliased(5, 5), Err(ControlError::Aliased { control: 5, net: 5 }));
    assert_eq!(reject_aliased(5, 6), Ok(()));
    assert_eq!(reject_aliased(5, -1), Ok(())); // no net
    assert_eq!(reject_aliased(-1, -1), Ok(()));
}

#[test]
fn control_transport_type_checked() {
    // a socket is accepted
    let mut fds = [0 as libc::c_int; 2];
    assert_eq!(
        unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) },
        0
    );
    assert_eq!(validate_control_transport(fds[0]), Ok(()));
    unsafe {
        libc::close(fds[0]);
        libc::close(fds[1]);
    }
    // a regular file is refused
    let d = std::env::temp_dir().join(format!("dsmack-v3-ctl-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let p = d.join("not-a-transport");
    let mut f = std::fs::File::create(&p).unwrap();
    f.write_all(b"x").unwrap();
    use std::os::fd::AsRawFd;
    match validate_control_transport(f.as_raw_fd()) {
        Err(ControlError::NotTransport { kind, .. }) => assert_eq!(kind, "regular file"),
        other => panic!("expected NotTransport, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&d);
}
