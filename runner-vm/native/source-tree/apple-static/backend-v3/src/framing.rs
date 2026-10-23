//! F10/F11 — the generic-NIC transport primitives the native backend OWNS:
//! bounded, EOF-aware four-byte big-endian Ethernet-frame framing, bounded
//! network-worker shutdown, and control/net descriptor validation.
//!
//! OWNERSHIP BOUNDARY (per the native-net-helper gate): the PORTABLE HELPER
//! (passt/pasta/slirp-style, pinned source, framing adapter, launch/stop) is
//! owned by the `controller35/native-net-helper` lane and is a SEPARATE gate.
//! This module owns only the in-process wire contract the libkrun UnixstreamFd
//! backend speaks across an ALREADY-CONNECTED fd: a 4-byte big-endian length
//! prefix followed by exactly that many Ethernet-frame bytes. The far end is
//! the helper; nothing here launches, installs or depends on a helper binary.
//! A missing helper executable is therefore NOT a compile dependency — the
//! native source takes only a generic connected fd (see `net.rs`).
//!
//! These primitives are proven on host Linux with real descriptors and real
//! threads; the identical framing/teardown is wired into the libkrun net
//! device source patch (see the source-tree net/unixstream/worker changes).

use std::io::{self, Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

/// Hard upper bound on a single framed Ethernet payload. A virtio-net guest
/// with GSO/TSO can hand the host a large aggregated buffer, but the length is
/// a 16-bit-domain quantity in the unixstream framing; we cap at 65535 so a
/// hostile/partial peer length can NEVER drive an unbounded allocation or read.
pub const MAX_ETHERNET_FRAME_BYTES: usize = 65_535;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("framing I/O error: {0}")]
    Io(String),
    #[error("partial length header at stream end: got {got} of 4 bytes")]
    PartialHeader { got: usize },
    #[error("partial frame at stream end: got {got} of {want} bytes")]
    PartialFrame { want: usize, got: usize },
    #[error("peer-supplied frame length {len} exceeds the {MAX_ETHERNET_FRAME_BYTES}-byte bound")]
    Oversized { len: usize },
    #[error("peer-supplied frame length is zero")]
    ZeroLength,
    /// F10 — the worker was asked to stop (its stop fd became readable) while a
    /// frame was still being assembled. This is a terminal transport outcome:
    /// the partial-frame state is discarded with the reader (the transport is
    /// going away), never logged-and-continued into the next frame.
    #[error("stop requested during frame read")]
    Stopped,
    /// F10 — the ABSOLUTE frame deadline elapsed before the frame completed.
    /// This is a monotonic wall-clock instant fixed when framing begins; peer
    /// progress does NOT reset it (the old per-iteration spin counter that reset
    /// on progress permitted ~205s of no net progress).
    #[error("frame not completed before the absolute deadline")]
    DeadlineExceeded,
}

/// Fill `buf` fully, or return the number of bytes read before a clean EOF.
/// Retries on EINTR. Never loops without progress: a `read` returning 0 is a
/// terminal EOF, not a spin (closes the "loops without progress on EOF" defect).
fn fill_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

/// Read ONE frame. EOF-aware and bounded:
///   * a clean EOF exactly at a frame boundary (0 header bytes) -> `Ok(None)`
///     (the peer closed; the read loop terminates instead of blocking forever);
///   * 1-3 header bytes then EOF -> `PartialHeader` (never block for the rest);
///   * the length is validated against `MAX_ETHERNET_FRAME_BYTES` BEFORE any
///     payload allocation/read, so an unchecked peer length cannot be sliced;
///   * EOF before the full payload -> `PartialFrame` (no indefinite wait).
pub fn read_frame<R: Read>(r: &mut R) -> Result<Option<Vec<u8>>, FrameError> {
    let mut hdr = [0u8; 4];
    let got = fill_or_eof(r, &mut hdr).map_err(|e| FrameError::Io(e.to_string()))?;
    if got == 0 {
        return Ok(None);
    }
    if got < 4 {
        return Err(FrameError::PartialHeader { got });
    }
    let len = u32::from_be_bytes(hdr) as usize;
    if len == 0 {
        return Err(FrameError::ZeroLength);
    }
    if len > MAX_ETHERNET_FRAME_BYTES {
        return Err(FrameError::Oversized { len });
    }
    let mut frame = vec![0u8; len];
    let got2 = fill_or_eof(r, &mut frame).map_err(|e| FrameError::Io(e.to_string()))?;
    if got2 < len {
        return Err(FrameError::PartialFrame { want: len, got: got2 });
    }
    Ok(Some(frame))
}

/// Write ONE frame with the 4-byte big-endian length prefix. Refuses an empty
/// or oversized frame (the same bound the reader enforces).
pub fn write_frame<W: Write>(w: &mut W, frame: &[u8]) -> Result<(), FrameError> {
    if frame.is_empty() {
        return Err(FrameError::ZeroLength);
    }
    if frame.len() > MAX_ETHERNET_FRAME_BYTES {
        return Err(FrameError::Oversized { len: frame.len() });
    }
    let hdr = (frame.len() as u32).to_be_bytes();
    w.write_all(&hdr).map_err(|e| FrameError::Io(e.to_string()))?;
    w.write_all(frame).map_err(|e| FrameError::Io(e.to_string()))?;
    w.flush().map_err(|e| FrameError::Io(e.to_string()))?;
    Ok(())
}

// ===========================================================================
// F10 — stateful, stop-aware, deadline-bounded stream frame reader.
//
// This is the host-executable mirror of the libkrun `unixstream/unix.rs` frame
// reader. The reviewer's F10 defect was concentrated there:
//
//   * the old `read_loop` polled ONLY the socket fd (`PollFd` on POLLIN), never
//     the worker's stop eventfd, so a stop request could not break the fill
//     loop promptly — it waited out up to MAX_FRAME_FILL_SPINS (4096) × 50 ms;
//   * the bound was a per-iteration spin COUNTER that `spins = 0` RESET on every
//     byte of progress, so a slow trickle gave ~205 s (or effectively unbounded)
//     of no net progress against a 5 s worker-shutdown bound;
//   * on timeout the partially-filled frame buffer was a LOCAL that got dropped;
//     the worker logged the read error and CONTINUED, so the next `read_frame`
//     re-read a mid-frame byte stream as a fresh header → framing desync;
//   * EOF / read errors were surfaced as a per-call error but not latched as a
//     terminal transport fault, so a later successful join concealed the loss.
//
// The replacement is a STATE MACHINE that (1) polls BOTH the socket and a stop
// fd, (2) carries partial-header and partial-payload state across calls so no
// consumed byte is ever dropped, (3) is bounded by an ABSOLUTE monotonic
// deadline (not a progress-reset counter), and (4) LATCHES the first terminal
// outcome (EOF / stop / deadline / I/O error) so every subsequent call
// re-reports it — the transport is dead, never log-and-continue.
// ===========================================================================

use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::time::Instant;

/// A cross-thread stop signal usable as a pollable fd. Implemented as a
/// self-pipe (portable across Linux and macOS, unlike `eventfd`): once a byte
/// is written the read end stays readable (the reader never drains it), so a
/// reader blocked in `poll` wakes immediately and `poll_frame` returns
/// `Stopped`.
///
/// This stands in for the libkrun worker's stop `EventFd` that the device's
/// checked teardown writes. The frame reader adds the read end to the poll set
/// alongside the socket so a stop breaks the read loop promptly — not after the
/// old 4096×50 ms spin budget.
pub struct StopSignal {
    read: OwnedFd,
    write: OwnedFd,
}

impl StopSignal {
    pub fn new() -> io::Result<Self> {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: pipe writes two fresh fds into `fds` or returns -1.
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        // Make the read end nonblocking so the reader's readiness check never
        // blocks; the write end can stay blocking (we write a single byte).
        // SAFETY: fcntl on the fresh read fd.
        unsafe {
            let flags = libc::fcntl(fds[0], libc::F_GETFL);
            if flags >= 0 {
                let _ = libc::fcntl(fds[0], libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }
        // SAFETY: both are fresh owned descriptors.
        let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        Ok(Self { read, write })
    }

    /// Make the signal permanently readable. The reader never drains the byte,
    /// so repeated stop observations stay consistent.
    pub fn request_stop(&self) -> io::Result<()> {
        let b: u8 = 1;
        // SAFETY: writing one byte to the pipe write end.
        let rc = unsafe {
            libc::write(
                self.write.as_raw_fd(),
                &b as *const u8 as *const libc::c_void,
                1,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn raw(&self) -> RawFd {
        self.read.as_raw_fd()
    }
}

use std::os::fd::FromRawFd;

/// The result of a single non-terminal `poll_frame` step.
#[derive(Debug)]
pub enum FrameOutcome {
    /// A complete frame was assembled.
    Frame(Vec<u8>),
    /// More bytes are needed; partial-frame state is preserved in the reader.
    /// Call `poll_frame` again (with the same absolute deadline) to continue.
    NeedMore,
    /// A clean EOF observed exactly at a frame boundary (peer closed with no
    /// partial frame in flight). Terminal and latched.
    Eof,
}

// Internal assembly state. Either accumulating the 4-byte header, or filling a
// payload of a known length. Terminal outcomes live in `latched`, not here.
enum ReadState {
    Header { got: usize, buf: [u8; 4] },
    Payload { got: usize, buf: Vec<u8> },
}

/// Terminal, latched outcome of the reader. Once set, every `poll_frame`
/// re-reports it — the transport is dead and must not be resumed.
#[derive(Debug, Clone)]
enum Latched {
    Eof,
    Err(FrameError),
}

/// F10 — stateful stop-aware frame reader over a nonblocking SOCK_STREAM fd.
///
/// `poll_frame(stop, deadline)` is the single step. It:
///   * drains all currently-available bytes into the partial-frame state via
///     nonblocking `recv` (EAGAIN → preserve state and wait);
///   * when it must wait, `poll`s BOTH the socket fd AND the stop fd with the
///     time remaining until `deadline` as the timeout, so a stop breaks the
///     wait at once and the ABSOLUTE deadline bounds total time regardless of
///     how much earlier progress was made;
///   * returns `Frame` on completion, `NeedMore` if more bytes are required,
///     or a terminal/latched `Eof` / `Err` (EOF mid-frame, stop, deadline,
///     oversized/zero length, I/O error).
///
/// The fd must be nonblocking (`new` sets O_NONBLOCK). Partial state is never
/// silently dropped: a terminal failure latches and the transport is finished.
pub struct StreamFrameReader {
    fd: OwnedFd,
    state: ReadState,
    latched: Option<Latched>,
}

impl StreamFrameReader {
    /// Wrap an owned stream fd. Sets it nonblocking so partial reads never block
    /// the poll-driven loop.
    pub fn new(fd: OwnedFd) -> Self {
        let raw = fd.as_raw_fd();
        // SAFETY: fcntl on an owned fd; set O_NONBLOCK, ignore benign failure
        // (the recvs use MSG_DONTWAIT regardless).
        unsafe {
            let flags = libc::fcntl(raw, libc::F_GETFL);
            if flags >= 0 {
                let _ = libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }
        Self {
            fd,
            state: ReadState::Header { got: 0, buf: [0u8; 4] },
            latched: None,
        }
    }

    /// Bytes of the current partial header accumulated (test/introspection).
    pub fn buffered_header_bytes(&self) -> usize {
        match &self.state {
            ReadState::Header { got, .. } => *got,
            ReadState::Payload { .. } => 4,
        }
    }

    /// Bytes of the current partial payload accumulated (test/introspection).
    pub fn buffered_payload_bytes(&self) -> usize {
        match &self.state {
            ReadState::Payload { got, .. } => *got,
            ReadState::Header { .. } => 0,
        }
    }

    fn latch(&mut self, l: Latched) -> Result<FrameOutcome, FrameError> {
        self.latched = Some(l.clone());
        match l {
            Latched::Eof => Ok(FrameOutcome::Eof),
            Latched::Err(e) => Err(e),
        }
    }

    // One nonblocking recv into `dst[*got..]`. Returns:
    //   Ok(true)  — made progress (got advanced), keep draining
    //   Ok(false) — EAGAIN/EWOULDBLOCK, must wait
    //   Err(fatal) — EOF mid-fill, or a hard I/O error (terminal)
    fn recv_into(fd: RawFd, dst: &mut [u8], got: &mut usize) -> Result<bool, FrameEof> {
        loop {
            let remaining = &mut dst[*got..];
            if remaining.is_empty() {
                return Ok(true);
            }
            // SAFETY: recv into a valid mutable slice with its true length.
            let n = unsafe {
                libc::recv(
                    fd,
                    remaining.as_mut_ptr() as *mut libc::c_void,
                    remaining.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if n > 0 {
                *got += n as usize;
                // Keep draining until EAGAIN or the slice is full.
                if *got == dst.len() {
                    return Ok(true);
                }
                continue;
            }
            if n == 0 {
                // Peer closed: EOF (clean at boundary if nothing buffered).
                return Err(FrameEof::Closed);
            }
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                // EAGAIN and EWOULDBLOCK are the same errno on Linux; list only
                // EAGAIN to avoid an unreachable-pattern warning.
                Some(libc::EAGAIN) => return Ok(false),
                #[allow(unreachable_patterns)]
                Some(libc::EWOULDBLOCK) => return Ok(false),
                Some(libc::EINTR) => continue,
                _ => return Err(FrameEof::Io(err.to_string())),
            }
        }
    }

    /// Poll both the socket and the stop fd until `deadline`; return once either
    /// is readable or the deadline elapses. `Ok(true)` = socket readable (or
    /// hang-up), `Ok(false)` = timed out, `Err(Stopped)` = stop fd readable.
    fn wait_readable(&self, stop: &StopSignal, deadline: Instant) -> Result<bool, FrameError> {
        let now = Instant::now();
        if now >= deadline {
            return Ok(false);
        }
        let remaining = deadline - now;
        // Clamp to i32 ms; at least 0 so we never block forever.
        let ms: i32 = remaining
            .as_millis()
            .try_into()
            .unwrap_or(i32::MAX);
        let mut fds = [
            libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: stop.raw(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: poll over a 2-element pollfd array.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), 2, ms) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                // Interrupted: treat as a spurious wake; caller re-checks the
                // deadline. Not readable, not stopped.
                return Ok(false);
            }
            return Err(FrameError::Io(err.to_string()));
        }
        if rc == 0 {
            return Ok(false); // timed out
        }
        // Stop takes priority — a teardown must win over pending socket bytes.
        if fds[1].revents & libc::POLLIN != 0 {
            return Err(FrameError::Stopped);
        }
        // Socket readable, hang-up, or error all warrant a recv attempt (which
        // surfaces EOF/errors precisely).
        Ok(true)
    }

    /// One step of the frame state machine. See the type docs.
    pub fn poll_frame(
        &mut self,
        stop: &StopSignal,
        deadline: Instant,
    ) -> Result<FrameOutcome, FrameError> {
        // Terminal outcomes are latched and re-reported forever.
        if let Some(l) = &self.latched {
            return match l.clone() {
                Latched::Eof => Ok(FrameOutcome::Eof),
                Latched::Err(e) => Err(e),
            };
        }
        // A stop already requested breaks before any further read.
        // (wait_readable also checks it, but check up front for promptness.)
        {
            let mut p = [libc::pollfd { fd: stop.raw(), events: libc::POLLIN, revents: 0 }];
            // SAFETY: 1-element poll with a 0ms timeout — a pure readiness check.
            let rc = unsafe { libc::poll(p.as_mut_ptr(), 1, 0) };
            if rc > 0 && p[0].revents & libc::POLLIN != 0 {
                return self.latch(Latched::Err(FrameError::Stopped));
            }
        }

        let fd = self.fd.as_raw_fd();
        loop {
            // 1) Drain whatever is available into the current state.
            match &mut self.state {
                ReadState::Header { got, buf } => {
                    match Self::recv_into(fd, &mut buf[..], got) {
                        Ok(true) => {
                            // header complete
                            let len = u32::from_be_bytes(*buf) as usize;
                            if len == 0 {
                                return self.latch(Latched::Err(FrameError::ZeroLength));
                            }
                            if len > MAX_ETHERNET_FRAME_BYTES {
                                return self.latch(Latched::Err(FrameError::Oversized { len }));
                            }
                            self.state = ReadState::Payload { got: 0, buf: vec![0u8; len] };
                            // loop to start draining the payload immediately
                            continue;
                        }
                        Ok(false) => { /* need to wait */ }
                        Err(FrameEof::Closed) => {
                            if *got == 0 {
                                return self.latch(Latched::Eof); // clean boundary EOF
                            }
                            let got = *got;
                            return self
                                .latch(Latched::Err(FrameError::PartialHeader { got }));
                        }
                        Err(FrameEof::Io(e)) => {
                            return self.latch(Latched::Err(FrameError::Io(e)));
                        }
                    }
                }
                ReadState::Payload { got, buf } => {
                    let want = buf.len();
                    match Self::recv_into(fd, &mut buf[..], got) {
                        Ok(true) => {
                            // payload complete — hand the frame out, reset to Header
                            let frame = std::mem::take(buf);
                            self.state = ReadState::Header { got: 0, buf: [0u8; 4] };
                            return Ok(FrameOutcome::Frame(frame));
                        }
                        Ok(false) => { /* need to wait */ }
                        Err(FrameEof::Closed) => {
                            let got = *got;
                            return self
                                .latch(Latched::Err(FrameError::PartialFrame { want, got }));
                        }
                        Err(FrameEof::Io(e)) => {
                            return self.latch(Latched::Err(FrameError::Io(e)));
                        }
                    }
                }
            }

            // 2) Nothing more available right now: wait on BOTH fds until the
            //    ABSOLUTE deadline. The partial state above is retained.
            match self.wait_readable(stop, deadline) {
                Ok(true) => continue, // socket readable: loop to drain
                Ok(false) => {
                    if Instant::now() >= deadline {
                        return self.latch(Latched::Err(FrameError::DeadlineExceeded));
                    }
                    // Spurious wake before the deadline: report NeedMore so the
                    // caller can re-poll. State is preserved either way.
                    return Ok(FrameOutcome::NeedMore);
                }
                Err(e @ FrameError::Stopped) => return self.latch(Latched::Err(e)),
                Err(e) => return self.latch(Latched::Err(e)),
            }
        }
    }
}

// Internal recv terminal signal.
enum FrameEof {
    Closed,
    Io(String),
}

/// Upper bound on waiting for a net worker to observe its stop signal. Mirrors
/// the block device's bounded-join discipline so a stalled worker cannot hold
/// teardown open forever: past the deadline the caller fails closed with the
/// latched timeout and the descriptors are retained (never a joined-dead state
/// that frees resources a live worker still touches).
pub const NET_WORKER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// A bounded-shutdown network worker. The worker loop is handed a shared stop
/// flag and MUST poll it between frames; `stop_join` sets the flag and joins
/// with a hard deadline, returning the worker's own result or a timeout fault.
///
/// This fixes F10's "NetWorker::run discards its JoinHandle and runs an
/// indefinite loop; Net has no checked stop/join integration": the handle is
/// retained and the join is bounded and checked.
pub struct BoundedNetWorker {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<Result<(), String>>>,
    // F10 — the FIRST terminal teardown outcome, latched PERMANENTLY. A repeated
    // stop_join after a timeout/worker-fault re-reports that fault and can never
    // return Ok on the strength of an already-consumed handle (the previous
    // defect: handle.take() -> None -> Ok masked an earlier failed teardown).
    outcome: Option<Result<(), String>>,
}

impl BoundedNetWorker {
    /// Spawn `body`, handing it the stop flag to poll. `body` returns `Ok(())`
    /// on a clean stop or `Err` describing a wire fault.
    pub fn spawn<F>(body: F) -> io::Result<Self>
    where
        F: FnOnce(Arc<AtomicBool>) -> Result<(), String> + Send + 'static,
    {
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let handle = std::thread::Builder::new()
            .name("net worker".into())
            .spawn(move || body(worker_stop))?;
        Ok(Self { stop, handle: Some(handle), outcome: None })
    }

    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    /// Signal stop and join within `NET_WORKER_SHUTDOWN_TIMEOUT`. Returns the
    /// worker's result, or `Err` with a timeout fault if it did not observe the
    /// stop in time (the handle is then abandoned on a reaper, never joined-dead
    /// inline). The FIRST terminal outcome is latched: a repeated call re-reports
    /// a clean stop as Ok and a fault as that same Err — never Ok after a fault.
    pub fn stop_join(&mut self) -> Result<(), String> {
        self.stop_join_within(NET_WORKER_SHUTDOWN_TIMEOUT)
    }

    /// `stop_join` with an explicit deadline (lets tests prove the bound
    /// without waiting the full production ceiling).
    pub fn stop_join_within(&mut self, timeout: Duration) -> Result<(), String> {
        // F10: re-report the latched first outcome. Crucially, a timeout/fault
        // latches an Err, so a repeated teardown after a failure never returns
        // Ok on the strength of the already-consumed handle.
        if let Some(outcome) = &self.outcome {
            return outcome.clone();
        }
        self.request_stop();
        let result = match self.handle.take() {
            // No worker was ever present -> a clean no-op stop.
            None => Ok(()),
            Some(handle) => {
                let (tx, rx) = mpsc::channel();
                match std::thread::Builder::new()
                    .name("net stop".into())
                    .spawn(move || {
                        let r = match handle.join() {
                            Ok(worker_result) => worker_result,
                            Err(p) => Err(format!("net worker panicked: {p:?}")),
                        };
                        let _ = tx.send(r);
                    }) {
                    Ok(_reaper) => match rx.recv_timeout(timeout) {
                        Ok(r) => r,
                        Err(_) => Err(format!(
                            "net worker did not stop within {timeout:?}; descriptors retained"
                        )),
                    },
                    Err(e) => Err(format!("net stop reaper spawn failed: {e}")),
                }
            }
        };
        self.outcome = Some(result.clone());
        result
    }
}

impl Drop for BoundedNetWorker {
    fn drop(&mut self) {
        // Best-effort bounded stop if the owner never called stop_join.
        let _ = self.stop_join();
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ControlError {
    #[error("control fd {fd} fstat failed: errno {errno}")]
    Fstat { fd: i32, errno: i32 },
    #[error("control fd {fd} must be a socket or pipe transport, not a {kind}")]
    NotTransport { fd: i32, kind: &'static str },
    #[error("control fd {control} and net fd {net} must be distinct descriptors \
             (an aliased fd would be owned — and closed — twice)")]
    Aliased { control: i32, net: i32 },
}

fn file_kind(mode: libc::mode_t) -> &'static str {
    match mode & libc::S_IFMT {
        libc::S_IFREG => "regular file",
        libc::S_IFDIR => "directory",
        libc::S_IFCHR => "character device",
        libc::S_IFBLK => "block device",
        libc::S_IFLNK => "symlink",
        _ => "non-transport object",
    }
}

/// F10: validate the control descriptor is a real transport (socket or pipe),
/// matching the header's claim. A regular file / device masquerading as the
/// control channel is refused.
pub fn validate_control_transport(fd: i32) -> Result<(), ControlError> {
    // SAFETY: fstat on a borrowed fd writes into a zeroed stat; no aliasing.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(ControlError::Fstat { fd, errno });
    }
    match st.st_mode & libc::S_IFMT {
        libc::S_IFSOCK | libc::S_IFIFO => Ok(()),
        other => Err(ControlError::NotTransport {
            fd,
            kind: file_kind(other),
        }),
    }
}

/// F10: the C boundary would construct two independent `OwnedFd`s if the caller
/// handed the SAME raw fd as both control and net — a guaranteed double-close.
/// Reject an aliased pair before either is owned.
pub fn reject_aliased(control: i32, net: i32) -> Result<(), ControlError> {
    if control >= 0 && net >= 0 && control == net {
        return Err(ControlError::Aliased { control, net });
    }
    Ok(())
}
