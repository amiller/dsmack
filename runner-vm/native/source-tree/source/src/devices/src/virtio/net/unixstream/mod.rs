use std::path::PathBuf;

#[cfg(unix)]
use std::os::fd::{OwnedFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::RawSocket;

use crate::virtio::net::backend::ConnectError;

use super::backend::{NetBackend, ReadError, WriteError};
#[cfg(unix)]
use super::write_virtio_net_hdr;

// Conditional compilation to pick the right platform implementation
#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as sys;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as sys;

/// Each frame the network proxy is prepended by a 4 byte "header".
/// It is interpreted as a big-endian u32 integer and is the length of the following ethernet frame.
#[cfg(unix)]
const FRAME_HEADER_LEN: usize = 4;

/// dsmack v3 (F10 / "Native frame admission") — admission bounds on the trusted
/// unixstream. A valid Ethernet frame is dst(6)+src(6)+ethertype(2) = 14 bytes
/// minimum and 65535 bytes maximum (the 16-bit length domain of the qemu
/// protocol prefix). A 4-byte big-endian prefix outside this range is REFUSED
/// fail-closed BEFORE any payload slice or read, on BOTH directions: the reader
/// previously sliced `buf[..frame_length]` on an UNCHECKED peer length (a length
/// greater than the buffer panics the slice; a sub-14 or zero length is the
/// wedging input the helper's trust boundary documents), and the writer must
/// never emit a prefix outside the admitted range. This mirrors the host-proven
/// `dsmack_backend_v3::framing` bound (which also rejects 0 and oversized but
/// accepted 1..=13 at the wrapper layer — the gate's named residual gap).
#[cfg(unix)]
const MIN_ETHERNET_FRAME_BYTES: usize = 14;
#[cfg(unix)]
const MAX_ETHERNET_FRAME_BYTES: usize = 65_535;

/// dsmack v3 F10 — upper bound on assembling a SINGLE frame on the trusted
/// unixstream. It is an ABSOLUTE monotonic instant fixed when a frame starts
/// (header or payload), NOT a per-iteration spin counter that peer progress
/// resets. The old reader allowed 4096 waits of 50 ms (~205 s) and RESET that
/// budget on every byte, so a slow trickle gave effectively unbounded no-net-
/// progress against the 5 s worker-shutdown bound. 3 s keeps a single frame's
/// read strictly under that shutdown ceiling; the stop fd (polled alongside the
/// socket) breaks the wait sooner on an actual teardown.
#[cfg(unix)]
const FRAME_READ_DEADLINE: std::time::Duration = std::time::Duration::from_secs(3);

/// dsmack v3 F10 — the stateful frame-assembly position. The reader preserves
/// this ACROSS `read_frame` calls so a partial header or partial payload is
/// never dropped (the old reader filled a LOCAL buffer and lost the consumed
/// bytes on timeout, desynchronizing the next frame). A terminal fault latches
/// `Failed`; once failed the transport is finished and never resumes.
#[cfg(unix)]
#[derive(Clone, Copy)]
enum RxState {
    /// Accumulating the 4-byte big-endian length header.
    Header {
        got: usize,
        buf: [u8; FRAME_HEADER_LEN],
    },
    /// Header complete; filling `got` of `len` payload bytes into the caller's
    /// rx buffer (offset by the virtio-net header length).
    Payload { len: usize, got: usize },
    /// A terminal transport fault was latched; re-reported on every call.
    Failed,
}

#[cfg(unix)]
pub struct Unixstream {
    fd: OwnedFd,
    // dsmack v3 F10 — stateful frame-assembly position (see RxState).
    rx_state: RxState,
    // dsmack v3 F10 — the absolute deadline for the frame currently being
    // assembled, set when the header or payload phase begins; None between
    // frames. Peer progress does NOT move it.
    rx_deadline: Option<std::time::Instant>,
    // dsmack v3 F10 — the worker's stop eventfd, polled ALONGSIDE the socket so a
    // teardown breaks a partial-frame read promptly instead of after ~205 s. -1
    // until the worker injects it (set_stop_fd).
    stop_fd: RawFd,
    // 0 if last write is fully complete, otherwise the length that was written
    last_partial_write_length: usize,
}

#[cfg(unix)]
impl Unixstream {
    /// Create the backend with a pre-established connection to the userspace network proxy.
    pub fn new(fd: sys::RawStreamHandle) -> Self {
        sys::create(fd)
    }
    /// Create the backend opening a connection to the userspace network proxy.
    pub fn open(path: PathBuf) -> Result<Self, ConnectError> {
        sys::open(path)
    }
    fn write_loop(&mut self, buf: &[u8]) -> Result<(), WriteError> {
        sys::write_loop(self, buf)
    }

    /// dsmack v3 F10 — the absolute deadline for the frame currently being
    /// assembled. Set once when a phase begins (header or payload); peer
    /// progress does NOT move it, so a slow trickle cannot extend the budget.
    fn frame_deadline(&mut self) -> std::time::Instant {
        *self
            .rx_deadline
            .get_or_insert_with(|| std::time::Instant::now() + FRAME_READ_DEADLINE)
    }

    /// dsmack v3 F10 — latch a terminal transport fault. The state becomes
    /// `Failed`; every subsequent `read_frame` re-reports the same error so a
    /// log-and-continue can never desynchronize framing, and the worker tears
    /// the rx path down. Returns the error for convenient `return`.
    fn fail(&mut self, e: nix::Error) -> ReadError {
        self.rx_state = RxState::Failed;
        self.rx_deadline = None;
        ReadError::Internal(e)
    }
}

#[cfg(unix)]
impl NetBackend for Unixstream {
    /// dsmack v3 F10 — stateful, stop-aware, absolute-deadline frame reader.
    ///
    /// Drives a header→payload state machine whose partial progress is preserved
    /// in `self.rx_state` ACROSS calls (the old reader filled a local buffer and
    /// dropped it on timeout, desynchronizing the next frame). `fill_until`
    /// polls BOTH the socket and the worker stop fd against a fixed deadline, so
    /// a teardown breaks the read promptly and no progress-reset counter can
    /// permit ~205 s of no net progress. EOF / deadline / stop / an out-of-range
    /// length are LATCHED as a terminal `Failed` state surfaced as
    /// `ReadError::Internal`, which the worker treats as a terminal rx fault.
    fn read_frame(&mut self, buf: &mut [u8]) -> Result<usize, ReadError> {
        // Terminal fault: re-report (do not attempt a fresh read on a dead
        // transport). ECONNABORTED stands in for "transport already failed".
        if matches!(self.rx_state, RxState::Failed) {
            return Err(ReadError::Internal(nix::Error::ECONNABORTED));
        }

        let hdr_len = write_virtio_net_hdr(buf);

        // ---- Phase 1: assemble the 4-byte length header (stateful) ----
        if let RxState::Header {
            mut got,
            buf: mut hbuf,
        } = self.rx_state
        {
            if got == 0 {
                match sys::start_header(&self.fd, self.stop_fd) {
                    Ok(Some(byte)) => {
                        hbuf[0] = byte;
                        got = 1;
                    }
                    Ok(None) => return Err(ReadError::NothingRead),
                    Err(ReadError::Internal(error)) => return Err(self.fail(error)),
                    Err(error) => return Err(error),
                }
            }
            let deadline = self.frame_deadline();
            let outcome =
                match sys::fill_until(&self.fd, self.stop_fd, &mut hbuf, &mut got, deadline) {
                    Ok(outcome) => outcome,
                    Err(ReadError::Internal(error)) => return Err(self.fail(error)),
                    Err(error) => return Err(error),
                };
            // Persist progress regardless of outcome (partial header preserved).
            self.rx_state = RxState::Header { got, buf: hbuf };
            match outcome {
                sys::FillOutcome::Complete => {}
                sys::FillOutcome::WouldBlock => {
                    // No frame has actually STARTED yet (no header byte read):
                    // this is an IDLE connection, not a frame-in-progress. Clear
                    // the just-armed deadline so a frame that arrives after a
                    // long idle period is not judged against a stale instant.
                    // Once any header byte is buffered the deadline is retained
                    // (an in-progress frame IS on the clock).
                    if got == 0 {
                        self.rx_deadline = None;
                    }
                    return Err(ReadError::NothingRead);
                }
                sys::FillOutcome::Stopped => return Err(self.fail(nix::Error::ECANCELED)),
                sys::FillOutcome::DeadlineExceeded => return Err(self.fail(nix::Error::ETIMEDOUT)),
                sys::FillOutcome::Eof => {
                    // Clean EOF exactly at a boundary (no header bytes yet) vs a
                    // partial header mid-read: both are terminal; a partial
                    // header is a transport fault, a clean boundary EOF is the
                    // peer closing — fail closed either way so the worker stops.
                    return Err(self.fail(nix::Error::ECONNRESET));
                }
            }

            let frame_length = u32::from_be_bytes(hbuf) as usize;
            let payload_buf = &mut buf[hdr_len..];
            // F10 admission: reject an out-of-range peer length BEFORE allocating
            // or reading the payload. An unchecked length would panic the slice
            // (frame_length > buf.len()) or admit a sub-minimum/zero frame.
            if frame_length < MIN_ETHERNET_FRAME_BYTES
                || frame_length > MAX_ETHERNET_FRAME_BYTES
                || frame_length > payload_buf.len()
            {
                return Err(self.fail(nix::Error::EINVAL));
            }
            // Transition to the payload phase; keep the SAME absolute deadline so
            // a header that just finished does not reset the budget.
            self.rx_state = RxState::Payload {
                len: frame_length,
                got: 0,
            };
        }

        // ---- Phase 2: fill the payload into the caller's buffer (stateful) ----
        let (len, mut got) = match self.rx_state {
            RxState::Payload { len, got } => (len, got),
            // Only reachable if Header just completed above; handled there.
            _ => unreachable!("rx_state must be Payload after header completion"),
        };
        let deadline = self.frame_deadline();
        let payload = &mut buf[hdr_len..hdr_len + len];
        let outcome = match sys::fill_until(&self.fd, self.stop_fd, payload, &mut got, deadline) {
            Ok(outcome) => outcome,
            Err(ReadError::Internal(error)) => return Err(self.fail(error)),
            Err(error) => return Err(error),
        };
        // Persist partial payload progress across calls (bytes already in `buf`).
        self.rx_state = RxState::Payload { len, got };
        match outcome {
            sys::FillOutcome::Complete => {
                // Frame complete: reset to a fresh header phase and clear the
                // deadline so the NEXT frame gets its own budget.
                self.rx_state = RxState::Header {
                    got: 0,
                    buf: [0u8; FRAME_HEADER_LEN],
                };
                self.rx_deadline = None;
                log::trace!("Read eth frame from network proxy: {len} bytes");
                Ok(hdr_len + len)
            }
            sys::FillOutcome::WouldBlock => Err(ReadError::NothingRead),
            sys::FillOutcome::Stopped => Err(self.fail(nix::Error::ECANCELED)),
            sys::FillOutcome::DeadlineExceeded => Err(self.fail(nix::Error::ETIMEDOUT)),
            sys::FillOutcome::Eof => Err(self.fail(nix::Error::ECONNRESET)),
        }
    }

    fn write_frame(&mut self, hdr_len: usize, buf: &mut [u8]) -> Result<(), WriteError> {
        if self.last_partial_write_length != 0 {
            panic!("Cannot write a frame to the proxy, while a partial write is not resolved.");
        }
        assert!(
            hdr_len >= FRAME_HEADER_LEN,
            "Not enough space to write the frame header"
        );
        assert!(buf.len() > hdr_len);
        let frame_length = buf.len() - hdr_len;
        // F10 admission: the trusted writer must never emit a prefix outside the
        // admitted Ethernet range. A sub-minimum frame wedges the upstream
        // switch (documented trust boundary); an oversized one exceeds the
        // 16-bit length domain. Refuse fail-closed before emitting any bytes.
        if frame_length < MIN_ETHERNET_FRAME_BYTES || frame_length > MAX_ETHERNET_FRAME_BYTES {
            return Err(WriteError::Internal(nix::Error::EINVAL));
        }
        buf[hdr_len - FRAME_HEADER_LEN..hdr_len]
            .copy_from_slice(&(frame_length as u32).to_be_bytes());
        self.write_loop(&buf[hdr_len - FRAME_HEADER_LEN..])
    }

    fn has_unfinished_write(&self) -> bool {
        self.last_partial_write_length != 0
    }

    fn try_finish_write(&mut self, hdr_len: usize, buf: &[u8]) -> Result<(), WriteError> {
        if self.last_partial_write_length != 0 {
            let already_written = self.last_partial_write_length;
            log::trace!("Requested to finish partial write");
            self.write_loop(&buf[hdr_len - FRAME_HEADER_LEN + already_written..])?;
            self.last_partial_write_length = 0;
            log::debug!("Finished partial write ({already_written} bytes written before)");
        }
        Ok(())
    }

    fn raw_socket_fd(&self) -> RawFd {
        sys::raw_socket_fd(&self.fd)
    }

    /// dsmack v3 F10 — adopt the worker's stop eventfd so a mid-frame wait polls
    /// it alongside the socket and breaks promptly on teardown.
    fn set_stop_fd(&mut self, fd: RawFd) {
        self.stop_fd = fd;
    }
}

#[cfg(windows)]
pub struct Unixstream {
    pub(crate) fd: sys::RawStreamHandle,
    _winsock: sys::WinsockGuard,
    tx_buffer: Box<[u8]>,
    tx_len: usize,
    tx_offset: usize,
    rx_buffer: Vec<u8>,
    rx_frame_buffer: Box<[u8]>,
    rx_buf_end: usize,
    rx_terminal: Option<sys::RxTerminal>,
}

#[cfg(windows)]
impl Unixstream {
    /// Create the backend with a pre-established connection to the userspace network proxy.
    pub fn new(fd: sys::RawStreamHandle) -> Result<Self, ConnectError> {
        sys::create(fd)
    }
    /// Create the backend opening a connection to the userspace network proxy.
    pub fn open(path: PathBuf) -> Result<Self, ConnectError> {
        sys::open(path)
    }
}

#[cfg(windows)]
impl NetBackend for Unixstream {
    fn raw_socket_fd(&self) -> RawSocket {
        sys::raw_socket_fd(&self.fd)
    }

    fn prepare_tx_buffer(&mut self) -> &mut [u8] {
        sys::prepare_tx_buffer(self)
    }

    fn start_tx(&mut self, total_bytes: usize) -> Result<super::backend::WriteStatus, WriteError> {
        sys::start_tx(self, total_bytes)
    }

    fn resume_tx(&mut self) -> Result<super::backend::WriteStatus, WriteError> {
        sys::resume_tx(self)
    }

    fn read_frames_to_guest(
        &mut self,
        mem: &vm_memory::GuestMemoryMmap,
        rx_queue: &mut crate::virtio::queue::Queue,
    ) -> Result<u32, ReadError> {
        sys::read_frames_to_guest(self, mem, rx_queue)
    }
}

#[cfg(all(test, unix))]
mod native_reader_tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    fn pair() -> (Unixstream, UnixStream) {
        let (reader, writer) = UnixStream::pair().unwrap();
        (Unixstream::new(reader.into()), writer)
    }
    fn idle(reader: &mut Unixstream, buf: &mut [u8]) {
        let now = Instant::now();
        assert!(matches!(
            reader.read_frame(buf),
            Err(ReadError::NothingRead)
        ));
        assert!(
            now.elapsed() < Duration::from_millis(100),
            "idle read blocked"
        );
        assert!(reader.rx_deadline.is_none());
    }
    #[test]
    fn native_initial_idle() {
        let (mut reader, _writer) = pair();
        idle(&mut reader, &mut [0; 65560]);
    }
    #[test]
    fn native_complete_frame_then_idle() {
        let (mut reader, mut writer) = pair();
        writer.write_all(&14u32.to_be_bytes()).unwrap();
        writer.write_all(&[7; 14]).unwrap();
        let mut buf = [0; 65560];
        assert!(reader.read_frame(&mut buf).is_ok());
        idle(&mut reader, &mut buf);
        std::thread::sleep(FRAME_READ_DEADLINE + Duration::from_millis(10));
        idle(&mut reader, &mut buf);
        writer.write_all(&14u32.to_be_bytes()).unwrap();
        writer.write_all(&[8; 14]).unwrap();
        assert!(reader.read_frame(&mut buf).is_ok());
    }
    #[test]
    fn native_partial_header_deadline_latches() {
        let (mut reader, mut writer) = pair();
        writer.write_all(&[0]).unwrap();
        assert!(matches!(
            reader.read_frame(&mut [0; 65560]),
            Err(ReadError::Internal(nix::Error::ETIMEDOUT))
        ));
        assert!(matches!(
            reader.read_frame(&mut [0; 65560]),
            Err(ReadError::Internal(nix::Error::ECONNABORTED))
        ));
    }
    #[test]
    fn native_partial_payload_stop_and_repeated_read() {
        let (mut reader, mut writer) = pair();
        let (stop_reader, mut stop_writer) = UnixStream::pair().unwrap();
        reader.set_stop_fd(stop_reader.as_raw_fd());
        writer.write_all(&14u32.to_be_bytes()).unwrap();
        writer.write_all(&[4]).unwrap();
        let stopper = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            stop_writer.write_all(&[1]).unwrap();
        });
        let now = Instant::now();
        assert!(matches!(
            reader.read_frame(&mut [0; 65560]),
            Err(ReadError::Internal(nix::Error::ECANCELED))
        ));
        assert!(now.elapsed() < Duration::from_secs(1));
        assert!(matches!(
            reader.read_frame(&mut [0; 65560]),
            Err(ReadError::Internal(nix::Error::ECONNABORTED))
        ));
        stopper.join().unwrap();
    }
    #[test]
    fn native_eof_latches() {
        let (mut reader, writer) = pair();
        drop(writer);
        assert!(matches!(
            reader.read_frame(&mut [0; 65560]),
            Err(ReadError::Internal(nix::Error::ECONNRESET))
        ));
        assert!(matches!(
            reader.read_frame(&mut [0; 65560]),
            Err(ReadError::Internal(nix::Error::ECONNABORTED))
        ));
    }
}
