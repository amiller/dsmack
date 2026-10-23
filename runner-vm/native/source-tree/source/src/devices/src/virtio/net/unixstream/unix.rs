use super::super::backend::{ReadError, WriteError};
use crate::virtio::net::backend::ConnectError;
use nix::sys::socket::{
    AddressFamily, MsgFlags, SockFlag, SockType, UnixAddr, connect, getsockopt, recv, send,
    setsockopt, socket, sockopt,
};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::PathBuf;

use super::{RxState, Unixstream};

pub type RawStreamHandle = OwnedFd;

pub(crate) fn create(fd: OwnedFd) -> Unixstream {
    if let Err(e) = setsockopt(&fd, sockopt::SndBuf, &(16 * 1024 * 1024)) {
        log::warn!("Failed to increase SO_SNDBUF (performance may be decreased): {e}");
    }

    log::debug!(
        "network proxy socket (fd {fd:?}) buffer sizes: SndBuf={:?} RcvBuf={:?}",
        getsockopt(&fd, sockopt::SndBuf),
        getsockopt(&fd, sockopt::RcvBuf)
    );

    Unixstream {
        fd,
        rx_state: RxState::Header {
            got: 0,
            buf: [0u8; super::FRAME_HEADER_LEN],
        },
        rx_deadline: None,
        stop_fd: -1,
        last_partial_write_length: 0,
    }
}

pub(crate) fn open(path: PathBuf) -> Result<Unixstream, ConnectError> {
    let fd = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .map_err(ConnectError::CreateSocket)?;
    let peer_addr = UnixAddr::new(&path).map_err(ConnectError::InvalidAddress)?;
    connect(fd.as_raw_fd(), &peer_addr).map_err(ConnectError::Binding)?;

    if let Err(e) = setsockopt(&fd, sockopt::SndBuf, &(16 * 1024 * 1024)) {
        log::warn!("Failed to increase SO_SNDBUF (performance may be decreased): {e}");
    }

    log::debug!(
        "network socket (fd {fd:?}) buffer sizes: SndBuf={:?} RcvBuf={:?}",
        getsockopt(&fd, sockopt::SndBuf),
        getsockopt(&fd, sockopt::RcvBuf)
    );

    Ok(Unixstream {
        fd,
        rx_state: RxState::Header {
            got: 0,
            buf: [0u8; super::FRAME_HEADER_LEN],
        },
        rx_deadline: None,
        stop_fd: -1,
        last_partial_write_length: 0,
    })
}

pub(crate) fn start_header(fd: &OwnedFd, stop_fd: RawFd) -> Result<Option<u8>, ReadError> {
    if stop_readable(stop_fd) {
        return Err(ReadError::Internal(nix::Error::ECANCELED));
    }
    let mut byte = [0];
    loop {
        match recv(fd.as_raw_fd(), &mut byte, MsgFlags::MSG_DONTWAIT) {
            Ok(0) => return Err(ReadError::Internal(nix::Error::ECONNRESET)),
            Ok(_) => return Ok(Some(byte[0])),
            Err(nix::Error::EAGAIN) => return Ok(None),
            Err(nix::Error::EINTR) => continue,
            Err(error) => return Err(ReadError::Internal(error)),
        }
    }
}

/// dsmack v3 F10 — outcome of one stateful, stop-aware fill step.
///
/// `fill_until` drains all currently-available bytes into `buf[*got..]` with a
/// nonblocking recv, then — if more are needed — polls BOTH the socket AND the
/// stop fd against an ABSOLUTE deadline. It never loops on a per-iteration
/// counter that peer progress resets. The CALLER owns the (`got`, `buf`) state
/// across invocations, so a partial header/payload is preserved, never dropped.
pub(crate) enum FillOutcome {
    /// `*got == buf.len()`: the slice is fully filled.
    Complete,
    /// Bytes were partially filled and the socket is not currently readable; the
    /// deadline has NOT elapsed. Caller returns NothingRead and preserves state.
    WouldBlock,
    /// The stop fd became readable — a teardown was requested. Terminal.
    Stopped,
    /// The absolute frame deadline elapsed before completion. Terminal.
    DeadlineExceeded,
    /// Peer closed mid-fill (recv returned 0). Terminal EOF.
    Eof,
}

/// dsmack v3 F10 — stateful, stop-aware, absolute-deadline fill of `buf[*got..]`.
///
/// Replaces the old `read_loop`'s per-iteration spin counter (4096 × 50 ms with
/// `spins = 0` reset on progress → ~205 s of no-net-progress). Here:
///   * all available bytes are drained via nonblocking recv (EAGAIN → wait);
///   * when a wait is needed, `poll` watches the socket AND `stop_fd` with the
///     time remaining until `deadline`, so a stop breaks the wait at once and
///     the absolute deadline bounds total time regardless of earlier progress;
///   * EOF mid-fill and hard errors are terminal.
///
/// `got` and `buf` are owned by the caller (the `Unixstream` rx state), so any
/// partial progress survives across `read_frame` calls — nothing is discarded.
pub(crate) fn fill_until(
    fd: &OwnedFd,
    stop_fd: RawFd,
    buf: &mut [u8],
    got: &mut usize,
    deadline: std::time::Instant,
) -> Result<FillOutcome, ReadError> {
    #[cfg(target_os = "linux")]
    let flags = MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL;
    #[cfg(target_os = "macos")]
    let flags = MsgFlags::MSG_DONTWAIT;

    loop {
        // 1) Drain everything available right now.
        while *got < buf.len() {
            match recv(fd.as_raw_fd(), &mut buf[*got..], flags) {
                Ok(0) => return Ok(FillOutcome::Eof),
                Ok(size) => *got += size,
                #[allow(unreachable_patterns)]
                Err(nix::Error::EAGAIN | nix::Error::EWOULDBLOCK) => break,
                Err(nix::Error::EINTR) => continue,
                Err(e) => return Err(ReadError::Internal(e)),
            }
        }
        if *got == buf.len() {
            return Ok(FillOutcome::Complete);
        }

        // 2) Need more bytes: check the stop fd first, then wait on BOTH fds
        //    until the absolute deadline. A stop wins over pending socket bytes.
        if stop_readable(stop_fd) {
            return Ok(FillOutcome::Stopped);
        }
        match wait_both(fd.as_raw_fd(), stop_fd, deadline) {
            WaitOutcome::Stopped => return Ok(FillOutcome::Stopped),
            WaitOutcome::TimedOut => {
                if std::time::Instant::now() >= deadline {
                    return Ok(FillOutcome::DeadlineExceeded);
                }
                // Woke before the deadline with no readiness (spurious / short
                // clamp): report WouldBlock so the worker re-polls; state kept.
                return Ok(FillOutcome::WouldBlock);
            }
            WaitOutcome::SocketReadable => continue, // loop to drain
            WaitOutcome::HangUp => return Ok(FillOutcome::Eof),
            WaitOutcome::Error(e) => return Err(ReadError::Internal(e)),
        }
    }
}

enum WaitOutcome {
    SocketReadable,
    HangUp,
    Stopped,
    TimedOut,
    Error(nix::Error),
}

/// A zero-timeout poll of `stop_fd` for POLLIN — a pure readiness check so a
/// teardown is observed before any blocking wait.
fn stop_readable(stop_fd: RawFd) -> bool {
    if stop_fd < 0 {
        return false;
    }
    let mut pfd = [libc::pollfd {
        fd: stop_fd,
        events: libc::POLLIN,
        revents: 0,
    }];
    // SAFETY: 1-element pollfd array, 0ms timeout.
    let rc = unsafe { libc::poll(pfd.as_mut_ptr(), 1, 0) };
    rc > 0 && pfd[0].revents & libc::POLLIN != 0
}

/// Poll the socket AND the stop fd until one is ready or `deadline` elapses.
fn wait_both(sock: RawFd, stop_fd: RawFd, deadline: std::time::Instant) -> WaitOutcome {
    let now = std::time::Instant::now();
    if now >= deadline {
        return WaitOutcome::TimedOut;
    }
    let ms: i32 = (deadline - now)
        .as_millis()
        .saturating_add(1)
        .try_into()
        .unwrap_or(i32::MAX);
    let mut fds = [
        libc::pollfd {
            fd: sock,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: stop_fd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    // If no stop fd is set, poll only the socket (nfds = 1).
    let nfds = if stop_fd < 0 { 1 } else { 2 };
    // SAFETY: `fds` has 2 valid entries; nfds is 1 or 2.
    let rc = unsafe { libc::poll(fds.as_mut_ptr(), nfds, ms) };
    if rc < 0 {
        let e = nix::Error::last();
        if e == nix::Error::EINTR {
            // Interrupted: treat as a spurious short wake; caller re-checks the
            // deadline. Reported as TimedOut (no readiness).
            return WaitOutcome::TimedOut;
        }
        return WaitOutcome::Error(e);
    }
    if rc == 0 {
        return WaitOutcome::TimedOut;
    }
    // Stop takes priority over pending socket bytes.
    if nfds == 2 && fds[1].revents & libc::POLLIN != 0 {
        return WaitOutcome::Stopped;
    }
    if fds[0].revents & (libc::POLLHUP | libc::POLLERR) != 0 && fds[0].revents & libc::POLLIN == 0 {
        return WaitOutcome::HangUp;
    }
    WaitOutcome::SocketReadable
}

pub(crate) fn write_loop(stream: &mut Unixstream, buf: &[u8]) -> Result<(), WriteError> {
    let mut bytes_send = 0;

    #[cfg(target_os = "linux")]
    let flags = MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL;
    #[cfg(target_os = "macos")]
    let flags = MsgFlags::MSG_DONTWAIT;

    while bytes_send < buf.len() {
        match send(stream.fd.as_raw_fd(), &buf[bytes_send..], flags) {
            Ok(size) => bytes_send += size,
            #[allow(unreachable_patterns)]
            Err(nix::Error::EAGAIN | nix::Error::EWOULDBLOCK) => {
                if bytes_send == 0 {
                    return Err(WriteError::NothingWritten);
                } else {
                    log::trace!(
                        "Wrote {bytes_send} bytes, but socket blocked, will need try_finish_write() to finish"
                    );

                    stream.last_partial_write_length += bytes_send;
                    return Err(WriteError::PartialWrite);
                }
            }
            Err(nix::Error::EPIPE) => return Err(WriteError::ProcessNotRunning),
            Err(e) => return Err(WriteError::Internal(e)),
        }
    }
    stream.last_partial_write_length = 0;
    Ok(())
}

pub(crate) fn raw_socket_fd(fd: &OwnedFd) -> RawFd {
    fd.as_raw_fd()
}
