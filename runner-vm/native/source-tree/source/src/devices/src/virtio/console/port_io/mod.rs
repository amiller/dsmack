use log::Level;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use utils::eventfd::EventFd;
use vm_memory::{VolatileSlice, WriteVolatile};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::*;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;

pub trait PortInput {
    fn read_volatile(&mut self, buf: &mut VolatileSlice) -> Result<usize, io::Error>;

    fn wait_until_readable(&self, stopfd: Option<&EventFd>);
}

pub trait PortOutput {
    fn write_volatile(&mut self, buf: &VolatileSlice) -> Result<usize, io::Error>;

    fn wait_until_writable(&self);
}

/// Terminal properties associated with this port
pub trait PortTerminalProperties: Send + Sync {
    fn get_win_size(&self) -> (u16, u16);
}

pub fn term_fixed_size(width: u16, height: u16) -> Box<dyn PortTerminalProperties + Send + Sync> {
    Box::new(PortTerminalPropertiesFixed((width, height)))
}

pub fn output_to_log_as_err() -> Box<dyn PortOutput + Send> {
    Box::new(PortOutputLog::new())
}

/// dsmack v3 F08 — shared, latched state for a byte-capped console output. The
/// returning console worker writes through [`LimitedPortOutput`], which updates
/// this state; a handle is retained by the VMM so the backend can read the
/// REAL latched `truncated` flag after teardown instead of a hardcoded literal.
/// Once `limit` bytes have been written every further byte is dropped and
/// `truncated` latches true, so the on-disk console can never grow past the cap.
#[derive(Debug)]
pub struct ConsoleLimit {
    limit: u64,
    written: AtomicU64,
    truncated: AtomicBool,
}

impl ConsoleLimit {
    pub fn new(limit: u64) -> Arc<Self> {
        Arc::new(Self {
            limit,
            written: AtomicU64::new(0),
            truncated: AtomicBool::new(false),
        })
    }
    /// The REAL latched truncation state (not a literal). True iff at least one
    /// console byte was dropped because the cap was reached.
    pub fn truncated(&self) -> bool {
        self.truncated.load(Ordering::SeqCst)
    }
    pub fn bytes_written(&self) -> u64 {
        self.written.load(Ordering::SeqCst)
    }
    pub fn limit(&self) -> u64 {
        self.limit
    }
}

/// dsmack v3 F08 — a [`PortOutput`] wrapper that caps total bytes forwarded to
/// the inner console sink at `state.limit`, truncating the final write to the
/// remaining budget and dropping everything after (latching `truncated`). This
/// is the actual native console sink the returning profile installs, so the
/// guest console can never grow unbounded and the latched truncation is a real
/// observation the finalize step consumes. Writer errors from the inner sink
/// propagate unchanged (never swallowed).
pub struct LimitedPortOutput {
    inner: Box<dyn PortOutput + Send>,
    state: Arc<ConsoleLimit>,
}

impl LimitedPortOutput {
    pub fn new(inner: Box<dyn PortOutput + Send>, state: Arc<ConsoleLimit>) -> Self {
        Self { inner, state }
    }
}

impl PortOutput for LimitedPortOutput {
    fn write_volatile(&mut self, buf: &VolatileSlice) -> Result<usize, io::Error> {
        let already = self.state.written.load(Ordering::SeqCst);
        let remaining = self.state.limit.saturating_sub(already);
        let len = buf.len() as u64;
        if remaining == 0 {
            // Cap reached: drop the whole chunk, latch truncation. Report it as
            // consumed so the guest TX ring advances (the guest is never
            // blocked by the host-side cap).
            self.state.truncated.store(true, Ordering::SeqCst);
            return Ok(buf.len());
        }
        if len <= remaining {
            // Entirely within budget: forward verbatim; propagate writer errors.
            let n = self.inner.write_volatile(buf)?;
            self.state.written.fetch_add(n as u64, Ordering::SeqCst);
            Ok(n)
        } else {
            // Straddles the cap: forward EXACTLY the remaining budget (so the
            // on-disk console is <= limit exactly, CONSOLE_SLACK_BYTES == 0),
            // latch truncation, and report the whole chunk consumed.
            let allow = remaining as usize;
            let sub = buf
                .subslice(0, allow)
                .map_err(|e| io::Error::other(format!("console subslice: {e:?}")))?;
            let n = self.inner.write_volatile(&sub)?;
            self.state.written.fetch_add(n as u64, Ordering::SeqCst);
            self.state.truncated.store(true, Ordering::SeqCst);
            // If the inner sink made only a partial write of the final slice,
            // report that partial count so the caller re-drives the remainder;
            // otherwise report the whole chunk consumed (the excess is dropped).
            if n < allow {
                Ok(n)
            } else {
                Ok(buf.len())
            }
        }
    }

    fn wait_until_writable(&self) {
        self.inner.wait_until_writable()
    }
}

struct PortTerminalPropertiesFixed((u16, u16));

impl PortTerminalProperties for PortTerminalPropertiesFixed {
    fn get_win_size(&self) -> (u16, u16) {
        self.0
    }
}

#[derive(Default)]
pub struct PortOutputLog {
    buf: Vec<u8>,
}

impl PortOutputLog {
    const FORCE_FLUSH_TRESHOLD: usize = 512;
    const LOG_TARGET: &'static str = "init_or_kernel";

    fn new() -> Self {
        Self::default()
    }

    fn force_flush(&mut self) {
        log::log!(target: PortOutputLog::LOG_TARGET, Level::Error, "[missing newline]{}", String::from_utf8_lossy(&self.buf));
        self.buf.clear();
    }
}

impl PortOutput for PortOutputLog {
    fn write_volatile(&mut self, buf: &VolatileSlice) -> Result<usize, io::Error> {
        self.buf.write_volatile(buf).map_err(io::Error::other)?;

        let mut start = 0;
        for (i, ch) in self.buf.iter().cloned().enumerate() {
            if ch == b'\n' {
                log::log!(target: PortOutputLog::LOG_TARGET, Level::Error, "{}", String::from_utf8_lossy(&self.buf[start..i]));
                start = i + 1;
            }
        }
        self.buf.drain(0..start);
        // Make sure to not grow the internal buffer forever!
        if self.buf.len() > PortOutputLog::FORCE_FLUSH_TRESHOLD {
            self.force_flush()
        }
        Ok(buf.len())
    }

    fn wait_until_writable(&self) {}
}

pub struct PortInputEmpty {}

impl PortInputEmpty {
    pub fn new() -> Self {
        PortInputEmpty {}
    }
}

impl Default for PortInputEmpty {
    fn default() -> Self {
        Self::new()
    }
}
