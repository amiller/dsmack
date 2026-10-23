use std::borrow::Cow;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use std::{mem, thread};

use vm_memory::GuestMemoryMmap;

use crate::virtio::console::console_control::ConsoleControl;
use crate::virtio::console::port_io::{PortInput, PortOutput};
use crate::virtio::console::process_rx::process_rx;
use crate::virtio::console::process_tx::process_tx;
use crate::virtio::port_io::PortTerminalProperties;
use crate::virtio::{InterruptTransport, Queue};

pub struct PortDescription {
    pub name: Cow<'static, str>,
    pub input: Option<Box<dyn PortInput + Send>>,
    pub output: Option<Box<dyn PortOutput + Send>>,
    pub terminal: Option<Box<dyn PortTerminalProperties>>,
}

impl PortDescription {
    pub fn console(
        input: Option<Box<dyn PortInput + Send>>,
        output: Option<Box<dyn PortOutput + Send>>,
        terminal: Box<dyn PortTerminalProperties>,
    ) -> Self {
        Self {
            name: "".into(),
            input,
            output,
            terminal: Some(terminal),
        }
    }

    pub fn output_pipe(
        name: impl Into<Cow<'static, str>>,
        output: Box<dyn PortOutput + Send>,
    ) -> Self {
        Self {
            name: name.into(),
            input: None,
            output: Some(output),
            terminal: None,
        }
    }

    pub fn input_pipe(
        name: impl Into<Cow<'static, str>>,
        input: Box<dyn PortInput + Send>,
    ) -> Self {
        Self {
            name: name.into(),
            input: Some(input),
            output: None,
            terminal: None,
        }
    }
}

enum PortState {
    Inactive,
    Active {
        stopfd: utils::eventfd::EventFd,
        stop: Arc<AtomicBool>,
        rx_thread: Option<JoinHandle<()>>,
        tx_thread: Option<JoinHandle<()>>,
    },
}

pub(crate) struct Port {
    port_id: u32,
    /// Empty if no name given
    name: Cow<'static, str>,
    state: PortState,
    input: Option<Arc<Mutex<Box<dyn PortInput + Send>>>>,
    output: Option<Arc<Mutex<Box<dyn PortOutput + Send>>>>,
    terminal: Option<Box<dyn PortTerminalProperties>>,
    // Writer errors observed by the port workers, reported by `shutdown` so a
    // lifecycle that must fail closed can suppress a successful return.
    errors: Arc<Mutex<Vec<String>>>,
    // A7 (R2-REVIEW-1): first shutdown fault, latched for the life of the
    // port. Neither reset() nor a restart may observe a clean state after a
    // shutdown failure: "no worker handle present" must never be mistaken for
    // "worker termination proven". A leaked (timed-out) worker keeps its
    // guest-memory clone alive; the latch is what every later shutdown,
    // checked exit and start() consults.
    shutdown_fault: Option<String>,
}

impl Port {
    pub(crate) fn new(port_id: u32, description: PortDescription) -> Self {
        Self {
            port_id,
            name: description.name,
            state: PortState::Inactive,
            input: description.input.map(|input| Arc::new(Mutex::new(input))),
            output: description
                .output
                .map(|output| Arc::new(Mutex::new(output))),
            terminal: description.terminal,
            errors: Arc::new(Mutex::new(Vec::new())),
            shutdown_fault: None,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// The latched shutdown fault, if this port ever failed to shut down.
    #[cfg(test)]
    pub(crate) fn shutdown_fault(&self) -> Option<&str> {
        self.shutdown_fault.as_deref()
    }

    /// A7 fault-injection seam (test builds only): clone of the worker input
    /// handle, so device-level tests can hold the mutex (timeout fault) or
    /// poison it (panic fault) through the real `process_rx` code paths.
    #[cfg(test)]
    pub(crate) fn input_arc_for_fault_injection(
        &self,
    ) -> Option<Arc<Mutex<Box<dyn PortInput + Send>>>> {
        self.input.clone()
    }

    pub fn terminal(&self) -> Option<&dyn PortTerminalProperties> {
        self.terminal.as_deref()
    }

    pub fn notify_rx(&self) {
        if let PortState::Active {
            rx_thread: Some(handle),
            ..
        } = &self.state
        {
            handle.thread().unpark()
        }
    }

    pub fn notify_tx(&self) {
        if let PortState::Active {
            tx_thread: Some(handle),
            ..
        } = &self.state
        {
            handle.thread().unpark()
        }
    }

    pub fn start(
        &mut self,
        mem: GuestMemoryMmap,
        rx_queue: Queue,
        tx_queue: Queue,
        interrupt: InterruptTransport,
        control: Arc<ConsoleControl>,
    ) {
        // A7: a faulted port never runs again — a restart would detach the
        // previous workers' unproven termination behind a fresh-looking Active
        // state.
        if let Some(fault) = &self.shutdown_fault {
            log::error!(
                "start of port {port_id} refused, latched shutdown fault: {fault}",
                port_id = self.port_id
            );
            return;
        }
        if let PortState::Active { .. } = &mut self.state
            && let Err(e) = self.shutdown()
        {
            // shutdown() latched the fault above: refuse the restart instead
            // of proceeding over a dirty shutdown.
            log::error!(
                "restart of port {port_id} refused over dirty shutdown: {e}",
                port_id = self.port_id
            );
            return;
        }

        let input = self.input.as_ref().cloned();
        let output = self.output.as_ref().cloned();

        let stopfd = utils::eventfd::EventFd::new(utils::eventfd::EFD_NONBLOCK)
            .expect("Failed to create EventFd for interrupt_evt");
        let stop = Arc::new(AtomicBool::new(false));

        let rx_thread = input.map(|input| {
            let mem = mem.clone();
            let interrupt = interrupt.clone();
            let port_id = self.port_id;
            let stopfd = stopfd.try_clone().unwrap();
            let stop = stop.clone();
            thread::Builder::new()
                .name("console port".into())
                .spawn(move || {
                    process_rx(
                        mem, rx_queue, interrupt, input, control, port_id, stopfd, stop,
                    )
                })
                .unwrap()
        });

        let tx_thread = output.map(|output| {
            let stop = stop.clone();
            let errors = self.errors.clone();
            thread::spawn(move || process_tx(mem, tx_queue, interrupt, output, stop, errors))
        });

        self.state = PortState::Active {
            stopfd,
            stop,
            rx_thread,
            tx_thread,
        }
    }

    /// Stops the port workers and reports every failure: writer errors recorded
    /// while the port ran, worker panics, and workers that failed to stop within
    /// [`PORT_SHUTDOWN_TIMEOUT`]. Any failure is LATCHED for the life of the
    /// port (A7): a second call after a failed shutdown re-reports the first
    /// fault instead of returning Ok on the strength of already-taken worker
    /// handles, and a latched port refuses `start`. Callers that must fail
    /// closed (the returning lifecycle) suppress a successful return on `Err`;
    /// the legacy path keeps logging only.
    pub fn shutdown(&mut self) -> std::result::Result<(), String> {
        if let Some(fault) = &self.shutdown_fault {
            return Err(fault.clone());
        }
        let mut errors = Vec::new();
        if let PortState::Active {
            stopfd,
            stop,
            tx_thread,
            rx_thread,
        } = &mut self.state
        {
            stop.store(true, Ordering::Release);
            if let Some(tx_thread) = mem::take(tx_thread) {
                tx_thread.thread().unpark();
                if let Err(e) = join_bounded(tx_thread, "tx", PORT_SHUTDOWN_TIMEOUT) {
                    log::error!(
                        "Failed to flush tx for port {port_id}: {e}",
                        port_id = self.port_id
                    );
                    errors.push(format!("tx worker: {e}"));
                }
            }
            if let Err(e) = stopfd.write(1) {
                let msg = format!("stop signal: {e}");
                log::error!(
                    "Failed to signal rx stop for port {port_id}: {e}",
                    port_id = self.port_id
                );
                errors.push(msg);
            }
            if let Some(rx_thread) = mem::take(rx_thread) {
                rx_thread.thread().unpark();
                if let Err(e) = join_bounded(rx_thread, "rx", PORT_SHUTDOWN_TIMEOUT) {
                    log::error!(
                        "Failed to flush rx for port {port_id}: {e}",
                        port_id = self.port_id
                    );
                    errors.push(format!("rx worker: {e}"));
                }
            }
            // The workers are gone (joined, or detached past the deadline with
            // the fault recorded); nobody else can touch the sink now. A
            // poisoned sink means a worker panicked while recording, which is
            // itself an error.
            match self.errors.lock() {
                Ok(mut guard) => errors.append(&mut guard),
                Err(poisoned) => {
                    errors.push("console error sink poisoned by panicked worker".to_string());
                    errors.append(&mut poisoned.into_inner());
                }
            }
        };
        // Worker handles are gone either way; the LATCH, not the missing
        // handles, is what later callers consult.
        self.state = PortState::Inactive;
        if errors.is_empty() {
            Ok(())
        } else {
            let fault = errors.join("; ");
            self.shutdown_fault = Some(fault.clone());
            Err(fault)
        }
    }
}

/// Upper bound on waiting for a port worker to observe the stop flag. A worker
/// blocked past this (e.g. parked in `wait_until_writable`) is leaked rather
/// than joined: the caller fails closed on the reported error either way.
const PORT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

fn join_bounded(
    handle: JoinHandle<()>,
    worker: &str,
    timeout: Duration,
) -> std::result::Result<(), String> {
    let deadline = Instant::now() + timeout;
    while !handle.is_finished() {
        if Instant::now() >= deadline {
            return Err(format!("{worker} worker did not exit within {timeout:?}"));
        }
        thread::sleep(Duration::from_millis(1));
    }
    handle.join().map_err(|panic| {
        let detail = panic
            .downcast_ref::<&str>()
            .map(|s| (*s).to_string())
            .or_else(|| panic.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "non-string panic payload".to_string());
        format!("{worker} worker panicked: {detail}")
    })?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::legacy::DummyIrqChip;
    use std::io;
    use utils::eventfd::EventFd;
    use vm_memory::{GuestAddress, GuestMemoryMmap, VolatileSlice};

    pub(crate) fn test_mem() -> GuestMemoryMmap {
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 1 << 20)]).unwrap()
    }

    pub(crate) fn test_interrupt() -> InterruptTransport {
        InterruptTransport::new(DummyIrqChip::new().into(), "console-test".to_string()).unwrap()
    }

    pub(crate) fn test_queues() -> (Queue, Queue) {
        (
            Queue::new(crate::virtio::console::defs::QUEUE_SIZE),
            Queue::new(crate::virtio::console::defs::QUEUE_SIZE),
        )
    }

    /// Input whose only role is to be locked by `process_rx` as its very first
    /// action: holding the `Arc<Mutex<..>>` from a test blocks the worker past
    /// any deadline (timeout fault), poisoning it makes the worker panic
    /// (panic fault) — both through the real worker code paths.
    pub(crate) struct MutexFaultInput;

    impl PortInput for MutexFaultInput {
        fn read_volatile(&mut self, _buf: &mut VolatileSlice) -> io::Result<usize> {
            Ok(0)
        }

        fn wait_until_readable(&self, _stopfd: Option<&EventFd>) {}
    }

    /// Output sink that accepts everything (used where the tx side only needs
    /// to run and stop cleanly).
    pub(crate) struct SinkOutput;

    impl PortOutput for SinkOutput {
        fn write_volatile(&mut self, buf: &VolatileSlice) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn wait_until_writable(&self) {}
    }

    fn new_port() -> Port {
        Port::new(
            0,
            PortDescription::input_pipe("dut", Box::new(MutexFaultInput)),
        )
    }

    fn start(port: &mut Port) {
        let (rx, tx) = test_queues();
        port.start(
            test_mem(),
            rx,
            tx,
            test_interrupt(),
            ConsoleControl::new(),
        );
    }

    #[test]
    fn clean_shutdown_is_ok_repeatable_and_allows_restart() {
        let mut port = new_port();
        start(&mut port);
        port.shutdown().expect("clean shutdown");
        port.shutdown().expect("repeatable clean shutdown");
        assert!(port.shutdown_fault().is_none());
        // Restart over a clean shutdown starts fresh workers, which stop cleanly.
        start(&mut port);
        port.shutdown().expect("clean shutdown after restart");
        assert!(port.shutdown_fault().is_none());
    }

    #[test]
    fn shutdown_timeout_is_latched_and_blocks_restart() {
        let mut port = new_port();
        start(&mut port);
        // Hold the input mutex: the rx worker blocks in its first `input.lock()`
        // and can never observe the stop flag — the real timeout path. The Arc
        // is cloned first so `port` stays free for the mutable shutdown calls.
        let input = port.input.clone().unwrap();
        let guard = input.lock().unwrap();
        let err = port.shutdown().unwrap_err();
        assert!(
            err.contains("rx worker did not exit within"),
            "expected timeout fault, got: {err}"
        );
        assert_eq!(
            port.shutdown().unwrap_err(),
            err,
            "latched fault must re-report identically"
        );
        drop(guard);
        // A latched port refuses to start. A fresh worker would shut down
        // cleanly, so a clean Ok (or any non-latched error) here would mean
        // the refusal failed and a new worker was spawned over the fault.
        start(&mut port);
        let err2 = port.shutdown().unwrap_err();
        assert!(
            err2.contains("did not exit within"),
            "start must be refused by the latch, got: {err2}"
        );
    }

    #[test]
    fn worker_panic_is_latched() {
        let mut port = new_port();
        let input = port.input.as_ref().unwrap().clone();
        // Poison the input mutex: the worker's `input.lock().unwrap()` panics.
        let _ = std::thread::spawn(move || {
            let _guard = input.lock().unwrap();
            panic!("injected");
        })
        .join();
        start(&mut port);
        let err = port.shutdown().unwrap_err();
        assert!(
            err.contains("rx worker panicked"),
            "expected panic fault, got: {err}"
        );
        assert_eq!(port.shutdown().unwrap_err(), err, "latch re-reports");
    }

    #[test]
    fn stop_signal_failure_is_latched() {
        let mut port = new_port();
        start(&mut port);
        // The stop-signal latch code point is the `errors.push` + latch
        // assignment after a failed `EventFd::write`; a real eventfd write
        // cannot be made to fail in-process without closing the owned
        // descriptor, which Rust IO safety turns into a fatal abort at Drop.
        // Exactly like the accepted block-device test, the fault is injected
        // and the latch/reset/checked-exit behavior around it is exercised
        // for real (the latch ASSIGNMENT itself runs in the timeout/panic
        // tests through the live shutdown path).
        port.shutdown_fault = Some("stop signal: Bad file descriptor (injected)".to_string());
        let err = port.shutdown().unwrap_err();
        assert!(
            err.contains("stop signal"),
            "expected stop-signal fault, got: {err}"
        );
        assert_eq!(port.shutdown().unwrap_err(), err, "latch re-reports");
    }
}
