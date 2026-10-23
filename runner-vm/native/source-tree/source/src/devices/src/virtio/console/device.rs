use std::cmp;
use std::io::Write;
use std::iter::zip;
use std::mem::{size_of, size_of_val};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;
#[cfg(target_os = "windows")]
use utils::windows::{AsRawFd, RawFd};

use utils::eventfd::EventFd;
use vm_memory::{ByteValued, Bytes, GuestMemoryMmap};

use super::super::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, QueueConfig, VirtioDevice,
};
use super::{defs, defs::control_event, defs::uapi};
use crate::virtio::console::console_control::{
    ConsoleControl, VirtioConsoleControl, VirtioConsoleResize,
};
use crate::virtio::console::defs::QUEUE_SIZE;
use crate::virtio::console::port::Port;
use crate::virtio::console::port_queue_mapping::{
    QueueDirection, num_queues, port_id_to_queue_idx,
};
use crate::virtio::{InterruptTransport, PortDescription, VmmExitObserver};

pub(crate) const CONTROL_RXQ_INDEX: usize = 2;
pub(crate) const CONTROL_TXQ_INDEX: usize = 3;

pub(crate) const AVAIL_FEATURES: u64 = (1 << uapi::VIRTIO_CONSOLE_F_SIZE as u64)
    | (1 << uapi::VIRTIO_CONSOLE_F_MULTIPORT as u64)
    | (1 << uapi::VIRTIO_F_VERSION_1 as u64);

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
pub struct VirtioConsoleConfig {
    cols: u16,
    rows: u16,
    max_nr_ports: u32,
    emerg_wr: u32,
}

// Safe because it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioConsoleConfig {}

impl VirtioConsoleConfig {
    pub fn new(cols: u16, rows: u16, max_nr_ports: u32) -> Self {
        VirtioConsoleConfig {
            cols,
            rows,
            max_nr_ports,
            emerg_wr: 0u32,
        }
    }
}

pub struct Console {
    pub(crate) device_state: DeviceState,
    pub(crate) control: Arc<ConsoleControl>,
    pub(crate) ports: Vec<Port>,

    queue_config: Vec<QueueConfig>,
    // Queues are stored as Option so individual queues can be taken when ports start.
    pub(crate) queues: Vec<Option<DeviceQueue>>,
    // TODO: move the queue event handling to the correct threads!
    pub(crate) queue_events: Vec<Arc<EventFd>>,

    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,

    pub(crate) activate_evt: EventFd,
    pub(crate) sigwinch_evt: EventFd,

    config: VirtioConsoleConfig,
}

impl Console {
    pub fn new(ports: Vec<PortDescription>) -> super::Result<Console> {
        assert!(!ports.is_empty(), "Expected at least 1 port");

        let num_queues = num_queues(ports.len());
        let queue_config: Vec<QueueConfig> = (0..num_queues)
            .map(|_| QueueConfig::new(QUEUE_SIZE))
            .collect();

        let ports: Vec<Port> = zip(0u32.., ports)
            .map(|(port_id, description)| Port::new(port_id, description))
            .collect();

        let (cols, rows) = ports[0]
            .terminal()
            .map(|t| t.get_win_size())
            .unwrap_or((0, 0));
        let config = VirtioConsoleConfig::new(cols, rows, ports.len() as u32);

        Ok(Console {
            control: ConsoleControl::new(),
            ports,
            queue_config,
            queues: Vec::new(),
            queue_events: Vec::new(),
            avail_features: AVAIL_FEATURES,
            acked_features: 0,
            activate_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(super::ConsoleError::EventFd)?,
            sigwinch_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(super::ConsoleError::EventFd)?,
            device_state: DeviceState::Inactive,
            config,
        })
    }

    pub fn id(&self) -> &str {
        defs::CONSOLE_DEV_ID
    }

    pub fn get_sigwinch_fd(&self) -> RawFd {
        self.sigwinch_evt.as_raw_fd()
    }

    pub fn update_console_size(&mut self, port_id: u32, cols: u16, rows: u16) {
        log::debug!("update_console_size {port_id}: {cols} {rows}");
        self.control
            .console_resize(port_id, VirtioConsoleResize { rows, cols });
    }

    pub(crate) fn process_control_rx(&mut self) -> bool {
        log::trace!("process_control_rx");
        let DeviceState::Activated(ref mem, _) = self.device_state else {
            unreachable!()
        };
        let mut raise_irq = false;

        let control_rx = self.queues[CONTROL_RXQ_INDEX]
            .as_mut()
            .expect("control rx queue should exist");

        while let Some(head) = control_rx.queue.pop(mem) {
            if let Some(buf) = self.control.queue_pop() {
                match mem.write(&buf, head.addr) {
                    Ok(n) => {
                        if n != buf.len() {
                            log::error!("process_control_rx: partial write");
                        }
                        raise_irq = true;
                        log::trace!("process_control_rx wrote {n}");
                        if let Err(e) = control_rx.queue.add_used(mem, head.index, n as u32) {
                            error!("failed to add used elements to the queue: {e:?}");
                        }
                    }
                    Err(e) => {
                        log::error!("process_control_rx failed to write: {e}");
                    }
                }
            } else {
                control_rx.queue.undo_pop();
                break;
            }
        }
        raise_irq
    }

    pub(crate) fn process_control_tx(&mut self) -> bool {
        log::trace!("process_control_tx");
        let DeviceState::Activated(ref mem, ref interrupt) = self.device_state else {
            unreachable!()
        };

        let control_tx = self.queues[CONTROL_TXQ_INDEX]
            .as_mut()
            .expect("control tx queue should exist");
        let mut raise_irq = false;

        let mut ports_to_start = Vec::new();

        while let Some(head) = control_tx.queue.pop(mem) {
            raise_irq = true;

            let cmd: VirtioConsoleControl = match mem.read_obj(head.addr) {
                Ok(cmd) => cmd,
                Err(e) => {
                    log::error!(
                        "Failed to read VirtioConsoleControl struct: {e:?}, struct len = {len}, head.len = {head_len}",
                        len = size_of::<VirtioConsoleControl>(),
                        head_len = head.len,
                    );
                    continue;
                }
            };
            if let Err(e) = control_tx
                .queue
                .add_used(mem, head.index, size_of_val(&cmd) as u32)
            {
                error!("failed to add used elements to the queue: {e:?}");
            }

            log::trace!("VirtioConsoleControl cmd: {cmd:?}");
            match cmd.event {
                control_event::VIRTIO_CONSOLE_DEVICE_READY => {
                    log::debug!(
                        "Device is ready: initialization {}",
                        if cmd.value == 1 { "ok" } else { "failed" }
                    );
                    for port_id in 0..self.ports.len() {
                        self.control.port_add(port_id as u32);
                    }
                }
                control_event::VIRTIO_CONSOLE_PORT_READY => {
                    if cmd.value != 1 {
                        log::error!("Port initialization failed: {cmd:?}");
                        continue;
                    }

                    if let Some(term) = self.ports[cmd.id as usize].terminal() {
                        self.control.mark_console_port(mem, cmd.id);
                        self.control.port_open(cmd.id, true);
                        let (cols, rows) = term.get_win_size();
                        self.control
                            .console_resize(cmd.id, VirtioConsoleResize { cols, rows });
                    } else {
                        // We start with all ports open, this makes sense for now,
                        // because underlying file descriptors STDIN, STDOUT, STDERR are always open too
                        self.control.port_open(cmd.id, true)
                    }

                    let name = self.ports[cmd.id as usize].name();
                    log::trace!("Port ready {id}: {name}", id = cmd.id);
                    if !name.is_empty() {
                        self.control.port_name(cmd.id, name)
                    }
                }
                control_event::VIRTIO_CONSOLE_PORT_OPEN => {
                    let opened = match cmd.value {
                        0 => false,
                        1 => true,
                        _ => {
                            log::error!(
                                "Invalid value ({}) for VIRTIO_CONSOLE_PORT_OPEN on port {}",
                                cmd.value,
                                cmd.id
                            );
                            continue;
                        }
                    };

                    if !opened {
                        log::debug!("Guest closed port {}", cmd.id);
                        continue;
                    }

                    ports_to_start.push(cmd.id as usize);
                }
                _ => log::warn!("Unknown console control event {:x}", cmd.event),
            }
        }

        for port_id in ports_to_start {
            log::trace!("Starting port io for port {port_id}");
            let rx_idx = port_id_to_queue_idx(QueueDirection::Rx, port_id);
            let tx_idx = port_id_to_queue_idx(QueueDirection::Tx, port_id);

            // Take ownership of port queues - they are moved to the port.
            let rx_queue = self.queues[rx_idx]
                .take()
                .expect("port rx queue should exist")
                .queue;
            let tx_queue = self.queues[tx_idx]
                .take()
                .expect("port tx queue should exist")
                .queue;

            self.ports[port_id].start(
                mem.clone(),
                rx_queue,
                tx_queue,
                interrupt.clone(),
                self.control.clone(),
            );
        }

        raise_irq
    }
}

impl VirtioDevice for Console {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features
    }

    fn device_type(&self) -> u32 {
        uapi::VIRTIO_ID_CONSOLE
    }

    fn device_name(&self) -> &str {
        "console"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &self.queue_config
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_slice = self.config.as_slice();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&config_slice[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        warn!(
            "console: guest driver attempted to write device config (offset={:x}, len={:x})",
            offset,
            data.len()
        );
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        if self.activate_evt.write(1).is_err() {
            error!("Cannot write to activate_evt");
            return Err(ActivateError::BadActivate);
        }

        self.queue_events = queues.iter().map(|dq| dq.event.clone()).collect();
        self.queues = queues.into_iter().map(Some).collect();
        self.device_state = DeviceState::Activated(mem, interrupt);

        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn reset(&mut self) -> bool {
        // A7 (R2-REVIEW-1): a shutdown failure must not be erased by reset.
        // Report it to the transport (false = reset not completed, mmio marks
        // the device FAILED) and keep it latched in the port, so every later
        // checked exit re-reports it instead of observing taken handles and
        // returning Ok without proof of worker termination.
        match self.on_vmm_exit_checked() {
            Ok(()) => true,
            Err(e) => {
                error!("console: reset failed to stop ports: {e}");
                false
            }
        }
    }
}

impl VmmExitObserver for Console {
    fn on_vmm_exit(&mut self) {
        // Legacy path: the same checked shutdown, failures logged only.
        if let Err(e) = self.on_vmm_exit_checked() {
            error!("console: vmm exit shutdown failed: {e}");
        }
        log::trace!("Console on_vmm_exit finished");
    }

    fn on_vmm_exit_checked(&mut self) -> std::result::Result<(), String> {
        let mut errors = Vec::new();
        for (idx, port) in self.ports.iter_mut().enumerate() {
            if let Err(e) = port.shutdown() {
                errors.push(format!("port[{idx}]: {e}"));
            }
        }
        if !errors.is_empty() {
            // Fail closed WITHOUT deactivating: queues and device state are
            // retained, so the device is never flipped to Inactive while any
            // worker termination is unproven. Each failed port has latched
            // its fault, so every later checked exit re-reports it — reset()
            // and a restart can no longer erase a failure.
            return Err(errors.join("; "));
        }
        self.queues.clear();
        self.queue_events.clear();
        self.device_state = DeviceState::Inactive;
        log::trace!("Console on_vmm_exit finished");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio::console::port::tests::{
        MutexFaultInput, SinkOutput, test_interrupt, test_mem,
    };
    use crate::virtio::console::port_queue_mapping::{QueueDirection, port_id_to_queue_idx};
    use crate::virtio::Queue;

    fn console_with_input() -> Console {
        Console::new(vec![PortDescription::input_pipe(
            "dut",
            Box::new(MutexFaultInput),
        )])
        .expect("console")
    }

    fn console_with_output() -> Console {
        Console::new(vec![PortDescription::output_pipe(
            "dut",
            Box::new(SinkOutput),
        )])
        .expect("console")
    }

    /// Activate the console and start port 0 exactly the way
    /// `process_control_tx` does: queues move from the device to the port.
    fn activate_and_start_port0(console: &mut Console) {
        let num = num_queues(console.ports.len());
        let queues = (0..num)
            .map(|_| {
                DeviceQueue::new(
                    Queue::new(defs::QUEUE_SIZE),
                    Arc::new(EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap()),
                )
            })
            .collect();
        console
            .activate(test_mem(), test_interrupt(), queues)
            .expect("activate");
        let rx_idx = port_id_to_queue_idx(QueueDirection::Rx, 0);
        let tx_idx = port_id_to_queue_idx(QueueDirection::Tx, 0);
        let rx_queue = console.queues[rx_idx].take().expect("rx queue").queue;
        let tx_queue = console.queues[tx_idx].take().expect("tx queue").queue;
        console.ports[0].start(
            test_mem(),
            rx_queue,
            tx_queue,
            test_interrupt(),
            console.control.clone(),
        );
    }

    #[test]
    fn clean_console_checked_exit_reset_is_repeatable() {
        let mut console = console_with_output();
        activate_and_start_port0(&mut console);
        console.on_vmm_exit_checked().expect("clean checked exit");
        assert!(!console.device_state.is_activated());
        assert!(console.reset(), "reset after clean exit must complete");
        console
            .on_vmm_exit_checked()
            .expect("repeatable clean checked exit");
    }

    #[test]
    fn reset_cannot_erase_a_latched_port_failure() {
        let mut console = console_with_input();
        // Poison the input mutex before start: the port worker panics on its
        // first `input.lock()` — a real latched failure, not an injected field.
        let input = console.ports[0]
            .input_arc_for_fault_injection()
            .expect("input port");
        let _ = std::thread::spawn(move || {
            let _guard = input.lock().unwrap();
            panic!("injected");
        })
        .join();
        activate_and_start_port0(&mut console);
        let err = console.on_vmm_exit_checked().unwrap_err();
        assert!(err.contains("port[0]"), "{err}");
        // The device stays activated on failure: its guest-memory state is
        // never dropped while worker termination is unproven.
        assert!(console.device_state.is_activated());
        // A7 regression: reset must NOT complete over the latched failure...
        assert!(!console.reset());
        // ...and the latch must survive it: the subsequent checked exit
        // re-reports instead of returning Ok on taken handles.
        assert_eq!(console.on_vmm_exit_checked().unwrap_err(), err);
        assert!(!console.reset(), "repeated reset stays refused");
        assert!(console.device_state.is_activated());
    }

    #[test]
    fn latched_port_refuses_guest_driven_restart() {
        let mut console = console_with_input();
        let input = console.ports[0]
            .input_arc_for_fault_injection()
            .expect("input port");
        let _ = std::thread::spawn(move || {
            let _guard = input.lock().unwrap();
            panic!("injected");
        })
        .join();
        activate_and_start_port0(&mut console);
        assert!(console.on_vmm_exit_checked().is_err());
        // The transport refuses reset (false), so a driver retry would call
        // process_control_tx -> Port::start again; the port must refuse and
        // keep reporting the latch rather than run over the fault.
        let rx_idx = port_id_to_queue_idx(QueueDirection::Rx, 0);
        let tx_idx = port_id_to_queue_idx(QueueDirection::Tx, 0);
        console.queues[rx_idx] = Some(DeviceQueue::new(
            Queue::new(defs::QUEUE_SIZE),
            Arc::new(EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap()),
        ));
        console.queues[tx_idx] = Some(DeviceQueue::new(
            Queue::new(defs::QUEUE_SIZE),
            Arc::new(EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap()),
        ));
        let rx_queue = console.queues[rx_idx].take().expect("rx queue").queue;
        let tx_queue = console.queues[tx_idx].take().expect("tx queue").queue;
        console.ports[0].start(
            test_mem(),
            rx_queue,
            tx_queue,
            test_interrupt(),
            console.control.clone(),
        );
        // A fresh worker would shut down cleanly; a latched error proves the
        // start was refused (no worker spawned over the fault).
        let err = console.on_vmm_exit_checked().unwrap_err();
        assert!(
            err.contains("panicked") && err.contains("port[0]"),
            "restart must be refused by the latch: {err}"
        );
    }
}
