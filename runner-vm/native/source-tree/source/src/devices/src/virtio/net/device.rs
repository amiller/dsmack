// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.
use crate::Error as DeviceError;
use crate::virtio::net::Result;
use crate::virtio::net::{NUM_QUEUES, QUEUE_CONFIG};
use crate::virtio::queue::Error as QueueError;
use crate::virtio::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, InterruptTransport, QueueConfig,
    TYPE_NET, VirtioDevice, VmmExitObserver,
};

use super::backend::{ReadError, WriteError};
use super::worker::NetWorker;

#[cfg(unix)]
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::RawSocket;

use std::cmp;
use std::io::Write;
use std::path::PathBuf;
#[cfg(unix)]
use std::thread::JoinHandle;
#[cfg(unix)]
use utils::eventfd::{EFD_NONBLOCK, EventFd};
use virtio_bindings::virtio_net::VIRTIO_NET_F_MAC;
use virtio_bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use vm_memory::{ByteValued, GuestMemoryError, GuestMemoryMmap};

const VIRTIO_F_VERSION_1: u32 = 32;

#[derive(Debug)]
pub enum FrontendError {
    DescriptorChainTooSmall,
    EmptyQueue,
    GuestMemory(GuestMemoryError),
    QueueError(QueueError),
    ReadOnlyDescriptor,
}

#[derive(Debug)]
pub enum RxError {
    Backend(ReadError),
    DeviceError(DeviceError),
}

#[derive(Debug)]
pub enum TxError {
    Backend(WriteError),
    DeviceError(DeviceError),
    QueueError(QueueError),
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioNetConfig {
    mac: [u8; 6],
    status: u16,
    max_virtqueue_pairs: u16,
}

// Safe because it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioNetConfig {}

#[derive(Clone)]
pub enum VirtioNetBackend {
    #[cfg(unix)]
    UnixstreamFd(RawFd),
    #[cfg(windows)]
    UnixstreamFd(RawSocket),
    UnixstreamPath(PathBuf),
    #[cfg(unix)]
    UnixgramFd(RawFd),
    #[cfg(unix)]
    UnixgramPath(PathBuf, bool),
    #[cfg(target_os = "linux")]
    Tap(String),
}

pub struct Net {
    id: String,
    pub cfg_backend: VirtioNetBackend,

    avail_features: u64,
    acked_features: u64,

    pub(crate) device_state: DeviceState,

    config: VirtioNetConfig,

    // dsmack v3 F10 — carries the caller-handed OWNED backend fd through the
    // INACTIVE and activation-FAILURE paths. Previously the fd was turned into a
    // bare RawFd in the backend enum and leaked if the device was never
    // activated (or activation failed before the worker took it). Here `Net`
    // owns it: if the device is dropped without a running worker the fd closes
    // exactly once; on a successful activation ownership is RELEASED to the
    // worker (into_raw_fd, no close) which closes it when it ends.
    #[cfg(unix)]
    owned_fd: Option<OwnedFd>,
    // dsmack v3 F10 — retained after activation so teardown can prove the worker
    // stopped (checked join) before the device is considered closed.
    #[cfg(unix)]
    worker_thread: Option<JoinHandle<()>>,
    #[cfg(unix)]
    worker_stop: Option<EventFd>,
    // dsmack v3 F10 — a teardown fault is latched PERMANENTLY: a second checked
    // exit re-reports it and can never return Ok on a missing handle.
    #[cfg(unix)]
    shutdown_fault: Option<String>,
    // dsmack v3 F10 — the worker latches a TERMINAL rx transport fault (EOF,
    // framing desync, deadline, stop-mid-read) here. `stop_worker_checked` reads
    // it AFTER a successful join, so a clean join can never conceal a transport
    // failure the worker already observed.
    #[cfg(unix)]
    rx_fault: std::sync::Arc<std::sync::Mutex<Option<String>>>,
}

/// dsmack v3 F10 — upper bound on waiting for the net worker to observe the stop
/// eventfd. Past it the worker is reaped on a helper thread and the fault is
/// latched, mirroring the block device's checked teardown.
#[cfg(unix)]
const NET_WORKER_SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

impl Net {
    /// Create a new virtio network device using the backend
    pub fn new(
        id: String,
        cfg_backend: VirtioNetBackend,
        mac: [u8; 6],
        features: u32,
    ) -> Result<Self> {
        let avail_features = features as u64
            | (1 << VIRTIO_NET_F_MAC)
            | (1 << VIRTIO_RING_F_EVENT_IDX)
            | (1 << VIRTIO_F_VERSION_1);

        let config = VirtioNetConfig {
            mac,
            status: 0,
            max_virtqueue_pairs: 0,
        };

        // F10: take OWNERSHIP of the caller-handed backend fd so it is closed
        // exactly once even if the device is never activated. The enum keeps the
        // bare RawFd (a number) for the worker to adopt on activation; `Net`
        // holds the sole owning handle until then.
        #[cfg(unix)]
        let owned_fd = match &cfg_backend {
            VirtioNetBackend::UnixstreamFd(fd) | VirtioNetBackend::UnixgramFd(fd) => {
                // SAFETY: the caller relinquished ownership of this fd to the net
                // device; we adopt it exactly once here.
                Some(unsafe { OwnedFd::from_raw_fd(*fd) })
            }
            _ => None,
        };

        Ok(Net {
            id,
            cfg_backend,

            avail_features,
            acked_features: 0u64,

            device_state: DeviceState::Inactive,
            config,

            #[cfg(unix)]
            owned_fd,
            #[cfg(unix)]
            worker_thread: None,
            #[cfg(unix)]
            worker_stop: None,
            #[cfg(unix)]
            shutdown_fault: None,
            #[cfg(unix)]
            rx_fault: std::sync::Arc::new(std::sync::Mutex::new(None)),
        })
    }

    /// Provides the ID of this net device.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Provides the virtio-net backend of this net device.
    pub fn backend(&self) -> &VirtioNetBackend {
        &self.cfg_backend
    }
}

impl VirtioDevice for Net {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn device_type(&self) -> u32 {
        TYPE_NET
    }

    fn device_name(&self) -> &str {
        "net"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &QUEUE_CONFIG
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
        log::warn!(
            "Net: guest driver attempted to write device config (offset={:x}, len={:x})",
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
        let [rx_q, tx_q]: [_; NUM_QUEUES] = queues.try_into().map_err(|_| {
            error!("Cannot perform activate. Expected {} queue(s)", NUM_QUEUES);
            ActivateError::BadActivate
        })?;

        // F10: a stop eventfd the worker adds to its epoll set; teardown writes
        // it to break the worker loop so its JoinHandle can be joined and the
        // backend fd is closed exactly once.
        let stop_efd = EventFd::new(EFD_NONBLOCK).map_err(|e| {
            error!("virtio-net ({}): stop eventfd: {e:?}", self.id());
            ActivateError::BadActivate
        })?;
        let worker_stop = stop_efd.try_clone().map_err(|e| {
            error!("virtio-net ({}): stop eventfd clone: {e:?}", self.id());
            ActivateError::BadActivate
        })?;

        // F10: fresh rx-fault slot for this activation so a prior worker's latched
        // fault cannot bleed into a new one.
        #[cfg(unix)]
        {
            self.rx_fault = std::sync::Arc::new(std::sync::Mutex::new(None));
        }
        match NetWorker::new(
            rx_q,
            tx_q,
            interrupt.clone(),
            mem.clone(),
            self.acked_features,
            self.cfg_backend.clone(),
            stop_efd,
            std::sync::Arc::clone(&self.rx_fault),
        ) {
            Ok(worker) => {
                // NetWorker::new adopted the backend fd (from_raw_fd); from this
                // point the worker owns it (and closes it on drop/teardown).
                // RELEASE Net's owning handle WITHOUT closing so the fd is never
                // double-closed — do this BEFORE run() so that even a spawn
                // failure (which drops `worker`, closing the fd once) cannot race
                // a second close from Net's owned_fd.
                #[cfg(unix)]
                if let Some(owned) = self.owned_fd.take() {
                    let _ = owned.into_raw_fd();
                }
                // F10: retain the worker JoinHandle (previously discarded). A
                // spawn failure fails the activation closed instead of panicking.
                let handle = worker.run().map_err(|e| {
                    error!("virtio-net ({}): worker spawn: {e:?}", self.id());
                    ActivateError::BadActivate
                })?;
                self.worker_thread = Some(handle);
                self.worker_stop = Some(worker_stop);
                self.device_state = DeviceState::Activated(mem, interrupt);
                Ok(())
            }
            Err(err) => {
                // Activation failed: `self.owned_fd` still holds the backend fd
                // and will close it exactly once on drop (owned-fd carry). The
                // worker never took it.
                error!(
                    "Error activating virtio-net ({}) backend: {err:?}",
                    self.id()
                );
                Err(ActivateError::BadActivate)
            }
        }
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }
}

/// dsmack v3 F10 — checked teardown of the net worker. Pushed as a VMM exit
/// observer so `stop_returning` proves the worker stopped (bounded join, latched
/// fault) BEFORE the vCPUs are destroyed and guest memory is freed — and the
/// backend fd is closed exactly once when the worker ends. A teardown failure
/// fails the returning lifecycle closed.
#[cfg(unix)]
impl Net {
    pub fn stop_worker_checked(&mut self) -> std::result::Result<(), String> {
        // Latched faults are permanent: a second call re-reports the first
        // failure, never returning Ok on the strength of a missing handle.
        if let Some(fault) = &self.shutdown_fault {
            return Err(fault.clone());
        }
        if self.worker_thread.is_some() {
            // Signal the stopfd BEFORE taking the JoinHandle: a failed write must
            // leave the handle in place (dropping it would detach the worker and
            // lose all ability to prove termination before guest memory frees).
            let Some(stop) = &self.worker_stop else {
                let fault = "virtio-net: worker present without a stop eventfd".to_string();
                self.shutdown_fault = Some(fault.clone());
                return Err(fault);
            };
            if let Err(e) = stop.write(1) {
                let fault = format!("virtio-net: worker stop eventfd write failed: {e:?}");
                self.shutdown_fault = Some(fault.clone());
                return Err(fault);
            }
            let deadline = std::time::Instant::now() + NET_WORKER_SHUTDOWN_TIMEOUT;
            while !self.worker_thread.as_ref().unwrap().is_finished() {
                if std::time::Instant::now() >= deadline {
                    let fault = format!(
                        "virtio-net: worker did not stop within {NET_WORKER_SHUTDOWN_TIMEOUT:?}; guest memory retained"
                    );
                    self.shutdown_fault = Some(fault.clone());
                    return Err(fault);
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            let worker = self.worker_thread.take().unwrap();
            match worker.join() {
                Ok(()) => {
                    // F10: the join succeeded, but a CLEAN join must not conceal a
                    // transport failure the worker already latched (EOF, framing
                    // desync, read deadline, stop-mid-read). Surface it now so the
                    // returning lifecycle fails closed.
                    if let Some(fault) = self.rx_fault.lock().ok().and_then(|slot| slot.clone()) {
                        let fault = format!(
                            "virtio-net: worker joined but a transport fault was latched: {fault}"
                        );
                        self.shutdown_fault = Some(fault.clone());
                        return Err(fault);
                    }
                }
                Err(error) => {
                    let fault = format!("virtio-net: worker thread failed: {error:?}");
                    self.shutdown_fault = Some(fault.clone());
                    return Err(fault);
                }
            }
        }
        self.worker_stop = None;
        self.device_state = DeviceState::Inactive;
        Ok(())
    }
}

#[cfg(unix)]
impl VmmExitObserver for Net {
    fn on_vmm_exit(&mut self) {
        let _ = self.on_vmm_exit_checked();
    }
    fn on_vmm_exit_checked(&mut self) -> std::result::Result<(), String> {
        self.stop_worker_checked()
    }
}

#[cfg(all(test, unix))]
mod native_worker_tests {
    use super::*;
    use crate::legacy::DummyIrqChip;
    use crate::virtio::{DeviceQueue, Queue};
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use std::time::Duration;
    use vm_memory::GuestAddress;

    fn activated() -> (Net, UnixStream) {
        let (reader, writer) = UnixStream::pair().unwrap();
        let mut net = Net::new(
            "native-worker".into(),
            VirtioNetBackend::UnixstreamFd(reader.into_raw_fd()),
            [2; 6],
            0,
        )
        .unwrap();
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 65536)]).unwrap();
        let interrupt = InterruptTransport::new(DummyIrqChip::new().into(), "test".into()).unwrap();
        let queues = (0..2)
            .map(|_| {
                DeviceQueue::new(
                    Queue::new(256),
                    Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()),
                )
            })
            .collect();
        net.activate(memory, interrupt, queues).unwrap();
        (net, writer)
    }

    #[test]
    fn native_worker_idle_stop_repeat() {
        let (mut net, _writer) = activated();
        std::thread::sleep(Duration::from_millis(20));
        net.stop_worker_checked().unwrap();
        net.stop_worker_checked().unwrap();
    }

    #[test]
    fn native_worker_partial_stop_fault_repeat() {
        let (mut net, mut writer) = activated();
        writer.write_all(&[0]).unwrap();
        std::thread::sleep(Duration::from_millis(30));
        let first = net.stop_worker_checked().unwrap_err();
        assert!(first.contains("transport fault"), "{first}");
        assert_eq!(first, net.stop_worker_checked().unwrap_err());
    }

    #[test]
    fn native_worker_eof_fault_repeat() {
        let (mut net, writer) = activated();
        drop(writer);
        std::thread::sleep(Duration::from_millis(30));
        let first = net.stop_worker_checked().unwrap_err();
        assert!(first.contains("transport fault"), "{first}");
        assert_eq!(first, net.stop_worker_checked().unwrap_err());
    }
}
