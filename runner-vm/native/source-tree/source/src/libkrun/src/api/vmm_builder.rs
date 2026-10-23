use std::marker::PhantomData;
#[cfg(not(target_os = "windows"))]
use std::os::fd::{AsRawFd, BorrowedFd};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex};

#[cfg(target_os = "macos")]
use crate::vmm::VmCtl;
use crate::vmm::Vmm as InnerVmm;
#[cfg(unix)]
use crate::vmm::resources::SerialConsoleConfig;
use crate::vmm::resources::VmResources;
use crate::vmm::returning_unrecoverable as unrecoverable;
use crate::vmm::vmm_config::machine_config::VmConfig;
use crossbeam_channel::unbounded;
use polly::event_manager::EventManager;
#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
use utils::eventfd::EventFd;
#[cfg(target_os = "macos")]
use utils::pollable_channel::PollableChannelSender;

use super::device_builders::{DeviceManager, MmioDeviceManager};
use super::error::VmmError;
use super::payload::Payload;

#[derive(Default)]
pub struct VmmBuilder<'a> {
    vcpus: Option<u8>,
    ram_mib: Option<u32>,
    payload: Option<Payload>,
    device_manager: Option<Box<dyn DeviceManager<'a> + 'a>>,
    #[cfg(unix)]
    serial_consoles: Vec<SerialConsoleConfig>,
    kernel_console: Option<String>,
    nested_virt: bool,
    split_irqchip: bool,
    acpi: bool,
    smbios_oem_strings: Vec<String>,
    shutdown_support: bool,
    returning_console: Option<std::fs::File>,
    ctl_channel: Option<std::os::fd::OwnedFd>,
    ctl_disk: Option<CtlDiskSpec>,
    ctl_scratch: Option<CtlScratchSpec>,
    ctl_workload: Option<CtlDiskSpec>,
    // dsmack v3 control profile (five owned-file disks + optional generic NIC).
    ctl_v3_control: Option<std::os::fd::OwnedFd>,
    ctl_v3_disks: Option<Vec<CtlV3DiskFile>>,
    ctl_v3_net: Option<CtlNetSpec>,
    // dsmack v3 F09 — execution budget armed before the vCPUs start.
    exec_budget: Option<std::time::Duration>,
}

/// dsmack v3 F09 — default execution budget armed for the returning profile when
/// the caller did not request a tighter one. The returning run loop would
/// otherwise wait for the guest halt with no deadline; this bounds that wait so
/// a guest that never halts cannot execute indefinitely. The backend passes the
/// admitted budget via [`VmmBuilder::exec_budget`]; this is only the fallback
/// ceiling, never a relaxation of a smaller admitted budget.
pub const DEFAULT_EXEC_BUDGET: std::time::Duration = std::time::Duration::from_secs(900);

/// Authenticated read-only system disk for the control profile: the builder
/// pins the image by content hash and attaches it read-only; callers cannot
/// express a writable or unpinned disk.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))] // consumed on the profile platform; tested elsewhere
pub struct CtlDiskSpec {
    pub path: String,
    pub expected_sha256_hex: String,
}

/// Fresh read-write scratch disk (vdb) for the v2 control profile: the path
/// is created by the backend O_EXCL at 0600, EMPTY (fresh-inode owner; a
/// refused launch unlinks it again); the builder only OPENS it and verifies
/// the fresh-inode invariants, then pre-sizes SPARSE — the guest bootstrap
/// owns the ext4 format.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))] // consumed on the profile platform; tested elsewhere
pub struct CtlScratchSpec {
    pub path: String,
}

/// dsmack v3 (F01/F02) — one owned-file disk in the five-role control profile.
/// The backend has ALREADY verified/created the inode and hands the OPEN file
/// over; the builder attaches it via the owned-file route (retained inode, no
/// path re-open, no sparse re-init). `is_result` marks the vdd result image
/// whose checked flush/sync is wired into teardown (F07).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))] // consumed on the profile platform
pub struct CtlV3DiskFile {
    pub name: String,
    pub file: std::fs::File,
    pub read_only: bool,
    pub is_result: bool,
}

/// dsmack v3 (F01/F10) — the SINGLE bounded, allowlisted generic virtio-net
/// option: a caller-handed connected SOCK_STREAM fd (far end = external NAT
/// helper) attached as one virtio-net device with a fixed MAC.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))] // consumed on the profile platform
pub struct CtlNetSpec {
    pub fd: std::os::fd::OwnedFd,
    pub mac: [u8; 6],
    pub features: u32,
}

/// Opt-in returning lifecycle (aarch64 macOS only, not exported over FFI).
impl<'a> VmmBuilder<'a> {
    /// Select the returning profile. The sole device is an output-only virtio console whose
    /// port owns a dup of `console_log`, which must be a regular file. [`build`](Self::build)
    /// then rejects caller devices, serial or kernel consoles, shutdown support, nested
    /// virtualization, more than one vCPU and any payload other than verified owned bytes,
    /// before any VM construction.
    pub fn returning_console(mut self, console_log: std::fs::File) -> Self {
        self.returning_console = Some(console_log);
        self
    }

    /// Extend the returning profile into the control profile: attach the dedicated named
    /// bidirectional `dsmack-ctl` console over `control_fd`, an OWNED descriptor the builder
    /// consumes. The descriptor must be a socket or pipe (never a host file/device path);
    /// each port direction holds its own dup, set non-blocking and close-on-exec, and the
    /// original fd is dropped when the builder is consumed. Requires
    /// [`ctl_disk`](Self::ctl_disk) — the control profile always boots the authenticated
    /// read-only disk.
    pub fn ctl_channel(mut self, control_fd: std::os::fd::OwnedFd) -> Self {
        self.ctl_channel = Some(control_fd);
        self
    }

    /// Extend the returning profile into the control profile: attach `disk_path` as the
    /// single read-only virtio block device, refusing it unless its full content hashes to
    /// `expected_sha256_hex` (lowercase hex). The pin is caller-supplied but this API's
    /// callers are pinned apps: arbitrary or writable disks are not expressible, and any
    /// host path whose content fails the pin is rejected before VM construction.
    pub fn ctl_disk(mut self, disk_path: &str, expected_sha256_hex: &str) -> Self {
        self.ctl_disk = Some(CtlDiskSpec {
            path: disk_path.to_string(),
            expected_sha256_hex: expected_sha256_hex.to_ascii_lowercase(),
        });
        self
    }

    /// v2: attach the FRESH read-write scratch disk (vdb). The backend must
    /// have created the path O_EXCL 0600 EMPTY immediately before this call
    /// (it owns the fresh-inode create and the refusal-cleanup unlink);
    /// [`build`](Self::build) opens it and refuses unless it is a regular
    /// empty 0600 file, then pre-sizes it sparse and attaches it read-write;
    /// all guest container state dies with it at poweroff. Requires
    /// [`ctl_workload_disk`](Self::ctl_workload_disk) — the v2 profile
    /// always selects the full vda/vdb/vdc triple.
    pub fn ctl_scratch_disk(mut self, path: &str) -> Self {
        self.ctl_scratch = Some(CtlScratchSpec {
            path: path.to_string(),
        });
        self
    }

    /// v2: attach the read-only workload disk (vdc), refusing it unless its
    /// full content hashes to `expected_sha256_hex` (same verify-on-open as
    /// [`ctl_disk`](Self::ctl_disk)). The in-guest supervisor independently
    /// re-verifies the workload SHA256SUMS before use — this pin only
    /// narrows the host staging window.
    pub fn ctl_workload_disk(mut self, disk_path: &str, expected_sha256_hex: &str) -> Self {
        self.ctl_workload = Some(CtlDiskSpec {
            path: disk_path.to_string(),
            expected_sha256_hex: expected_sha256_hex.to_ascii_lowercase(),
        });
        self
    }

    /// dsmack v3 (F01) — select the v3 control profile: the dedicated `dsmack-ctl`
    /// channel over the owned `control_fd`, the five-role OWNED-FILE disk set
    /// (`disks`, in guest-enumeration order), and an OPTIONAL single generic
    /// virtio-net device (`net`). `build` attaches every disk via the owned-file
    /// route (retained verified inode, no sparse re-init), wires the result
    /// image's checked flush/sync into teardown, and refuses everything outside
    /// the profile — all before any vCPU runs. Takes precedence over the v2
    /// `ctl_disk`/`ctl_channel` selection when present.
    pub fn ctl_v3(
        mut self,
        control_fd: std::os::fd::OwnedFd,
        disks: Vec<CtlV3DiskFile>,
        net: Option<CtlNetSpec>,
    ) -> Self {
        self.ctl_v3_control = Some(control_fd);
        self.ctl_v3_disks = Some(disks);
        self.ctl_v3_net = net;
        self
    }

    /// dsmack v3 F09 — set the execution budget armed before the vCPUs start.
    /// The returning run loop fails closed once it elapses. Omitting it leaves
    /// the returning profile on the [`DEFAULT_EXEC_BUDGET`] fallback ceiling.
    pub fn exec_budget(mut self, budget: std::time::Duration) -> Self {
        self.exec_budget = Some(budget);
        self
    }
}

#[cfg_attr(feature = "ffi", ffier::export)]
impl<'a> VmmBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn vcpus(mut self, count: u8) -> Result<Self, VmmError> {
        if count == 0 {
            return Err(VmmError::OutOfRange());
        }
        self.vcpus = Some(count);
        Ok(self)
    }

    pub fn ram_mib(mut self, mib: u32) -> Result<Self, VmmError> {
        if mib == 0 {
            return Err(VmmError::OutOfRange());
        }
        self.ram_mib = Some(mib);
        Ok(self)
    }

    pub fn payload(mut self, payload: Payload) -> Self {
        self.payload = Some(payload);
        self
    }

    pub fn devices(mut self, devices: MmioDeviceManager<'a>) -> Self {
        self.device_manager = Some(Box::new(devices));
        self
    }

    pub fn set_kernel_console(mut self, console: &str) -> Self {
        self.kernel_console = Some(console.to_string());
        self
    }

    /// Add a legacy serial console device with the given input and output file descriptors.
    ///
    /// Can be called multiple times to add multiple serial consoles (ttyS0, ttyS1, …).
    /// This is required for FreeBSD guests which use the legacy serial console instead
    /// of the virtio console.
    ///
    /// The descriptors are borrowed, not duplicated. They must remain open and valid
    /// until the VMM exits.
    #[cfg(not(target_os = "windows"))]
    pub fn add_serial_console(
        mut self,
        input_fd: Option<BorrowedFd<'a>>,
        output_fd: Option<BorrowedFd<'a>>,
    ) -> Result<Self, VmmError> {
        let in_fd = input_fd.map_or(-1, |fd| fd.as_raw_fd());
        let out_fd = output_fd.map_or(-1, |fd| fd.as_raw_fd());
        self.serial_consoles.push(SerialConsoleConfig {
            input_fd: in_fd,
            output_fd: out_fd,
        });
        Ok(self)
    }

    pub fn nested_virt(mut self, enabled: bool) -> Self {
        self.nested_virt = enabled;
        self
    }

    pub fn split_irqchip(mut self, enabled: bool) -> Result<Self, VmmError> {
        if enabled && !cfg!(target_arch = "x86_64") {
            return Err(VmmError::InvalidParam());
        }
        self.split_irqchip = enabled;
        Ok(self)
    }

    /// Enable ACPI table generation for x86_64 guests.
    ///
    /// When disabled (the default), virtio-mmio devices are passed on the kernel
    /// command line and SMP uses the MP table. When enabled, devices are described
    /// in the ACPI DSDT and the RSDP is published in boot parameters.
    pub fn acpi(mut self, enabled: bool) -> Result<Self, VmmError> {
        if enabled && !cfg!(target_arch = "x86_64") {
            return Err(VmmError::InvalidParam());
        }
        self.acpi = enabled;
        Ok(self)
    }

    pub fn add_smbios_oem_string(mut self, s: &str) -> Self {
        self.smbios_oem_strings.push(s.to_string());
        self
    }

    /// Enable the optional guest shutdown device.
    ///
    /// When enabled on aarch64 macOS, [`VmmHandle::shutdown`] signals the
    /// guest through the PL061 GPIO device. The device is not attached by
    /// default. On other platforms, shutdown remains unsupported.
    pub fn shutdown_support(mut self, enabled: bool) -> Self {
        self.shutdown_support = enabled;
        self
    }

    pub fn build(self) -> Result<Vmm<'a>, VmmError> {
        build_vm(self).inspect_err(|e| log::error!("{e}"))
    }
}

enum VmmInner {
    Vmm {
        #[allow(dead_code)]
        vmm: Arc<Mutex<InnerVmm>>,
        event_manager: EventManager,
        #[allow(dead_code)]
        _worker_sender: crossbeam_channel::Sender<utils::worker_message::WorkerMessage>,
        #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
        shutdown_efd: Option<EventFd>,
    },
    #[cfg(feature = "aws-nitro")]
    Nitro(aws_nitro::enclave::NitroEnclave),
}

pub struct Vmm<'a> {
    inner: VmmInner,
    // Armed only for the returning profile: its vCPUs are already running when
    // `build()` returns, and there is no proven path to tear the VM down outside
    // `run_returning`. Dropping the guard therefore aborts, so a built VM can
    // never be silently discarded (a plain drop would free guest memory under
    // live vCPUs). Discharged only after `run_returning` completed teardown.
    #[cfg_attr(
        not(all(target_arch = "aarch64", target_os = "macos")),
        allow(dead_code) // only read by run_returning, which is profile-gated
    )]
    returning_guard: Option<ReturningGuard>,
    // dsmack v3 F08 — a handle to the returning console's latched byte-cap
    // state, retained so the backend can read the REAL `truncated` flag after
    // teardown (the console worker updates it through `LimitedPortOutput`).
    #[cfg_attr(
        not(all(target_arch = "aarch64", target_os = "macos")),
        allow(dead_code)
    )]
    console_truncation: Option<Arc<devices::virtio::port_io::ConsoleLimit>>,
    _lifetime: PhantomData<&'a ()>,
}

/// dsmack v3 F08 — native console hard cap, matching the backend's
/// `MAX_CONSOLE_BYTES` (16 MiB) with `CONSOLE_SLACK_BYTES == 0`: the final write
/// is truncated to the remaining budget, so the on-disk console is <= this many
/// bytes EXACTLY and the latched `truncated` flag reflects whether any byte was
/// dropped.
pub const CONSOLE_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// Drop guard for a built-but-not-yet-run returning VM. Fires on plain drop and
/// on any unwind that abandons the VM between `build()` and `run_returning`.
struct ReturningGuard;

impl Drop for ReturningGuard {
    fn drop(&mut self) {
        super::super::vmm::returning_unrecoverable(
            "returning VMM dropped or unwound without run_returning",
        );
    }
}

/// Handle to the inner VMM, usable from another thread while the
/// event loop runs on the main thread via [`Vmm::run`].
///
/// Obtain via [`Vmm::handle`] before calling `run()`.
// FIXME: make Vmm::run() non-blocking (requires making EventManager Send)
// so that run() returns a RunningVmm with wait(). Then this handle
// can be obtained from RunningVmm instead of requiring a pre-run call.
pub struct VmmHandle {
    #[cfg(target_os = "macos")]
    vm_ctl_tx: PollableChannelSender<VmCtl>,
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    shutdown_efd: Option<EventFd>,
}

impl Clone for VmmHandle {
    fn clone(&self) -> Self {
        Self {
            #[cfg(target_os = "macos")]
            vm_ctl_tx: self.vm_ctl_tx.clone(),
            #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
            shutdown_efd: self
                .shutdown_efd
                .as_ref()
                .map(|efd| efd.try_clone().expect("dup shutdown_efd")),
        }
    }
}

#[cfg_attr(feature = "ffi", ffier::export)]
impl VmmHandle {
    pub fn pause(&self) -> Result<(), VmmError> {
        #[cfg(target_os = "macos")]
        {
            self.vm_ctl_tx
                .send(VmCtl::Pause)
                .map_err(|e| VmmError::Internal(format!("pause: {e}")))
        }
        #[cfg(not(target_os = "macos"))]
        Err(VmmError::FeatureDisabled())
    }

    pub fn resume(&self) -> Result<(), VmmError> {
        #[cfg(target_os = "macos")]
        {
            self.vm_ctl_tx
                .send(VmCtl::Resume)
                .map_err(|e| VmmError::Internal(format!("resume: {e}")))
        }
        #[cfg(not(target_os = "macos"))]
        Err(VmmError::FeatureDisabled())
    }

    /// Signal the guest to perform an orderly ACPI shutdown.
    ///
    /// This requires [`VmmBuilder::shutdown_support`] to have been enabled
    /// before building the VMM. On aarch64 macOS it writes to the GPIO
    /// device's eventfd, which triggers a restart-key press in the guest. On
    /// other platforms, or when support was not enabled, it returns
    /// [`VmmError::FeatureDisabled`].
    pub fn shutdown(&self) -> Result<(), VmmError> {
        #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
        {
            let Some(shutdown_efd) = &self.shutdown_efd else {
                return Err(VmmError::FeatureDisabled());
            };
            shutdown_efd
                .write(1)
                .map_err(|e| VmmError::Internal(format!("shutdown: {e}")))
        }
        #[cfg(not(all(target_arch = "aarch64", target_os = "macos")))]
        Err(VmmError::FeatureDisabled())
    }
}

#[cfg_attr(feature = "ffi", ffier::export)]
impl<'a> Vmm<'a> {
    /// Obtain a thread-safe handle to the inner VMM.
    ///
    /// Must be called before [`run`](Self::run) which consumes `self`.
    /// The handle can be moved to another thread for pause/resume.
    /// dsmack v3 F08 — a handle to the returning console's latched byte-cap
    /// state. Obtain it BEFORE [`run_returning`](Self::run_returning) consumes
    /// the VM; after teardown the backend reads the REAL `truncated` flag from
    /// it instead of asserting an unproven literal. `None` when no capped
    /// returning console is installed.
    pub fn console_truncation(&self) -> Option<Arc<devices::virtio::port_io::ConsoleLimit>> {
        self.console_truncation.clone()
    }

    pub fn handle(&self) -> Result<VmmHandle, VmmError> {
        match &self.inner {
            VmmInner::Vmm {
                #[cfg(target_os = "macos")]
                vmm,
                #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
                shutdown_efd,
                ..
            } => {
                // The returning profile retains no out-of-band control handles.
                #[cfg(target_os = "macos")]
                if vmm.lock().unwrap().returning {
                    return Err(VmmError::FeatureDisabled());
                }
                Ok(VmmHandle {
                    #[cfg(target_os = "macos")]
                    vm_ctl_tx: vmm.lock().unwrap().vm_ctl_sender(),
                    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
                    shutdown_efd: shutdown_efd
                        .as_ref()
                        .map(|efd| efd.try_clone().expect("dup shutdown_efd")),
                })
            }
            #[cfg(feature = "aws-nitro")]
            VmmInner::Nitro(_) => Err(VmmError::FeatureDisabled()),
        }
    }

    pub fn run(self) {
        match self.inner {
            VmmInner::Vmm {
                #[cfg(target_os = "macos")]
                vmm,
                mut event_manager,
                ..
            } => {
                // The legacy event loop has no returning teardown: on a returning VM
                // it would observe the halt event and loop forever without ever
                // destroying the HVF VM, its vCPU or guest memory.
                #[cfg(target_os = "macos")]
                if vmm.lock().unwrap().returning {
                    unrecoverable("legacy run() on a returning VM; use run_returning()");
                }
                loop {
                    if let Err(e) = event_manager.run() {
                        log::error!("fatal event loop error: {e:?}");
                        return;
                    }
                }
            }
            #[cfg(feature = "aws-nitro")]
            VmmInner::Nitro(enclave) => {
                let exit_code = enclave.run().unwrap_or_else(|e| {
                    log::error!("Error running nitro enclave: {e}");
                    -libc::EINVAL
                });
                unsafe { libc::_exit(exit_code) }
            }
        }
    }
}

impl Vmm<'_> {
    /// Returning lifecycle: run until the guest halts, tear the VM down and return the vCPU
    /// exit code (0 = guest halt via PSCI SYSTEM_OFF/RESET, not workload success). Returns only
    /// after every teardown step succeeded. Any failure aborts the process, including calling
    /// this on a VMM built without the returning profile, whose vCPUs are already running.
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    pub fn run_returning(self) -> u8 {
        self.run_returning_with_cancel(
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            std::time::Duration::from_secs(30),
        )
    }

    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    pub fn run_returning_with_cancel(
        mut self,
        cancel: Arc<std::sync::atomic::AtomicBool>,
        teardown_budget: std::time::Duration,
    ) -> u8 {
        // Discharge the drop guard only on the success path; any other exit from
        // the teardown below must abort rather than leave a half-torn-down VM.
        let guard = self.returning_guard.take();
        // A panic mid-teardown is an unreported returning-lifecycle fault: catch
        // it here so the guard's abort fires instead of unwinding into the caller.
        let result = catch_unwind(AssertUnwindSafe(|| {
            self.run_returning_inner(cancel, teardown_budget)
        }));
        match result {
            Ok(code) => {
                std::mem::forget(guard);
                code
            }
            Err(_) => {
                drop(guard);
                unreachable!("guard drop aborts the process");
            }
        }
    }

    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    fn run_returning_inner(
        self,
        cancel: Arc<std::sync::atomic::AtomicBool>,
        teardown_budget: std::time::Duration,
    ) -> u8 {
        #[allow(irrefutable_let_patterns)]
        let VmmInner::Vmm {
            vmm,
            mut event_manager,
            _worker_sender,
            shutdown_efd,
        } = self.inner
        else {
            unrecoverable("not a returning VMM");
        };
        if !vmm.lock().unwrap().returning {
            unrecoverable("not a returning VMM");
        }
        // F09: enforce the execution budget armed at vCPU start. Previously this
        // waited for the guest halt through `event_manager.run()` with NO run
        // deadline, so a guest that never halts could execute indefinitely. We
        // now wait in bounded slices so the budget is checked even while the
        // guest is silent, and fail CLOSED (the returning profile's abort
        // discipline — never a reported result) once the deadline elapses.
        let exec_deadline = vmm.lock().unwrap().exec_deadline;
        const EXEC_POLL_SLICE_MS: i32 = 200;
        let budget_expired = |deadline: Option<std::time::Instant>| -> bool {
            matches!(deadline, Some(d) if std::time::Instant::now() >= d)
        };
        while vmm.lock().unwrap().halted.is_none() {
            if let Err(e) = event_manager.run_with_timeout(EXEC_POLL_SLICE_MS) {
                unrecoverable(&format!("event loop: {e:?}"));
            }
            // F09: fail closed the moment the deadline elapses, UNCONDITIONALLY —
            // do NOT re-read `halted` here. The previous `&& halted.is_none()`
            // guard let a halt that landed in the same slice as the deadline
            // bypass the budget; an expired budget must fail closed even if a
            // (late) halt has just been recorded.
            if budget_expired(exec_deadline) {
                unrecoverable(
                    "execution budget exceeded: the guest did not halt within the admitted \
                     budget (failing closed; no result is produced)",
                );
            }
        }
        // F09: a halt was observed. If the deadline had ALREADY elapsed when the
        // halt landed, the budget was exceeded and a late halt must NOT bypass it
        // — fail closed. Only a halt strictly within budget proceeds to teardown.
        if budget_expired(exec_deadline) {
            unrecoverable(
                "execution budget exceeded: the guest halted only after the admitted budget \
                 elapsed (late halt does not bypass the budget; failing closed)",
            );
        }
        // Arm before any observer lock, checked flush, join, or destruction.
        // The VMM cannot safely move off its HVF thread. Timeout/cancellation
        // terminates the owning process without unwinding still-live resources.
        let teardown_watchdog = super::teardown_watchdog::TeardownWatchdog::arm(
            std::time::Instant::now() + teardown_budget,
            cancel,
        )
        .unwrap_or_else(|error| unrecoverable(&format!("teardown watchdog: {error}")));
        vmm.lock().unwrap().cancel_exec_watchdog();
        let code = vmm
            .lock()
            .unwrap()
            .stop_returning()
            .unwrap_or_else(|e| unrecoverable(&e));
        drop((event_manager, _worker_sender, shutdown_efd));
        let vmm = Arc::try_unwrap(vmm)
            .unwrap_or_else(|a| {
                unrecoverable(&format!("VMM still shared: {}", Arc::strong_count(&a)))
            })
            .into_inner()
            .unwrap_or_else(|_| unrecoverable("poisoned VMM"));
        vmm.finish_returning()
            .unwrap_or_else(|e| unrecoverable(&format!("finish: {e}")));
        teardown_watchdog.finish();
        code
    }
}

/// Checks shared by the returning and control profiles: platform, vCPU count,
/// verified owned payload, no options outside the profile, regular-file console.
fn returning_checks(
    console_log: &std::fs::File,
    vcpus: u8,
    payload: &Payload,
    extra_config: bool,
) -> Result<(), VmmError> {
    use super::payload::PayloadKind;
    let reject = |why: &str| Err(VmmError::BootError(format!("returning profile: {why}")));
    if !cfg!(all(target_arch = "aarch64", target_os = "macos")) {
        return reject("aarch64 macOS only");
    }
    if vcpus != 1 {
        return reject("exactly one vCPU");
    }
    if !matches!(&payload.kind, PayloadKind::External { kernel } if kernel.verified().is_some()) {
        return reject("verified owned payload required");
    }
    if extra_config {
        return reject("devices, consoles or options outside the profile");
    }
    let meta = console_log
        .metadata()
        .map_err(|e| VmmError::Internal(format!("console metadata: {e}")))?;
    if !meta.file_type().is_file() {
        return reject("console must be a regular file");
    }
    Ok(())
}

fn returning_profile<'a>(
    console_log: std::fs::File,
    vcpus: u8,
    payload: &Payload,
    extra_config: bool,
) -> Result<MmioDeviceManager<'a>, VmmError> {
    returning_checks(&console_log, vcpus, payload, extra_config)?;
    let output = devices::virtio::port_io::output_to_raw_fd_dup(console_log.as_raw_fd())
        .map_err(|e| VmmError::Internal(format!("console dup: {e}")))?;
    drop(console_log);
    let mut console = super::device_builders::ConsoleDevice::builder();
    console.add_console_port("", output);
    let mut dm = MmioDeviceManager::new();
    dm.add(console.build()?);
    Ok(dm)
}

/// The named guest-side control port; the guest bridge opens exactly this
/// port (exposed by the guest init as the pinned root-owned 0600 node).
pub const CONTROL_PORT_NAME: &str = "dsmack-ctl";

/// Control profile device set: the returning output console PLUS the dedicated
/// named bidirectional control console over an owned fd PLUS the single
/// content-pinned read-only system disk. Every guard from
/// [`returning_checks`] applies unchanged, plus:
/// - the control fd must be a socket or pipe (a host file or device is refused
///   — the control channel is a private fd handover, never a path);
/// - the disk must be a regular file whose full content matches the caller's
///   compiled-in pin, attached read-only.
#[cfg(all(feature = "blk", target_os = "macos"))]
fn control_profile<'a>(
    console_log: std::fs::File,
    vcpus: u8,
    payload: &Payload,
    extra_config: bool,
    control_fd: std::os::fd::OwnedFd,
    disk: CtlDiskSpec,
    scratch: Option<CtlScratchSpec>,
    workload: Option<CtlDiskSpec>,
) -> Result<MmioDeviceManager<'a>, VmmError> {
    use std::os::fd::AsRawFd;
    returning_checks(&console_log, vcpus, payload, extra_config)?;
    // v2 pairing rule: the disk triple is selected together or not at all.
    let Some(workload) = workload else {
        return Err(VmmError::BootError(
            "returning profile: the workload disk (vdc) is required with the              control profile"
                .into(),
        ));
    };
    let Some(scratch) = scratch else {
        return Err(VmmError::BootError(
            "returning profile: the fresh scratch disk (vdb) is required with              the control profile"
                .into(),
        ));
    };
    // The control channel is a private fd handover, never a host path: only
    // sockets and pipes are accepted.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(control_fd.as_raw_fd(), &mut st) } != 0 {
        return Err(VmmError::Internal(format!(
            "control fd fstat: {}",
            std::io::Error::last_os_error()
        )));
    }
    let ifmt = st.st_mode & libc::S_IFMT;
    if ifmt != libc::S_IFSOCK && ifmt != libc::S_IFIFO {
        return Err(VmmError::BootError(
            "returning profile: control fd must be a socket or pipe, not a host path or device"
                .into(),
        ));
    }

    // Content verifications run BEFORE any fd is consumed: a refused launch
    // leaves the caller's control descriptor un-duped and the console log
    // unopened (the backend's consumption-refusal path unlinks the scratch).
    // vda system: pin by content BEFORE any device exists.
    verify_disk_pin(&disk.path, &disk.expected_sha256_hex)?;
    // vdb scratch: the backend owns the O_EXCL fresh-inode create; krun only
    // verifies the invariants it needs (fable-native-audit F1).
    let scratch_file = verify_fresh_scratch(&scratch.path)?;
    // vdc workload: verify-on-open, attached read-only.
    verify_disk_pin(&workload.path, &workload.expected_sha256_hex)?;
    // Sparse pre-size AFTER every verification: a refused launch leaves the
    // scratch exactly as the backend created it (empty; the backend unlinks
    // it again on its own refusal path).
    scratch_file
        .set_len(SCRATCH_SPARSE_BYTES)
        .map_err(|e| VmmError::Internal(format!("scratch sizing: {e}")))?;
    drop(scratch_file);

    let console_output = devices::virtio::port_io::output_to_raw_fd_dup(console_log.as_raw_fd())
        .map_err(|e| VmmError::Internal(format!("console dup: {e}")))?;
    drop(console_log);
    let mut console = super::device_builders::ConsoleDevice::builder();
    console.add_console_port("", console_output);
    // The named bidirectional control port: the builder dups both directions
    // from the owned control fd; the original is dropped at the end of this
    // function and the dups are owned (and closed) by the console port.
    console
        .add_inout_port(
            CONTROL_PORT_NAME,
            // SAFETY: control_fd is owned and valid for this call; the port
            // keeps independent duplicates, never the borrowed descriptor.
            Some(unsafe { BorrowedFd::borrow_raw(control_fd.as_raw_fd()) }),
            Some(unsafe { BorrowedFd::borrow_raw(control_fd.as_raw_fd()) }),
        )
        .map_err(|e| VmmError::Internal(format!("control port: {e}")))?;
    drop(control_fd);

    let mut dm = MmioDeviceManager::new();
    dm.add(console.build()?);
    // vda, vdb, vdc — the attach order IS the pinned guest contract (see
    // `ctl_disk_attach_order`; fable-native-audit F3).
    for d in ctl_disk_attach_order(&disk, &scratch, &workload) {
        let mut dev = super::device_builders::BlockDevice::new(
            d.name,
            &d.path,
            devices::virtio::block::DiskFormat::Raw,
        )
        .map_err(|e| VmmError::Internal(format!("{} disk: {e}", d.name)))?;
        dev.set_read_only(d.read_only);
        dm.add(dev);
    }
    Ok(dm)
}

/// dsmack v3 (F01/F02/F07/F09/F10) control-profile device set: the returning
/// output console, the named bidirectional `dsmack-ctl` channel over the owned
/// control fd, the FIVE-ROLE disk set attached from RETAINED OWNED FILES (vda
/// system RO, vdb scratch RW, vdc workload RO, vdd result RW — its checked
/// flush/sync wired into teardown — and optional vde private RO), and an
/// OPTIONAL single bounded generic virtio-net device. Every `returning_checks`
/// guard applies (aarch64 macOS, exactly one vCPU, verified owned payload,
/// regular-file console), and the control fd must be a socket or pipe. Every
/// disk uses the owned-file route: the backend's exact verified inode is
/// retained, never re-opened by path, never sparse-reinitialized — so a
/// NON-EMPTY admitted template copy is carried through unchanged (F02).
#[cfg(all(feature = "blk", target_os = "macos"))]
#[allow(clippy::too_many_arguments)]
fn control_profile_v3<'a>(
    console_log: std::fs::File,
    vcpus: u8,
    payload: &Payload,
    extra_config: bool,
    control_fd: std::os::fd::OwnedFd,
    disks: Vec<CtlV3DiskFile>,
    net: Option<CtlNetSpec>,
    console_truncation: &mut Option<Arc<devices::virtio::port_io::ConsoleLimit>>,
) -> Result<MmioDeviceManager<'a>, VmmError> {
    use std::os::fd::AsRawFd;
    returning_checks(&console_log, vcpus, payload, extra_config)?;
    if disks.is_empty() {
        return Err(VmmError::BootError(
            "returning profile: the v3 control profile requires the owned-file disk set".into(),
        ));
    }
    // The control channel is a private fd handover, never a host path: only
    // sockets and pipes are accepted (same rule as v2).
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(control_fd.as_raw_fd(), &mut st) } != 0 {
        return Err(VmmError::Internal(format!(
            "control fd fstat: {}",
            std::io::Error::last_os_error()
        )));
    }
    let ifmt = st.st_mode & libc::S_IFMT;
    if ifmt != libc::S_IFSOCK && ifmt != libc::S_IFIFO {
        return Err(VmmError::BootError(
            "returning profile: control fd must be a socket or pipe, not a host path or device"
                .into(),
        ));
    }

    let raw_output = devices::virtio::port_io::output_to_raw_fd_dup(console_log.as_raw_fd())
        .map_err(|e| VmmError::Internal(format!("console dup: {e}")))?;
    drop(console_log);
    // F08: route the actual native console writes through the byte-cap limiter
    // so the on-disk console can never grow past CONSOLE_MAX_BYTES, and retain
    // the shared latched state so the backend reads the REAL truncation flag.
    let limit = devices::virtio::port_io::ConsoleLimit::new(CONSOLE_MAX_BYTES);
    let console_output = Box::new(devices::virtio::port_io::LimitedPortOutput::new(
        raw_output,
        limit.clone(),
    ));
    *console_truncation = Some(limit);
    let mut console = super::device_builders::ConsoleDevice::builder();
    console.add_console_port("", console_output);
    console
        .add_inout_port(
            CONTROL_PORT_NAME,
            // SAFETY: control_fd is owned and valid for this call; the port keeps
            // independent duplicates, never the borrowed descriptor.
            Some(unsafe { BorrowedFd::borrow_raw(control_fd.as_raw_fd()) }),
            Some(unsafe { BorrowedFd::borrow_raw(control_fd.as_raw_fd()) }),
        )
        .map_err(|e| VmmError::Internal(format!("control port: {e}")))?;
    drop(control_fd);

    let mut dm = MmioDeviceManager::new();
    dm.add(console.build()?);
    // Attach every disk from its RETAINED OWNED FILE, in the caller's guest
    // enumeration order (vda, vdb, vdc, vdd, [vde]).
    for d in disks {
        dm.add(super::device_builders::OwnedFileBlockDevice::new(
            &d.name,
            d.file,
            d.read_only,
            d.is_result,
        ));
    }
    // Optional single generic virtio-net device over the owned connected fd.
    if let Some(net) = net {
        #[cfg(feature = "net")]
        {
            let dev = super::device_builders::NetDevice::new_unixstream_fd(
                "dsmack-net",
                net.fd,
                &net.mac,
                net.features,
                super::device_builders::NetFlags::empty(),
            )
            .map_err(|e| VmmError::Internal(format!("v3 net device: {e:?}")))?;
            dm.add(dev);
        }
        #[cfg(not(feature = "net"))]
        {
            let _ = net;
            return Err(VmmError::BootError(
                "returning profile: the v3 NIC requires the net feature".into(),
            ));
        }
    }
    Ok(dm)
}

/// The v3 control profile exists only for aarch64 macOS (with blk); anywhere
/// else the builder must refuse it before any VM construction.
#[cfg(all(feature = "blk", not(target_os = "macos")))]
#[allow(clippy::too_many_arguments)]
fn control_profile_v3<'a>(
    console_log: std::fs::File,
    vcpus: u8,
    payload: &Payload,
    extra_config: bool,
    control_fd: std::os::fd::OwnedFd,
    disks: Vec<CtlV3DiskFile>,
    net: Option<CtlNetSpec>,
    console_truncation: &mut Option<Arc<devices::virtio::port_io::ConsoleLimit>>,
) -> Result<MmioDeviceManager<'a>, VmmError> {
    let _ = (
        &console_log,
        &vcpus,
        payload,
        &extra_config,
        &control_fd,
        &disks,
        &net,
    );
    *console_truncation = None;
    returning_checks(&console_log, vcpus, payload, extra_config)?;
    Err(VmmError::BootError(
        "returning profile: aarch64 macOS only".into(),
    ))
}

#[cfg(not(feature = "blk"))]
#[allow(clippy::too_many_arguments)]
fn control_profile_v3<'a>(
    console_log: std::fs::File,
    vcpus: u8,
    payload: &Payload,
    extra_config: bool,
    control_fd: std::os::fd::OwnedFd,
    disks: Vec<CtlV3DiskFile>,
    net: Option<CtlNetSpec>,
    console_truncation: &mut Option<Arc<devices::virtio::port_io::ConsoleLimit>>,
) -> Result<MmioDeviceManager<'a>, VmmError> {
    let _ = (
        &console_log,
        &vcpus,
        payload,
        &extra_config,
        &control_fd,
        &disks,
        &net,
    );
    *console_truncation = None;
    Err(VmmError::BootError(
        "returning profile: v3 control profile requires the blk feature".into(),
    ))
}

/// v2 scratch (vdb) fresh-inode invariant, verified at attach WITHOUT
/// creating: the backend (`dsmack-backend` disks::create_scratch) owns the
/// O_EXCL 0600 EMPTY create and the refusal-cleanup unlink, so krun only
/// opens the inode the backend just made and checks what attach requires:
/// regular file, size 0, mode 0600. Creating here would be the
/// fable-native-audit F1 double-create — O_EXCL would refuse EVERY launch
/// on the backend's own inode, and a non-O_EXCL create would silently reuse
/// a stale scratch across launches. Returns the open handle (used for the
/// sparse pre-size).
///
/// Public on purpose: the create↔verify pairing crosses the crate boundary
/// (backend creates, krun verifies), so the pairing test lives in the
/// apple-static integration tree, and the Mac gate can assert the
/// invariant against the exact shipped bytes.
pub fn verify_fresh_scratch(path: &str) -> Result<std::fs::File, VmmError> {
    let file = std::fs::OpenOptions::new().read(true).write(true).open(path).map_err(|e| {
        VmmError::BootError(format!(
            "returning profile: scratch {path} must exist fresh (0600, empty) from the backend: {e}"
        ))
    })?;
    let meta = file
        .metadata()
        .map_err(|e| VmmError::Internal(format!("scratch metadata: {e}")))?;
    if !meta.is_file() {
        return Err(VmmError::BootError(format!(
            "returning profile: scratch {path} must be a regular file"
        )));
    }
    if meta.len() != 0 {
        return Err(VmmError::BootError(format!(
            "returning profile: scratch {path} must be EMPTY (fresh inode from the backend; size {})",
            meta.len()
        )));
    }
    use std::os::unix::fs::PermissionsExt;
    if meta.permissions().mode() & 0o777 != 0o600 {
        return Err(VmmError::BootError(format!(
            "returning profile: scratch {path} must be mode 0600 (backend create_scratch contract)"
        )));
    }
    Ok(file)
}

/// One control-profile disk attachment, carrying everything the attach step
/// needs in the order the device manager must receive it.
pub struct CtlDiskAttach {
    pub name: &'static str,
    pub path: String,
    pub read_only: bool,
}

/// The v2 control-profile disk triple IN GUEST ENUMERATION ORDER: vda, vdb,
/// vdc. On aarch64 the guest enumerates virtio-blk devices in attach order,
/// so this order IS the pinned guest contract (policy/dstack-arm64.image.json
/// `guest.scratch_device` "vdb" — the docker data-root — and
/// `guest.workload_device` "vdc"; backend-v2 disks.rs DiskRole).
/// fable-native-audit F3: adding the workload before the scratch inverted
/// the contract (vdb=workload / vdc=scratch) and guaranteed a boot failure
/// of the smoke-proven guest; the Mac gate must keep asserting this order.
///
/// Public on purpose: the order is the cross-crate guest contract with the
/// backend's `DiskRole` (System→vda, Scratch→vdb, Workload→vdc), so the
/// pairing is asserted in the apple-static integration tree and can be
/// re-asserted by the Mac gate against the exact shipped bytes.
pub fn ctl_disk_attach_order(
    system: &CtlDiskSpec,
    scratch: &CtlScratchSpec,
    workload: &CtlDiskSpec,
) -> [CtlDiskAttach; 3] {
    [
        CtlDiskAttach {
            name: "dsmack-system",
            path: system.path.clone(),
            read_only: true,
        },
        CtlDiskAttach {
            name: "dsmack-scratch",
            path: scratch.path.clone(),
            read_only: false,
        },
        CtlDiskAttach {
            name: "dsmack-workload",
            path: workload.path.clone(),
            read_only: true,
        },
    ]
}

/// Sparse pre-size of the fresh scratch image: non-zero (block devices
/// refuse empty images) and Docker/baseline-sized; the guest formats it.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))] // profile platform; sized in host tests
const SCRATCH_SPARSE_BYTES: u64 = 2 << 30;

/// Without the blk feature the control profile is not implementable: refuse
/// outright instead of building a disk-less control VM.
#[cfg(not(feature = "blk"))]
fn control_profile<'a>(
    console_log: std::fs::File,
    vcpus: u8,
    payload: &Payload,
    extra_config: bool,
    control_fd: std::os::fd::OwnedFd,
    disk: CtlDiskSpec,
    scratch: Option<CtlScratchSpec>,
    workload: Option<CtlDiskSpec>,
) -> Result<MmioDeviceManager<'a>, VmmError> {
    let _ = (
        &console_log,
        &vcpus,
        &payload,
        &extra_config,
        &control_fd,
        &disk,
        &scratch,
        &workload,
    );
    Err(VmmError::BootError(
        "returning profile: control profile requires the blk feature".into(),
    ))
}

/// The control profile exists only for aarch64 macOS; anywhere else the
/// builder must refuse it before any VM construction, so no caller can build
/// a half-wired control VM on the wrong platform.
#[cfg(all(feature = "blk", not(target_os = "macos")))]
fn control_profile<'a>(
    console_log: std::fs::File,
    vcpus: u8,
    payload: &Payload,
    extra_config: bool,
    control_fd: std::os::fd::OwnedFd,
    disk: CtlDiskSpec,
    scratch: Option<CtlScratchSpec>,
    workload: Option<CtlDiskSpec>,
) -> Result<MmioDeviceManager<'a>, VmmError> {
    let _ = (
        &console_log,
        &vcpus,
        &payload,
        &extra_config,
        &control_fd,
        &disk,
        &scratch,
        &workload,
    );
    Err(VmmError::BootError(
        "returning profile: aarch64 macOS only".into(),
    ))
}

/// Pin the control disk by content before any device is constructed: regular
/// file, non-zero multiple of 512 bytes, full-content sha256 equal to the
/// expected (lowercase) hex digest.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))] // profile platform; boundary-tested everywhere
fn verify_disk_pin(path: &str, expected_sha256_hex: &str) -> Result<(), VmmError> {
    let meta = std::fs::metadata(path)
        .map_err(|e| VmmError::BootError(format!("returning profile: control disk: {e}")))?;
    if !meta.is_file() {
        return Err(VmmError::BootError(
            "returning profile: control disk must be a regular file".into(),
        ));
    }
    if meta.len() == 0 || !meta.len().is_multiple_of(512) {
        return Err(VmmError::BootError(
            "returning profile: control disk size must be a non-zero multiple of 512".into(),
        ));
    }
    let actual = sha256_file_hex(path)?;
    if actual != expected_sha256_hex {
        return Err(VmmError::BootError(
            "returning profile: control disk content does not match the pinned digest".into(),
        ));
    }
    Ok(())
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn sha256_file_hex(path: &str) -> Result<String, VmmError> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = std::fs::File::open(path)
        .map_err(|e| VmmError::BootError(format!("returning profile: control disk open: {e}")))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(|e| {
            VmmError::BootError(format!("returning profile: control disk read: {e}"))
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg_attr(feature = "ffi", ffier::export)]
pub fn check_nested_virt() -> bool {
    #[cfg(target_os = "macos")]
    {
        hvf::check_nested_virt().unwrap_or(false)
    }

    #[cfg(target_os = "linux")]
    {
        use std::fs;
        let paths = [
            "/sys/module/kvm_intel/parameters/nested",
            "/sys/module/kvm_amd/parameters/nested",
        ];
        paths.iter().any(|path| {
            fs::read_to_string(path).is_ok_and(|contents| {
                let val = contents.trim();
                val == "1" || val.eq_ignore_ascii_case("Y")
            })
        })
    }
    #[cfg(target_os = "windows")]
    {
        false
    }
}

fn build_vm(mut builder_cfg: VmmBuilder<'_>) -> Result<Vmm<'_>, VmmError> {
    use super::payload::PayloadKind;

    let vcpus_count = builder_cfg
        .vcpus
        .ok_or_else(|| VmmError::MissingConfig("vcpus not set".into()))?;
    let ram_mib = builder_cfg
        .ram_mib
        .ok_or_else(|| VmmError::MissingConfig("ram_mib not set".into()))?;
    let payload = builder_cfg
        .payload
        .ok_or_else(|| VmmError::MissingConfig("payload not set".into()))?;

    if let PayloadKind::External { kernel } = &payload.kind
        && let Some(images) = kernel.verified()
    {
        #[cfg(unix)]
        let serial = !builder_cfg.serial_consoles.is_empty();
        #[cfg(not(unix))]
        let serial = false;
        if payload.cmdline != images.cmdline()
            || kernel.cmdline.as_deref() != Some(images.cmdline())
            || builder_cfg.kernel_console.is_some()
            || serial
        {
            return Err(VmmError::BootError(
                "verified boot: approved cmdline would be modified".into(),
            ));
        }
    }

    // F08: captures the v3 console's latched byte-cap state (set by
    // control_profile_v3) so it can be surfaced on the built Vmm.
    let mut console_truncation: Option<Arc<devices::virtio::port_io::ConsoleLimit>> = None;
    let returning_devices = match builder_cfg.returning_console {
        Some(file) => {
            #[cfg(unix)]
            let serial = !builder_cfg.serial_consoles.is_empty();
            #[cfg(not(unix))]
            let serial = false;
            let extra = serial
                || builder_cfg.device_manager.is_some()
                || builder_cfg.kernel_console.is_some()
                || builder_cfg.nested_virt
                || builder_cfg.split_irqchip
                || builder_cfg.acpi
                || builder_cfg.shutdown_support;
            // dsmack v3 control profile takes precedence when selected: the
            // five-role owned-file disk set + optional generic NIC over the
            // dedicated control channel.
            if let Some(disks) = builder_cfg.ctl_v3_disks.take() {
                let control = builder_cfg.ctl_v3_control.take().ok_or_else(|| {
                    VmmError::MissingConfig(
                        "v3 control profile selected without a control fd".into(),
                    )
                })?;
                Some(control_profile_v3(
                    file,
                    vcpus_count,
                    &payload,
                    extra,
                    control,
                    disks,
                    builder_cfg.ctl_v3_net.take(),
                    &mut console_truncation,
                )?)
            } else {
                // Control profile parity: the channel and the disk are selected
                // together or not at all, and the extensions require the profile's
                // output console.
                match (builder_cfg.ctl_channel, builder_cfg.ctl_disk) {
                    (Some(fd), Some(disk)) => Some(control_profile(
                        file,
                        vcpus_count,
                        &payload,
                        extra,
                        fd,
                        disk,
                        builder_cfg.ctl_scratch.take(),
                        builder_cfg.ctl_workload.take(),
                    )?),
                    (None, None) => Some(returning_profile(file, vcpus_count, &payload, extra)?),
                    (Some(_), None) | (None, Some(_)) => {
                        return Err(VmmError::BootError(
                            "returning profile: the control channel and the authenticated disk \
                         are selected together"
                                .into(),
                        ));
                    }
                }
            }
        }
        None if builder_cfg.ctl_channel.is_some()
            || builder_cfg.ctl_disk.is_some()
            || builder_cfg.ctl_v3_disks.is_some() =>
        {
            return Err(VmmError::BootError(
                "returning profile: ctl_channel/ctl_disk/ctl_v3 require returning_console".into(),
            ));
        }
        None => None,
    };

    #[cfg(feature = "aws-nitro")]
    if let PayloadKind::Nitro(nitro_config) = payload.kind {
        let enclave = nitro_config
            .into_enclave(vcpus_count, ram_mib as usize)
            .map_err(|e| VmmError::MissingConfig(e.to_string()))?;
        return Ok(Vmm {
            inner: VmmInner::Nitro(enclave),
            console_truncation: None,
            _lifetime: PhantomData,
        });
    }

    let returning = returning_devices.is_some();
    let device_manager = match returning_devices {
        Some(dm) => Box::new(dm),
        None => builder_cfg.device_manager.ok_or_else(|| {
            VmmError::MissingConfig("no device manager set (call .devices())".into())
        })?,
    };

    let mut vm_resources = VmResources::default();
    vm_resources
        .set_vm_config(&VmConfig {
            vcpu_count: Some(vcpus_count),
            mem_size_mib: Some(ram_mib as usize),
            ht_enabled: Some(false),
            cpu_template: None,
        })
        .map_err(|e| {
            log::error!("vm config: {e:?}");
            VmmError::InvalidParam()
        })?;

    match payload.kind {
        PayloadKind::Kernel { bundle } => {
            vm_resources.kernel_bundle = Some(bundle);
        }
        PayloadKind::External { kernel } => {
            vm_resources.external_kernel = Some(kernel);
        }
        PayloadKind::Firmware { path } => {
            vm_resources
                .set_firmware_config(crate::vmm::vmm_config::firmware::FirmwareConfig { path });
        }
        #[cfg(feature = "tee")]
        PayloadKind::Tee {
            bundle,
            qboot_bundle,
            initrd_bundle,
            tee_config_path,
            #[cfg(feature = "tdx")]
            firmware_path,
        } => {
            vm_resources.kernel_bundle = Some(bundle);
            if let Some(qboot_bundle) = qboot_bundle {
                vm_resources.set_qboot_bundle(qboot_bundle).map_err(|e| {
                    log::error!("qboot bundle: {e}");
                    VmmError::InvalidParam()
                })?;
            }
            #[cfg(feature = "tdx")]
            if let Some(path) = firmware_path {
                vm_resources.set_tee_firmware_config(
                    crate::vmm::vmm_config::firmware::TeeFirmwareConfig {
                        fw_type: crate::vmm::vmm_config::firmware::TeeFirmwareType::TdShim,
                        path,
                    },
                );
            }
            vm_resources.set_initrd_bundle(initrd_bundle);
            vm_resources.set_tee_config(tee_config_path).map_err(|e| {
                log::error!("tee config: {e:?}");
                VmmError::InvalidParam()
            })?;
        }
        #[cfg(feature = "aws-nitro")]
        PayloadKind::Nitro(_) => unreachable!("handled above"),
    }

    vm_resources.kernel_cmdline.prolog = Some(payload.cmdline);

    vm_resources.nested_enabled = builder_cfg.nested_virt;
    vm_resources.returning = returning;
    // F09: arm the execution budget. The returning profile is ALWAYS bounded —
    // use the caller's admitted budget if set, otherwise the fallback ceiling —
    // so the run loop can never wait indefinitely for a halt. Non-returning
    // profiles keep whatever the caller requested (usually none).
    vm_resources.exec_budget = match (returning, builder_cfg.exec_budget) {
        (_, Some(b)) => Some(b),
        (true, None) => Some(DEFAULT_EXEC_BUDGET),
        (false, None) => None,
    };
    vm_resources.split_irqchip = builder_cfg.split_irqchip;
    vm_resources.acpi_enabled = builder_cfg.acpi;
    if !builder_cfg.smbios_oem_strings.is_empty() {
        vm_resources.smbios_oem_strings = Some(builder_cfg.smbios_oem_strings);
    }

    if let Some(console) = builder_cfg.kernel_console {
        vm_resources.kernel_console = Some(console);
    }

    #[cfg(unix)]
    {
        vm_resources.serial_consoles = builder_cfg.serial_consoles;
    }

    let mut event_manager =
        EventManager::new().map_err(|e| VmmError::Internal(format!("{e:?}")))?;

    let (sender, receiver) = unbounded();

    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    let shutdown_efd = if builder_cfg.shutdown_support {
        Some(EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(|_| VmmError::ResourceAlloc())?)
    } else {
        None
    };
    #[cfg(not(all(target_arch = "aarch64", target_os = "macos")))]
    let _ = builder_cfg.shutdown_support;

    let built = if returning {
        // A panic during a returning build may leave a running vCPU or the
        // process-wide HVF VM behind; unwinding into the caller would hide that.
        // Catch and fail closed instead.
        match catch_unwind(AssertUnwindSafe(|| {
            crate::vmm::builder::build_microvm(
                &vm_resources,
                &mut event_manager,
                #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
                shutdown_efd
                    .as_ref()
                    .map(|efd| EventFd::try_clone(efd).expect("dup shutdown_efd")),
                #[cfg(not(all(target_arch = "aarch64", target_os = "macos")))]
                None,
                sender.clone(),
                device_manager,
            )
        })) {
            Ok(built) => built,
            Err(_) => unrecoverable("returning build panicked"),
        }
    } else {
        crate::vmm::builder::build_microvm(
            &vm_resources,
            &mut event_manager,
            #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
            shutdown_efd
                .as_ref()
                .map(|efd| EventFd::try_clone(efd).expect("dup shutdown_efd")),
            #[cfg(not(all(target_arch = "aarch64", target_os = "macos")))]
            None,
            sender.clone(),
            device_manager,
        )
    };
    // A failed returning build may already own the process-wide HVF VM or a running vCPU, with
    // no proven cleanup path, so the process must not continue to another run.
    if returning && let Err(e) = &built {
        unrecoverable(&format!("returning build failed: {e:?}"));
    }
    let inner = built.map_err(|e| VmmError::BootError(format!("{e:?}")))?;

    let needs_worker = {
        #[cfg(any(feature = "amd-sev", feature = "tdx"))]
        {
            true
        }
        #[cfg(not(any(feature = "amd-sev", feature = "tdx")))]
        {
            #[cfg(target_arch = "x86_64")]
            {
                builder_cfg.split_irqchip
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                false
            }
        }
    };

    if needs_worker {
        crate::vmm::worker::start_worker_thread(inner.clone(), receiver.clone())
            .map_err(|e| VmmError::Internal(format!("worker thread: {e}")))?;
    } else {
        let _ = receiver;
    }

    Ok(Vmm {
        inner: VmmInner::Vmm {
            vmm: inner,
            event_manager,
            _worker_sender: sender,
            #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
            shutdown_efd,
        },
        returning_guard: returning.then_some(ReturningGuard),
        console_truncation,
        _lifetime: PhantomData,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::payload::PayloadKind;
    use crate::vmm::vmm_config::external_kernel::{
        ExternalKernelSource, KernelFormat, VerifiedBootPins,
    };
    use sha2::{Digest, Sha256};

    const CMDLINE: &str = "console=hvc0 ro";

    fn sha(d: &[u8]) -> String {
        format!("{:x}", Sha256::digest(d))
    }

    fn verified_payload() -> Payload {
        let (k, c) = (sha(b"kernel"), sha(CMDLINE.as_bytes()));
        let pins = VerifiedBootPins {
            kernel_sha256: &k,
            initrd_sha256: None,
            cmdline_sha256: &c,
        };
        Payload::load_external_raw_verified(b"kernel", None, CMDLINE, &pins).unwrap()
    }

    fn base<'a>() -> VmmBuilder<'a> {
        VmmBuilder::new().vcpus(1).unwrap().ram_mib(64).unwrap()
    }

    fn refused(r: Result<Vmm<'_>, VmmError>) -> bool {
        matches!(r, Err(VmmError::BootError(_)))
    }

    // An unmodified payload passes the cmdline lock and stops at the missing device
    // manager, before any VM is created.
    fn passed_lock(r: Result<Vmm<'_>, VmmError>) -> bool {
        matches!(r, Err(VmmError::MissingConfig(m)) if m.contains("device manager"))
    }

    #[test]
    fn verified_payload_wrong_pin_refused() {
        let c = sha(CMDLINE.as_bytes());
        let pins = VerifiedBootPins {
            kernel_sha256: &sha(b"other"),
            initrd_sha256: None,
            cmdline_sha256: &c,
        };
        assert!(matches!(
            Payload::load_external_raw_verified(b"kernel", None, CMDLINE, &pins),
            Err(VmmError::InvalidParam())
        ));
    }

    #[test]
    fn verified_cmdline_modifications_refused_before_vm_creation() {
        assert!(passed_lock(base().payload(verified_payload()).build()));

        let mut p = verified_payload();
        p.append_cmdline("init=/bin/sh");
        assert!(refused(base().payload(p).build()));

        let console = base()
            .payload(verified_payload())
            .set_kernel_console("ttyAMA0");
        assert!(refused(console.build()));

        #[cfg(unix)]
        {
            use std::os::fd::AsFd;
            let out = std::io::stdout();
            let serial = base()
                .payload(verified_payload())
                .add_serial_console(None, Some(out.as_fd()))
                .unwrap();
            assert!(refused(serial.build()));
        }
    }

    // The returning profile exists only for aarch64 macOS; anywhere else the
    // builder must refuse it before any VM construction, so a caller cannot
    // build a half-returning VM on the wrong platform.
    #[cfg(not(all(target_arch = "aarch64", target_os = "macos")))]
    #[test]
    fn returning_console_refused_outside_profile_platform() {
        let console =
            std::env::temp_dir().join(format!("krun-returning-{}.log", std::process::id()));
        let file = std::fs::File::create(&console).unwrap();
        let built = base()
            .payload(verified_payload())
            .returning_console(file)
            .build();
        // Only the error side is formatted: the success payload is a built Vmm,
        // which deliberately has no Debug impl.
        match built {
            Ok(_) => panic!("expected returning profile refusal, got Ok"),
            Err(VmmError::BootError(m)) => assert!(m.contains("returning profile"), "{m}"),
            Err(e) => panic!("expected BootError returning profile refusal, got {e:?}"),
        }
        std::fs::remove_file(&console).unwrap();
    }

    // Control-profile selection guards are platform-independent: parity
    // between the channel and the disk, and the requirement of an output
    // console, are refused before any platform-specific validation.
    fn ctl_payload() -> Payload {
        verified_payload()
    }

    /// One end of an AF_UNIX socketpair as an owned fd (the other end is
    /// closed immediately; the ctl_channel guard tests only exercise the
    /// selection logic, which runs before any fd-type validation).
    fn owned_socketpair_fd() -> std::os::fd::OwnedFd {
        use std::os::fd::FromRawFd;
        let mut fds = [0 as libc::c_int; 2];
        let r = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert_eq!(r, 0, "socketpair for test");
        // SAFETY: fds[0] is a fresh owned descriptor from socketpair.
        let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[0]) };
        // SAFETY: fds[1] is a fresh owned descriptor from socketpair.
        drop(unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[1]) });
        fd
    }

    /// Boot refusals are BootError with a checked message; a Vmm result can't
    /// be Debug-formatted on the Ok side, so unwrap only the error here.
    fn boot_err(r: Result<Vmm<'_>, VmmError>) -> String {
        match r {
            Err(VmmError::BootError(m)) => m,
            Err(e) => panic!("expected BootError, got {e:?}"),
            Ok(_) => panic!("expected BootError refusal, got Ok (VM built)"),
        }
    }

    fn pin_err(r: Result<(), VmmError>) -> String {
        match r {
            Err(VmmError::BootError(m)) => m,
            Err(e) => panic!("expected BootError, got {e:?}"),
            Ok(()) => panic!("expected pin refusal, got Ok"),
        }
    }

    #[test]
    fn ctl_channel_without_ctl_disk_refused() {
        let console = std::env::temp_dir().join(format!("krun-ctlch-{}.log", std::process::id()));
        let file = std::fs::File::create(&console).unwrap();
        let built = base()
            .payload(ctl_payload())
            .returning_console(file)
            .ctl_channel(owned_socketpair_fd())
            .build();
        assert!(boot_err(built).contains("selected together"));
        std::fs::remove_file(&console).unwrap();
    }

    #[test]
    fn ctl_disk_without_ctl_channel_refused() {
        let console = std::env::temp_dir().join(format!("krun-ctldk-{}.log", std::process::id()));
        let file = std::fs::File::create(&console).unwrap();
        let disk = std::env::temp_dir().join(format!("krun-ctldk-{}.img", std::process::id()));
        std::fs::write(&disk, vec![0u8; 512]).unwrap();
        let built = base()
            .payload(ctl_payload())
            .returning_console(file)
            .ctl_disk(disk.to_str().unwrap(), &sha(b"anything"))
            .build();
        assert!(boot_err(built).contains("selected together"));
        std::fs::remove_file(&console).unwrap();
        std::fs::remove_file(&disk).unwrap();
    }

    #[test]
    fn ctl_extensions_without_console_refused() {
        let built = base()
            .payload(ctl_payload())
            .ctl_disk("/nonexistent/disk.img", &sha(b"x"));
        assert!(boot_err(built.build()).contains("require returning_console"));
    }

    #[test]
    fn disk_pin_rejects_mismatch_content() {
        let disk = std::env::temp_dir().join(format!("krun-pin-{}.img", std::process::id()));
        std::fs::write(&disk, vec![1u8; 1024]).unwrap();
        let err = pin_err(verify_disk_pin(disk.to_str().unwrap(), &sha(b"expected")));
        assert!(err.contains("pinned digest"), "{err}");
        std::fs::remove_file(&disk).unwrap();
    }

    #[test]
    fn disk_pin_rejects_bad_size_and_missing_file() {
        let small = std::env::temp_dir().join(format!("krun-pin-s{}.img", std::process::id()));
        std::fs::write(&small, vec![1u8; 100]).unwrap();
        assert!(
            pin_err(verify_disk_pin(small.to_str().unwrap(), &sha(b"x")))
                .contains("multiple of 512")
        );
        std::fs::remove_file(&small).unwrap();

        let empty = std::env::temp_dir().join(format!("krun-pin-e{}.img", std::process::id()));
        std::fs::write(&empty, []).unwrap();
        assert!(
            pin_err(verify_disk_pin(empty.to_str().unwrap(), &sha(b"x")))
                .contains("multiple of 512")
        );
        std::fs::remove_file(&empty).unwrap();

        assert!(
            pin_err(verify_disk_pin("/nonexistent/disk.img", &sha(b"x"))).contains("control disk")
        );
    }

    #[test]
    fn disk_pin_accepts_matching_content() {
        let disk = std::env::temp_dir().join(format!("krun-pin-ok{}.img", std::process::id()));
        std::fs::write(&disk, vec![7u8; 512]).unwrap();
        assert!(verify_disk_pin(disk.to_str().unwrap(), &sha(&[7u8; 512])).is_ok());
        std::fs::remove_file(&disk).unwrap();
    }

    #[test]
    fn legacy_path_payload_unchanged() {
        let p =
            Payload::load_external("/nonexistent/kernel", KernelFormat::Raw, None, "a").unwrap();
        match &p.kind {
            PayloadKind::External { kernel } => {
                assert!(matches!(
                    &kernel.source,
                    ExternalKernelSource::Path { kernel, initramfs: None }
                        if kernel.as_os_str() == "/nonexistent/kernel"
                ));
                assert_eq!(kernel.initramfs_size, 0);
            }
            _ => panic!("expected external payload"),
        }
        assert!(matches!(
            Payload::load_external("/k", KernelFormat::Raw, Some("/nonexistent/initrd"), "a"),
            Err(VmmError::FileNotFound())
        ));

        let initrd = std::env::temp_dir().join(format!("krun-legacy-{}", std::process::id()));
        std::fs::write(&initrd, [0u8; 1234]).unwrap();
        let mut p = Payload::load_external("/k", KernelFormat::Raw, initrd.to_str(), "a").unwrap();
        std::fs::remove_file(&initrd).unwrap();
        p.append_cmdline("b");
        match &p.kind {
            PayloadKind::External { kernel } => {
                assert_eq!(kernel.initramfs_size, 1234);
                assert_eq!(kernel.cmdline.as_deref(), Some("a b"));
            }
            _ => panic!("expected external payload"),
        }
        assert!(passed_lock(
            base().payload(p).set_kernel_console("hvc0").build()
        ));
    }

    // --- v2 control-profile disk triple boundary tests (host-executed) ------
    //
    // `verify_fresh_scratch` and `ctl_disk_attach_order` are consumed by the
    // macOS control-profile arm only, but they are the fable-native-audit
    // F1/F3 fix surface. These tests execute the EXACT helper code that arm
    // calls on EVERY host, so the fresh-inode and vda/vdb/vdc invariants stay
    // detecting instead of source-only (the arm itself first typechecked on
    // aarch64-apple-darwin; executing it stays the Mac gate's business).

    /// Mirror of dsmack-backend disks::create_scratch — the backend's
    /// documented create contract (O_EXCL 0600, EMPTY). libkrun cannot
    /// depend on the backend crate; the cross-crate pairing test lives in
    /// the apple-static integration tree.
    fn scratch_created_like_backend(path: &std::path::Path) {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
    }

    #[test]
    fn fresh_scratch_invariant_accepts_backend_created_inode() {
        let dir = std::env::temp_dir().join(format!("krun-vfs-ok-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("scratch.img");
        scratch_created_like_backend(&p);
        let f = verify_fresh_scratch(p.to_str().unwrap()).unwrap();
        // The sparse pre-size attaches on the very handle the invariant
        // returned (open → verify → size, never a second create).
        f.set_len(SCRATCH_SPARSE_BYTES).unwrap();
        assert_eq!(std::fs::metadata(&p).unwrap().len(), SCRATCH_SPARSE_BYTES);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn fresh_scratch_invariant_refuses_stale_nonempty_wrong_mode_and_missing() {
        let dir = std::env::temp_dir().join(format!("krun-vfs-no-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // stale inode from an earlier launch: reuse must refuse
        let stale = dir.join("stale.img");
        std::fs::write(&stale, vec![0u8; 512]).unwrap();
        assert!(verify_fresh_scratch(stale.to_str().unwrap()).is_err());
        // wrong mode: not the backend's private 0600 create
        let lax = dir.join("lax.img");
        std::fs::write(&lax, []).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mut perm = std::fs::metadata(&lax).unwrap().permissions();
        perm.set_mode(0o644);
        std::fs::set_permissions(&lax, perm).unwrap();
        assert!(verify_fresh_scratch(lax.to_str().unwrap()).is_err());
        // not a regular file
        assert!(verify_fresh_scratch(dir.to_str().unwrap()).is_err());
        // missing: the backend must have created the inode first
        assert!(verify_fresh_scratch(dir.join("absent.img").to_str().unwrap()).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ctl_disk_attach_order_is_the_guest_contract() {
        // vda system (ro), vdb scratch (rw), vdc workload (ro) — the dstack
        // guest pins scratch_device "vdb" (docker data-root) and
        // workload_device "vdc" (dstack-arm64.image.json guest block). This
        // is the F3 regression pin: the workload must never precede the
        // scratch in the attach plan.
        let sys = CtlDiskSpec {
            path: "vda.img".into(),
            expected_sha256_hex: "0".repeat(64),
        };
        let sc = CtlScratchSpec {
            path: "vdb.img".into(),
        };
        let wl = CtlDiskSpec {
            path: "vdc.img".into(),
            expected_sha256_hex: "0".repeat(64),
        };
        let plan = ctl_disk_attach_order(&sys, &sc, &wl);
        let seen: Vec<_> = plan.iter().map(|d| (d.name, d.read_only)).collect();
        assert_eq!(
            seen,
            vec![
                ("dsmack-system", true),
                ("dsmack-scratch", false),
                ("dsmack-workload", true),
            ]
        );
        assert_eq!(plan[0].path, "vda.img");
        assert_eq!(plan[1].path, "vdb.img");
        assert_eq!(plan[2].path, "vdc.img");
    }
}
