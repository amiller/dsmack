//! The v3 consumption seam + the host mock platform.
//!
//! `build` receives everything already verified — owned boot images, the
//! five-device verified set (each holding its retained inode), the owned
//! control descriptor, the optional owned generic-NIC transport, the O_EXCL
//! console, and the prebuilt launch receipt. It must not re-open any verified
//! path and must consume boot bytes only from `images`.
//!
//! FD OWNERSHIP (exact, on every path):
//!   - `control`: moves into `build`. On a build REFUSAL it is dropped (closed
//!     exactly once). On success it lives inside the built VM and is closed
//!     exactly once at teardown. The caller must never touch it again.
//!   - `net` (optional): identical discipline — the `NetTransport` owns the fd;
//!     dropped/closed once on refusal, held and closed once on teardown.
//!   - the vdd/console retained descriptors are dup'd (F_DUPFD_CLOEXEC, access
//!     mode preserved) at build and closed once at teardown.
//!
//! On aarch64 macOS the real HVF consumption is installed via the factory; this
//! crate alone runs the MOCK platform (engineering evidence on Linux — never a
//! VM, never Mac evidence), which performs the ACTUAL checked finalization over
//! the retained descriptors so R06 is unit-proven on real file/FD/storage.

use std::fs::File;
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};

use crate::disks_v3::{AttachedDiskV3, DiskRole};
use crate::finalize::{self, ConsoleDigest, FinalizeError, ResultDigest, ResultStorage};
use crate::net::NetTransport;
use crate::owned_verified::VerifiedBootImages;
use crate::receipt_v3::{LaunchReceiptV3, RunResultV3};

pub const MOCK_LABEL: &str = "mock-platform-v3 (engineering; not a VM; not Mac evidence)";

#[derive(Debug, thiserror::Error)]
pub enum BuildRefusedV3 {
    #[error("missing {0} in verified disk set")]
    MissingDisk(DiskRole),
    #[error("consumption unavailable on this platform: {0}")]
    Platform(String),
    #[error("retained descriptor dup: {0}")]
    Dup(FinalizeError),
}

/// Concrete storage layer over a raw I/O fd. On the real backend the imago
/// `FormatAccess` implements `ResultStorage`; here `flush_checked`/`sync_checked`
/// perform a real `fsync` (or an injected failure, for the adversarial tests).
pub struct FdStorage {
    io_fd: RawFd,
    /// When present, the storage OWNS the I/O descriptor — used by the
    /// watchdog-supervised finalize path so a blocked flush/sync on a detached
    /// worker thread retains safe ownership of its fd (never a reuse race).
    _owned: Option<OwnedFd>,
    pub inject_flush_error: Option<String>,
    pub inject_sync_error: Option<String>,
}

impl FdStorage {
    pub fn new(io_fd: RawFd) -> Self {
        Self {
            io_fd,
            _owned: None,
            inject_flush_error: None,
            inject_sync_error: None,
        }
    }
    /// Build storage that OWNS its I/O descriptor (an `F_DUPFD_CLOEXEC` dup of
    /// the device's I/O fd). The owned fd travels with the storage into the
    /// supervised worker thread, so a timeout can safely detach the worker.
    pub fn owning(fd: OwnedFd) -> Self {
        Self {
            io_fd: fd.as_raw_fd(),
            _owned: Some(fd),
            inject_flush_error: None,
            inject_sync_error: None,
        }
    }
    pub fn with_flush_error(io_fd: RawFd, msg: &str) -> Self {
        Self {
            io_fd,
            _owned: None,
            inject_flush_error: Some(msg.to_string()),
            inject_sync_error: None,
        }
    }
    pub fn with_sync_error(io_fd: RawFd, msg: &str) -> Self {
        Self {
            io_fd,
            _owned: None,
            inject_flush_error: None,
            inject_sync_error: Some(msg.to_string()),
        }
    }
}

impl ResultStorage for FdStorage {
    fn flush_checked(&mut self) -> Result<(), FinalizeError> {
        if let Some(m) = &self.inject_flush_error {
            return Err(FinalizeError::StorageFlushFailed(m.clone()));
        }
        // SAFETY: fsync on the owned I/O fd.
        if unsafe { libc::fsync(self.io_fd) } != 0 {
            return Err(FinalizeError::StorageFlushFailed(
                std::io::Error::last_os_error().to_string(),
            ));
        }
        Ok(())
    }
    fn sync_checked(&mut self) -> Result<(), FinalizeError> {
        if let Some(m) = &self.inject_sync_error {
            return Err(FinalizeError::StorageSyncFailed(m.clone()));
        }
        if unsafe { libc::fsync(self.io_fd) } != 0 {
            return Err(FinalizeError::StorageSyncFailed(
                std::io::Error::last_os_error().to_string(),
            ));
        }
        Ok(())
    }
    fn io_fd(&self) -> RawFd {
        self.io_fd
    }
}

pub trait ConsumptionV3 {
    fn label(&self) -> &'static str;
    #[allow(clippy::too_many_arguments)]
    fn build(
        &self,
        images: VerifiedBootImages,
        disks: Vec<AttachedDiskV3>,
        control: OwnedFd,
        net: Option<NetTransport>,
        console: File,
        receipt: LaunchReceiptV3,
    ) -> Result<Box<dyn GuestVmV3>, BuildRefusedV3>;
}

pub trait GuestVmV3 {
    fn cancellation_token(&self) -> Option<std::sync::Arc<std::sync::atomic::AtomicBool>> {
        None
    }

    /// Real-guest run. The mock never executes a guest and returns the honest
    /// platform refusal; on HVF this runs the returning lifecycle and fuses the
    /// checked teardown/finalization below.
    fn run(&mut self) -> Result<i32, BuildRefusedV3>;
    /// Checked finalization over the retained descriptors (R06). On the mock
    /// this is the exercisable mechanism (no guest ran); on HVF it is the
    /// teardown path invoked inside `run`.
    fn finalize(
        &mut self,
        cancel: &mut dyn FnMut() -> bool,
        deadline: Option<std::time::Instant>,
    ) -> Result<RunResultV3, FinalizeError>;
    fn receipt(&self) -> &LaunchReceiptV3;
}

/// F07 — the terminal native lifecycle. finalize is permitted ONLY from a
/// proven `Halted` state; a finalize failure latches `Faulted` so a repeated
/// finalize re-reports the fault and can never resurrect a stale result; a
/// completed finalize latches `Finalized` (the result is single-shot).
#[derive(Debug, Clone)]
pub enum LifecyclePhase {
    /// Built but the guest has not run; finalize is refused (NotHalted).
    Built,
    /// The returning run completed and the writers are proven stopped. Carries
    /// the ACTUAL vmm exit code and the ACTUAL elapsed run time (F09).
    Halted { vmm_code: i32, run_ms: u64 },
    /// finalize completed once; the result is now single-shot.
    Finalized,
    /// A teardown/finalize fault, latched permanently.
    Faulted(String),
}

/// The host mock platform. Holds all owned descriptors; retains dup'd hash
/// descriptors for vdd and the console at build time.
pub struct MockPlatform;

pub struct MockVm {
    receipt: LaunchReceiptV3,
    // vdd result: the VERIFIED/created inode File (I/O descriptor) + a retained
    // dup (hash descriptor, same inode, access mode preserved).
    vdd_file: File,
    vdd_retained: OwnedFd,
    result_template_sha256: String,
    result_template_bytes: u64,
    // console: the O_EXCL inode + a retained dup.
    console_file: File,
    console_retained: OwnedFd,
    /// F08: the console limiter's latched truncation state — NEVER a hardcoded
    /// literal. Derived from the `LimitedConsoleWriter` every console byte went
    /// through at build time.
    console_truncated: bool,
    runtime_input_present: bool,
    // F07/F09 lifecycle.
    phase: LifecyclePhase,
    /// F09: the monotonic clock STARTS at build — before any vCPU could run —
    /// so run_ms covers construction→execution and is never a hardcoded 0.
    built_at: std::time::Instant,
    // owned for their whole lifetime; closed exactly once on drop.
    _control: OwnedFd,
    _net: Option<NetTransport>,
    _images: VerifiedBootImages,
    _other_disks: Vec<AttachedDiskV3>,
}

impl ConsumptionV3 for MockPlatform {
    fn label(&self) -> &'static str {
        MOCK_LABEL
    }

    fn build(
        &self,
        images: VerifiedBootImages,
        disks: Vec<AttachedDiskV3>,
        control: OwnedFd,
        net: Option<NetTransport>,
        console: File,
        receipt: LaunchReceiptV3,
    ) -> Result<Box<dyn GuestVmV3>, BuildRefusedV3> {
        use std::io::Write as _;
        // F09: start the monotonic clock BEFORE anything that could execute a
        // guest (on HVF the builder starts vCPUs in build()).
        let built_at = std::time::Instant::now();
        // Pull the result disk out; the rest are held to keep their inodes.
        let mut disks = disks;
        let pos = disks
            .iter()
            .position(|d| d.role == DiskRole::Result)
            .ok_or(BuildRefusedV3::MissingDisk(DiskRole::Result))?;
        let vdd = disks.remove(pos);
        let runtime_input_present = disks.iter().any(|d| d.role == DiskRole::PrivateInput);
        let result_template_sha256 = vdd.template_sha256.clone().unwrap_or_default();
        let result_template_bytes = vdd.template_bytes.unwrap_or(vdd.bytes);

        // F08: the honest engineering banner is written through the SAME
        // LimitedConsoleWriter every console byte must pass through, and the
        // console's `truncated` flag is taken from the limiter's latched state
        // — never hardcoded. (On the mock the banner is far under the cap, so
        // truncated is genuinely false; the value is still limiter-derived.)
        let mut writer = finalize::LimitedConsoleWriter::new(console);
        let _ = writeln!(
            writer,
            "DSMACK_BACKEND_V3 consumption={MOCK_LABEL} \
             kernel_sha256={} result_template_sha256={}",
            receipt.observed_kernel_sha256, result_template_sha256
        );
        let _ = writer.flush();
        let console_truncated = writer.truncated();
        let console = writer.into_inner();

        // Retain dup'd hash descriptors (access mode preserved — vdd is RW).
        let vdd_retained = finalize::dup_retained(vdd.file.as_fd()).map_err(BuildRefusedV3::Dup)?;
        let console_retained =
            finalize::dup_retained(console.as_fd()).map_err(BuildRefusedV3::Dup)?;

        Ok(Box::new(MockVm {
            receipt,
            vdd_file: vdd.file,
            vdd_retained,
            result_template_sha256,
            result_template_bytes,
            console_file: console,
            console_retained,
            console_truncated,
            runtime_input_present,
            phase: LifecyclePhase::Built,
            built_at,
            _control: control,
            _net: net,
            _images: images,
            _other_disks: disks,
        }))
    }
}

impl GuestVmV3 for MockVm {
    /// Perform the lifecycle QUIESCENCE transition. The mock executes NO guest
    /// (there is none — the banner and `consumption=MOCK_LABEL` make that
    /// explicit, and the result bytes are the template copy, not guest output);
    /// it models the returning backend's teardown ordering so the finalize
    /// gate (F07) and the actual-timing accounting (F09) are proven on real
    /// file/FD/storage. Built -> Halted exactly once; any re-entry is refused.
    fn run(&mut self) -> Result<i32, BuildRefusedV3> {
        match self.phase {
            LifecyclePhase::Built => {}
            LifecyclePhase::Halted { .. } | LifecyclePhase::Finalized => {
                return Err(BuildRefusedV3::Platform(
                    "run called out of order (the returning lifecycle runs once)".into(),
                ));
            }
            LifecyclePhase::Faulted(ref m) => {
                return Err(BuildRefusedV3::Platform(format!(
                    "run refused: lifecycle faulted: {m}"
                )));
            }
        }
        // No guest, no writers to stop on the mock; record ACTUAL elapsed since
        // build (F09) and a mock halt code (0 == PSCI-style halt, NOT guest
        // workload success — carried honestly in the honesty block).
        let run_ms = self.built_at.elapsed().as_millis() as u64;
        let vmm_code = 0;
        self.phase = LifecyclePhase::Halted { vmm_code, run_ms };
        Ok(vmm_code)
    }

    fn finalize(
        &mut self,
        cancel: &mut dyn FnMut() -> bool,
        deadline: Option<std::time::Instant>,
    ) -> Result<RunResultV3, FinalizeError> {
        // F07: finalize ONLY from a proven halt. Built -> NotHalted;
        // Finalized -> AlreadyFinalized (single-shot); Faulted -> re-report.
        let (vmm_code, run_ms) = match &self.phase {
            LifecyclePhase::Built => return Err(FinalizeError::NotHalted),
            LifecyclePhase::Finalized => return Err(FinalizeError::AlreadyFinalized),
            LifecyclePhase::Faulted(m) => return Err(FinalizeError::LifecycleFault(m.clone())),
            LifecyclePhase::Halted { vmm_code, run_ms } => (*vmm_code, *run_ms),
        };
        // F08: the whole finalization (checked storage flush/sync over the vdd
        // I/O descriptor, retained-descriptor fsync, identity, bounded pread, and
        // the console hash) runs UNDER THE INDEPENDENT WATCHDOG. The worker owns
        // F_DUPFD_CLOEXEC dups of the I/O and retained descriptors, so a blocked
        // flush/sync/fsync on timeout is quarantined on a detached thread that
        // keeps safe ownership of its fds — the call fails closed with NO result
        // rather than hanging or freeing a descriptor into a reuse race. A
        // failure (or timeout) LATCHES Faulted so no later finalize can produce a
        // stale result.
        let eff_deadline = deadline.unwrap_or_else(|| {
            std::time::Instant::now()
                + std::time::Duration::from_secs(finalize::FINALIZE_DEADLINE_SECONDS)
        });
        // Owned dups handed to the worker (safe ownership on timeout).
        let io_dup = match finalize::dup_retained(self.vdd_file.as_fd()) {
            Ok(d) => d,
            Err(e) => {
                self.phase = LifecyclePhase::Faulted(e.to_string());
                return Err(e);
            }
        };
        let ret_dup = match finalize::dup_retained(self.vdd_retained.as_fd()) {
            Ok(d) => d,
            Err(e) => {
                self.phase = LifecyclePhase::Faulted(e.to_string());
                return Err(e);
            }
        };
        let tmpl_bytes = self.result_template_bytes;
        let result: ResultDigest =
            match finalize::supervise_finalize(eff_deadline, &mut *cancel, move || {
                let mut storage = FdStorage::owning(io_dup);
                finalize::finalize_result(&mut storage, &ret_dup, tmpl_bytes, || false, None)
            }) {
                Ok(r) => r,
                Err(e) => {
                    self.phase = LifecyclePhase::Faulted(e.to_string());
                    return Err(e);
                }
            };
        let _ = self.console_file.as_raw_fd(); // console I/O fd kept alive
        let con_dup = match finalize::dup_retained(self.console_retained.as_fd()) {
            Ok(d) => d,
            Err(e) => {
                self.phase = LifecyclePhase::Faulted(e.to_string());
                return Err(e);
            }
        };
        let con_trunc = self.console_truncated;
        let console: ConsoleDigest =
            match finalize::supervise_finalize(eff_deadline, &mut *cancel, move || {
                finalize::finalize_console(&con_dup, con_trunc, || false, None)
            }) {
                Ok(c) => c,
                Err(e) => {
                    self.phase = LifecyclePhase::Faulted(e.to_string());
                    return Err(e);
                }
            };
        self.phase = LifecyclePhase::Finalized;
        Ok(RunResultV3 {
            result_role: "vdd",
            result_template_sha256: self.result_template_sha256.clone(),
            result_template_bytes: self.result_template_bytes,
            result,
            console,
            runtime_input_present: self.runtime_input_present,
            runtime_input_max_bytes: crate::disks_v3::PRIVATE_IMAGE_BYTES_MAX,
            runtime_input_commitment_claim: None,
            vmm_code,
            run_ms,
            backend_abi: crate::ctl_capi_v3::ABI_VERSION,
        })
    }

    fn receipt(&self) -> &LaunchReceiptV3 {
        &self.receipt
    }
}

// --- platform consumption factory (one-way install; mirrors v2) ---

static FACTORY: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// F01 — explicit test-only opt-in. The MOCK is NEVER a production fallback: it
/// runs ONLY when a test harness deliberately installs it through
/// `install_mock_for_test`, which sets this flag. A production archive that
/// forgets `dsmack_ctl_v3_init` (no HVF factory, no test opt-in) fails CLOSED in
/// `default_consumption` rather than silently executing the non-VM mock.
static MOCK_FOR_TEST: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn install_consumption_factory(f: fn() -> Box<dyn ConsumptionV3>) -> bool {
    FACTORY
        .compare_exchange(
            0,
            f as usize,
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
        )
        .is_ok()
}

/// F01 — install the host MockPlatform as the v3 consumption factory for a TEST
/// process only, and mark this process as an explicit test configuration.
/// Returns false if a factory is already installed. The real HVF archive never
/// calls this; only the backend-v3 unit/integration tests do. It is the sole
/// path by which `default_consumption` will ever yield a `MockPlatform`.
pub fn install_mock_for_test() -> bool {
    MOCK_FOR_TEST.store(true, std::sync::atomic::Ordering::SeqCst);
    install_consumption_factory(|| Box::new(MockPlatform))
}

/// F01 — resolve the platform consumption, FAILING CLOSED. VM creation is
/// refused unless the native HVF factory has been installed (via
/// `dsmack_ctl_v3_init`) OR the process explicitly opted into the test mock
/// (`install_mock_for_test`). Previously this returned `MockPlatform` whenever
/// the factory was unset, so an uninitialized production path silently executed
/// the non-VM mock; that fail-open default is removed.
pub fn default_consumption() -> Result<Box<dyn ConsumptionV3>, BuildRefusedV3> {
    let f = FACTORY.load(std::sync::atomic::Ordering::SeqCst);
    if f != 0 {
        // The installed factory is the MockPlatform ONLY when this process
        // explicitly opted in via install_mock_for_test; on the real archive it
        // is the HVF ConsumptionV3 installed by dsmack_ctl_v3_init. Either way a
        // factory was deliberately installed, so honour it.
        // SAFETY: FACTORY only ever holds a `fn() -> Box<dyn ConsumptionV3>`
        // installed by install_consumption_factory.
        let f: fn() -> Box<dyn ConsumptionV3> = unsafe { std::mem::transmute(f) };
        return Ok(f());
    }
    // No factory and no test opt-in: refuse. The mock is NEVER a production
    // fallback — a build that reaches here never called dsmack_ctl_v3_init.
    debug_assert!(
        !MOCK_FOR_TEST.load(std::sync::atomic::Ordering::SeqCst),
        "test opted into the mock but no factory installed"
    );
    Err(BuildRefusedV3::Platform(
        "no native consumption factory installed: call dsmack_ctl_v3_init() before \
         dsmack_ctl_join_vm_new_v3 (the mock platform is test-only and is not a \
         production fallback)"
            .into(),
    ))
}
