//! aarch64-macOS HVF consumption for the v3 GENERIC native backend (F01/F02/
//! F07/F09). Implements the `dsmack_backend_v3::consumption_v3::ConsumptionV3`
//! seam with the real krun returning/control route:
//!   - `Payload::load_external_raw_verified` over the ALREADY-VERIFIED owned
//!     copies (zero new pin source; same bytes the backend verified at R1),
//!   - the v3 control profile (`VmmBuilder::ctl_v3`): the five-role OWNED-FILE
//!     disk set (vda/vdb/vdc/vdd/[vde]) attached via the retained verified
//!     inodes (F02 — no path re-open, no sparse re-init), the vdd result image's
//!     checked flush/sync wired into teardown (F07), plus the single bounded
//!     generic virtio-net option over the caller's connected fd,
//!   - a monotonic clock started BEFORE `build()` (which starts the vCPUs on the
//!     returning profile), so `run_ms` is real elapsed time (F09),
//!   - checked finalization over the RETAINED result/console descriptors (R06)
//!     after the returning teardown proved the writers stopped.
//!
//! Install contract: `dsmack_ctl_v3_init()` (exported below) installs this
//! module as the v3 backend's platform consumption factory exactly once, as the
//! FIRST backend call, BEFORE the first `dsmack_ctl_join_vm_new_v3`. It FAILS
//! CLOSED (returns -1) if the backend ABI is not v3 or a factory is already
//! installed; the caller must then refuse to proceed (the mock platform is NOT
//! silently used on the signed path). This symbol is ABSENT from a host/mock
//! build, which is exactly how the backend's own tests document "no HVF here".
//!
//! Platform gate: `run()` executes a guest ONLY on aarch64 macOS via
//! `Vmm::run_returning`; on any other host the module type-checks and refuses
//! (no VM is ever executed off the profile platform).

use std::fs::File;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};

use dsmack_backend_v3::consumption_v3::{
    install_consumption_factory, BuildRefusedV3, ConsumptionV3, GuestVmV3, LifecyclePhase,
};
use dsmack_backend_v3::disks_v3::{AttachedDiskV3, DiskRole, PRIVATE_IMAGE_BYTES_MAX};
use dsmack_backend_v3::finalize::{self, ConsoleDigest, FinalizeError, ResultDigest, ResultStorage};
use dsmack_backend_v3::net::NetTransport;
use dsmack_backend_v3::owned_verified::VerifiedBootImages;
use dsmack_backend_v3::receipt_v3::{LaunchReceiptV3, RunResultV3};
use krun::api::vmm_builder::{CtlNetSpec, CtlV3DiskFile};
use krun::api::{Payload, VerifiedBootPins, VmmBuilder};

/// F09 — the admitted guest EXECUTION budget wired into the builder. This bounds
/// how long the guest may execute before the returning run fails closed; it is
/// enforced by an INDEPENDENT watchdog armed at vCPU start (not only inside the
/// run loop), so a built-but-unrun VM cannot leave the guest running forever.
/// Distinct from the finalization deadline (post-halt). Stated as an enforceable
/// bound, not a comment-only claim.
pub const GUEST_EXEC_BUDGET_SECONDS: u64 = 3600;

/// The v3 HVF consumption platform.
pub struct HvfConsumptionV3;

/// Install this HVF consumption as the v3 backend's platform factory. Returns
/// false if a factory is already installed (the archive must initialize once).
pub fn install() -> bool {
    install_consumption_factory(|| Box::new(HvfConsumptionV3))
}

/// C surface for the app (declared in include/dsmack_ctl_join_v3.h): call
/// exactly once before the first `dsmack_ctl_join_vm_new_v3`. 0 = installed;
/// -1 = already installed OR the backend ABI version is not 3. FAILS CLOSED.
#[unsafe(no_mangle)]
pub extern "C" fn dsmack_ctl_v3_init() -> i32 {
    if dsmack_backend_v3::ctl_capi_v3::dsmack_ctl_join_abi_version_v3() != 3 {
        return -1;
    }
    if install() { 0 } else { -1 }
}

/// Checked storage over the RETAINED result descriptor: `flush`/`sync` perform a
/// real `fsync` of the verified result inode, and `io_fd` reports that exact
/// descriptor. The imago-layer checked flush/sync already ran (and was
/// propagated) during the returning teardown via the result block's exit
/// observer; this is R06 step (4), the retained-descriptor sync + the identity
/// source for the hash.
struct RetainedResultStorage {
    /// OWNED dup of the retained result descriptor. Owning it (rather than a bare
    /// RawFd) means that when this storage is moved into the supervised finalize
    /// worker, a blocked fsync on a watchdog timeout keeps SAFE OWNERSHIP of the
    /// fd on the detached worker thread — never a reuse race.
    owned: OwnedFd,
}

impl ResultStorage for RetainedResultStorage {
    fn flush_checked(&mut self) -> Result<(), FinalizeError> {
        // SAFETY: fsync on the retained (owned) result descriptor.
        if unsafe { libc::fsync(self.owned.as_raw_fd()) } != 0 {
            return Err(FinalizeError::StorageFlushFailed(
                std::io::Error::last_os_error().to_string(),
            ));
        }
        Ok(())
    }
    fn sync_checked(&mut self) -> Result<(), FinalizeError> {
        if unsafe { libc::fsync(self.owned.as_raw_fd()) } != 0 {
            return Err(FinalizeError::StorageSyncFailed(
                std::io::Error::last_os_error().to_string(),
            ));
        }
        Ok(())
    }
    fn io_fd(&self) -> RawFd {
        self.owned.as_raw_fd()
    }
}

struct HvfVmV3 {
    // Consumed by `run_returning`; None after run.
    vm: Option<krun::api::Vmm<'static>>,
    teardown_cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
    receipt: LaunchReceiptV3,
    // vdd result: a retained hash descriptor (dup of the verified inode handed
    // to the builder) + the admitted template identity.
    result_retained: OwnedFd,
    result_template_sha256: String,
    result_template_bytes: u64,
    // console: a retained descriptor to the O_EXCL console inode.
    console_retained: OwnedFd,
    runtime_input_present: bool,
    phase: LifecyclePhase,
    // F09 — monotonic clock started at build, before any vCPU could run.
    built_at: std::time::Instant,
    // F08 — the returning console's latched byte-cap state, grabbed BEFORE
    // run_returning consumes the VM. After teardown `truncated()` reports the
    // REAL latched flag (whether any console byte was dropped at the cap), which
    // finalize surfaces instead of a hardcoded literal.
    console_truncation: Option<std::sync::Arc<devices::virtio::port_io::ConsoleLimit>>,
}

impl GuestVmV3 for HvfVmV3 {
    fn cancellation_token(&self) -> Option<std::sync::Arc<std::sync::atomic::AtomicBool>> {
        Some(self.teardown_cancel.clone())
    }
    fn run(&mut self) -> Result<i32, BuildRefusedV3> {
        match &self.phase {
            LifecyclePhase::Built => {}
            LifecyclePhase::Halted { .. } | LifecyclePhase::Finalized => {
                return Err(BuildRefusedV3::Platform(
                    "run called out of order (the returning lifecycle runs once)".into(),
                ));
            }
            LifecyclePhase::Faulted(m) => {
                return Err(BuildRefusedV3::Platform(format!("run refused: lifecycle faulted: {m}")));
            }
        }
        let vm = self
            .vm
            .take()
            .ok_or_else(|| BuildRefusedV3::Platform("v3 VM already consumed".into()))?;
        // run_returning exists only for the aarch64-macOS returning profile; it
        // runs the guest to a PSCI halt, performs the CHECKED teardown (exit
        // observers' on_vmm_exit_checked — including the result image's
        // flush/sync — are propagated, failing closed on error), destroys the
        // VM and returns the vCPU exit code (0 == guest halt, not workload
        // success).
        #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
        {
            let vmm_code = vm.run_returning_with_cancel(
                self.teardown_cancel.clone(),
                std::time::Duration::from_secs(finalize::FINALIZE_DEADLINE_SECONDS),
            ) as i32;
            let run_ms = self.built_at.elapsed().as_millis() as u64;
            self.phase = LifecyclePhase::Halted { vmm_code, run_ms };
            Ok(vmm_code)
        }
        #[cfg(not(all(target_arch = "aarch64", target_os = "macos")))]
        {
            drop(vm);
            self.phase = LifecyclePhase::Faulted("HVF requires aarch64 macOS".into());
            Err(BuildRefusedV3::Platform(
                "HVF run requires aarch64 macOS; this host build is type-check-only".into(),
            ))
        }
    }

    fn finalize(
        &mut self,
        cancel: &mut dyn FnMut() -> bool,
        deadline: Option<std::time::Instant>,
    ) -> Result<RunResultV3, FinalizeError> {
        let (vmm_code, run_ms) = match &self.phase {
            LifecyclePhase::Built => return Err(FinalizeError::NotHalted),
            LifecyclePhase::Finalized => return Err(FinalizeError::AlreadyFinalized),
            LifecyclePhase::Faulted(m) => return Err(FinalizeError::LifecycleFault(m.clone())),
            LifecyclePhase::Halted { vmm_code, run_ms } => (*vmm_code, *run_ms),
        };
        // F08: the returning teardown already proved the writers stopped and
        // propagated the imago-layer checked flush/sync. The remaining
        // finalization (retained-descriptor fsync, fixed-size + inode-identity
        // check, bounded pread hash, and the console hash) runs UNDER THE
        // INDEPENDENT WATCHDOG `supervise_finalize`: the worker owns
        // F_DUPFD_CLOEXEC dups of the retained descriptors, so a blocked fsync
        // on timeout is quarantined on a detached thread that keeps SAFE
        // OWNERSHIP of its fds while this call fails closed with NO result. Any
        // failure/timeout latches Faulted so no later finalize can produce a
        // stale result.
        let eff_deadline = deadline.unwrap_or_else(|| {
            std::time::Instant::now()
                + std::time::Duration::from_secs(finalize::FINALIZE_DEADLINE_SECONDS)
        });
        let res_dup = match finalize::dup_retained(self.result_retained.as_fd()) {
            Ok(d) => d,
            Err(e) => {
                self.phase = LifecyclePhase::Faulted(e.to_string());
                return Err(e);
            }
        };
        let io_dup = match finalize::dup_retained(self.result_retained.as_fd()) {
            Ok(d) => d,
            Err(e) => {
                self.phase = LifecyclePhase::Faulted(e.to_string());
                return Err(e);
            }
        };
        let tmpl_bytes = self.result_template_bytes;
        let result: ResultDigest = match finalize::supervise_finalize(
            eff_deadline,
            &mut *cancel,
            move || {
                let mut storage = RetainedResultStorage { owned: io_dup };
                finalize::finalize_result(&mut storage, &res_dup, tmpl_bytes, || false, None)
            },
        ) {
            Ok(r) => r,
            Err(e) => {
                self.phase = LifecyclePhase::Faulted(e.to_string());
                return Err(e);
            }
        };
        // F08: the returning console writer enforced the byte cap on the native
        // path through LimitedPortOutput; read its REAL latched truncation flag
        // here (no longer a hardcoded literal). finalize_console still
        // independently refuses a console that exceeds the cap (fail-closed).
        let console_truncated = self
            .console_truncation
            .as_ref()
            .map(|c| c.truncated())
            .unwrap_or(false);
        let con_dup = match finalize::dup_retained(self.console_retained.as_fd()) {
            Ok(d) => d,
            Err(e) => {
                self.phase = LifecyclePhase::Faulted(e.to_string());
                return Err(e);
            }
        };
        let console: ConsoleDigest = match finalize::supervise_finalize(
            eff_deadline,
            &mut *cancel,
            move || finalize::finalize_console(&con_dup, console_truncated, || false, None),
        ) {
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
            runtime_input_max_bytes: PRIVATE_IMAGE_BYTES_MAX,
            runtime_input_commitment_claim: None,
            vmm_code,
            run_ms,
            backend_abi: dsmack_backend_v3::ctl_capi_v3::ABI_VERSION,
        })
    }

    fn receipt(&self) -> &LaunchReceiptV3 {
        &self.receipt
    }
}

impl ConsumptionV3 for HvfConsumptionV3 {
    fn label(&self) -> &'static str {
        "krun-hvf-v3 (aarch64 macOS; real VM)"
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
        // F09: start the clock BEFORE build() (which starts the vCPUs).
        let built_at = std::time::Instant::now();

        // Pull the result disk out so we can retain its descriptor + template
        // identity; keep the others to build the owned-file set.
        let mut disks = disks;
        let result_pos = disks
            .iter()
            .position(|d| d.role == DiskRole::Result)
            .ok_or(BuildRefusedV3::MissingDisk(DiskRole::Result))?;
        // Retain a hash descriptor to the EXACT verified result inode BEFORE the
        // File is moved into the block device (so the retained descriptor is the
        // verified inode by construction — the R06 identity source).
        let result_retained =
            finalize::dup_retained(disks[result_pos].file.as_fd()).map_err(BuildRefusedV3::Dup)?;
        let result_template_sha256 = disks[result_pos].template_sha256.clone().unwrap_or_default();
        let result_template_bytes =
            disks[result_pos].template_bytes.unwrap_or(disks[result_pos].bytes);
        let runtime_input_present = disks.iter().any(|d| d.role == DiskRole::PrivateInput);

        // Retain a console descriptor BEFORE the console File is handed to krun.
        let console_retained =
            finalize::dup_retained(console.as_fd()).map_err(BuildRefusedV3::Dup)?;

        // Verified payload from the owned copies (double-check; no new pin
        // source — zero compiled-in identity).
        let kpin = receipt.observed_kernel_sha256.clone();
        let ipin = receipt.observed_initrd_sha256.clone();
        let cpin = receipt.observed_cmdline_sha256.clone();
        let pins = VerifiedBootPins {
            kernel_sha256: &kpin,
            initrd_sha256: ipin.as_deref(),
            cmdline_sha256: &cpin,
        };
        let payload = Payload::load_external_raw_verified(
            images.kernel(),
            images.initrd(),
            images.cmdline(),
            &pins,
        )
        .map_err(|e| BuildRefusedV3::Platform(format!("krun verified payload: {e:?}")))?;

        // Build the five-role OWNED-FILE disk set in guest enumeration order.
        // Every disk is attached from its retained verified inode (F02).
        let mut files: Vec<CtlV3DiskFile> = Vec::with_capacity(5);
        let order = [
            (DiskRole::System, "dsmack-system", true, false),
            (DiskRole::Scratch, "dsmack-scratch", false, false),
            (DiskRole::Workload, "dsmack-workload", true, false),
            (DiskRole::Result, "dsmack-result", false, true),
            (DiskRole::PrivateInput, "dsmack-private", true, false),
        ];
        for (role, name, read_only, is_result) in order {
            if let Some(pos) = disks.iter().position(|d| d.role == role) {
                let d = disks.remove(pos);
                files.push(CtlV3DiskFile {
                    name: name.to_string(),
                    file: d.file,
                    read_only,
                    is_result,
                });
            } else if role == DiskRole::Result {
                return Err(BuildRefusedV3::MissingDisk(DiskRole::Result));
            }
            // vde (PrivateInput) is optional; the others are required by the
            // backend before build() and their absence is a MissingDisk below.
        }
        for required in [DiskRole::System, DiskRole::Scratch, DiskRole::Workload] {
            if !files.iter().any(|f| match required {
                DiskRole::System => f.name == "dsmack-system",
                DiskRole::Scratch => f.name == "dsmack-scratch",
                DiskRole::Workload => f.name == "dsmack-workload",
                _ => false,
            }) {
                return Err(BuildRefusedV3::MissingDisk(required));
            }
        }

        // The single bounded generic NIC (if present): take ownership of the
        // validated connected fd and attach it with the fixed MAC.
        let net_spec: Option<CtlNetSpec> = net.map(|t| {
            let mac = t.mac();
            let raw = t.into_unixstream_fd();
            // SAFETY: NetTransport owned the fd and relinquished it via
            // into_unixstream_fd; we re-own it here for the device.
            let fd = unsafe { OwnedFd::from_raw_fd(raw) };
            CtlNetSpec { fd, mac, features: 0 }
        });

        let vcpus = receipt.vcpus;
        let ram_mib = receipt.ram_mib;
        let builder = VmmBuilder::new()
            .vcpus(vcpus)
            .map_err(|e| BuildRefusedV3::Platform(format!("vcpus: {e:?}")))?
            .ram_mib(ram_mib)
            .map_err(|e| BuildRefusedV3::Platform(format!("memory: {e:?}")))?
            // F09: WIRE the intended execution budget through the native adapter
            // (the reviewer's "HVF adapter never calls the new exec_budget
            // setter"). The builder arms an INDEPENDENT watchdog from this budget
            // at vCPU start, so the guest cannot execute past it even if run() is
            // deferred. Explicit here rather than relying on the builder's silent
            // returning-profile fallback.
            .exec_budget(std::time::Duration::from_secs(GUEST_EXEC_BUDGET_SECONDS))
            .payload(payload)
            .returning_console(console)
            .ctl_v3(control, files, net_spec);
        let vm = builder
            .build()
            .map_err(|e| BuildRefusedV3::Platform(format!("krun v3 build: {e:?}")))?;
        // F08: grab the console byte-cap handle BEFORE run_returning consumes the
        // VM, so the REAL latched truncation flag is readable in finalize.
        let console_truncation = vm.console_truncation();

        Ok(Box::new(HvfVmV3 {
            vm: Some(vm),
            teardown_cancel: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            receipt,
            result_retained,
            result_template_sha256,
            result_template_bytes,
            console_retained,
            runtime_input_present,
            phase: LifecyclePhase::Built,
            built_at,
            console_truncation,
        }))
    }
}
