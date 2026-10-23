//! aarch64-macOS HVF consumption for the v2 general backend: implements the
//! `dsmack_backend::Consumption` seam with the demonstrated krun route —
//! `Payload::load_external_raw_verified` over the ALREADY-VERIFIED owned
//! copies, the returning/control builder (vcpus/ram from the admitted
//! profile), `ctl_channel` (the named `dsmack-ctl` console over the caller's
//! owned descriptor — unchanged from v1), and the vda/vdb/vdc triple.
//!
//! Install contract: `dsmack_ctl_v2_init()` (exported below) installs this
//! module as the backend's platform consumption factory exactly once,
//! BEFORE the first `dsmack_ctl_join_vm_new` call (the Swift v2 binding
//! calls it as its first backend call and refuses on false). Nothing here
//! changes any ABI or refusal of the backend crate — this module only
//! supplies the real guest run path this crate alone refuses to fake.
//!
//! Honesty notes carried into every build:
//! - krun's `ctl_disk`/`ctl_workload_disk` re-hash the paths at attach
//!   (upstream `verify_disk_pin`); the backend crate already verified the
//!   same paths at open. The rootfs SECURITY boundary is the verified
//!   initrd's in-guest dm-verity plus the fail-closed cmdline (R4) — the
//!   host-side hashes are engineering narrowing, not the boundary.
//! - `run()` consumes the built VM and returns the VMM code (0 = guest halt
//!   via PSCI, never workload success), identical to v1's checked teardown.
use dsmack_backend::consumption::{BuildRefused, Consumption, GuestVm};
use dsmack_backend::disks::{AttachedDisk, DiskRole};
use dsmack_backend::owned_verified::VerifiedBootImages;
use dsmack_backend::receipt::LaunchReceipt;
use krun::api::{Payload, VmmBuilder};
use std::os::fd::OwnedFd;

pub struct HvfConsumption;

/// Install this platform consumption into the backend. Returns false if a
/// factory is already installed (the archive must be initialized once).
pub fn install() -> bool {
    dsmack_backend::ctl_capi::install_consumption_factory(|| Box::new(HvfConsumption))
}

/// C surface for the app: call exactly once before the first
/// `dsmack_ctl_join_vm_new`; 0 = installed, -1 = already installed or the
/// backend ABI version mismatched (the caller must refuse to proceed).
#[unsafe(no_mangle)]
pub extern "C" fn dsmack_ctl_v2_init() -> i32 {
    if dsmack_backend::ctl_capi::dsmack_ctl_join_abi_version() != 2 {
        return -1;
    }
    if install() {
        0
    } else {
        -1
    }
}

struct HvfVm {
    vm: krun::api::Vmm<'static>,
    receipt: LaunchReceipt,
}

impl GuestVm for HvfVm {
    fn run(self: Box<Self>) -> Result<i32, BuildRefused> {
        // Whole returning lifecycle to completion (checked teardown inside
        // krun). The receipt was readable before the run via
        // dsmack_ctl_join_receipt; the console log is final only after this.
        // run_returning exists only for the aarch64-macOS profile; other
        // hosts compile this module for unit coverage only and never execute
        // a VM (same cfg discipline as the v1 ctl_capi run arm).
        #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
        {
            Ok(self.vm.run_returning() as i32)
        }
        #[cfg(not(all(target_arch = "aarch64", target_os = "macos")))]
        {
            drop(self.vm);
            Err(BuildRefused::Platform(
                "HVF run requires aarch64 macOS; this host build is \
                 unit-coverage only"
                    .into(),
            ))
        }
    }

    /// The HVF route writes guest memory from the SAME owned Arc buffers the
    /// backend verified (upstream write_verified_images; the vendored
    /// placement proof lives in the backend crate's guest_write module). krun
    /// does not expose a guest-RAM readback, so the placed digests reported
    /// here are the verified owned-copy digests — labeled as such.
    fn placed_kernel_sha256(&self) -> String {
        self.receipt.observed_kernel_sha256.clone()
    }

    fn placed_initrd_sha256(&self) -> Option<String> {
        self.receipt.observed_initrd_sha256.clone()
    }

    fn receipt(&self) -> &LaunchReceipt {
        &self.receipt
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl Consumption for HvfConsumption {
    fn label(&self) -> &'static str {
        "krun-hvf (aarch64 macOS; real VM)"
    }

    fn build(
        &self,
        images: VerifiedBootImages,
        disks: Vec<AttachedDisk>,
        control: OwnedFd,
        console: std::fs::File,
        receipt: LaunchReceipt,
    ) -> Result<Box<dyn GuestVm>, BuildRefused> {
        let take = |disks: &mut Vec<AttachedDisk>, role: DiskRole| -> Result<AttachedDisk, BuildRefused> {
            let pos = disks.iter().position(|d| d.role == role).ok_or_else(|| {
                BuildRefused::Platform(format!("missing {} in verified disk set", role.name()))
            })?;
            Ok(disks.remove(pos))
        };
        let mut disks = disks;
        let system = take(&mut disks, DiskRole::System)?;
        let scratch = take(&mut disks, DiskRole::Scratch)?;
        let workload = take(&mut disks, DiskRole::Workload)?;

        // Pins: the bytes were already verified against the admitted spec
        // inside the backend (R1); krun re-verifies the same owned copies
        // (double check, no new pin source — still zero compiled-in pins).
        let kpin = receipt.observed_kernel_sha256.clone();
        let ipin = receipt.observed_initrd_sha256.clone();
        let cpin = receipt.observed_cmdline_sha256.clone();
        let pins = krun::api::VerifiedBootPins {
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
        .map_err(|e| BuildRefused::Placement(format!("krun verified payload: {e:?}")))?;

        let sys_sha = system.observed_sha256.clone();
        let wl_sha = workload.observed_sha256.clone();
        let builder = VmmBuilder::new()
            .vcpus(receipt.vcpus)
            .map_err(|e| BuildRefused::Placement(format!("vcpus: {e:?}")))?
            .ram_mib(receipt.ram_mib)
            .map_err(|e| BuildRefused::Placement(format!("memory: {e:?}")))?
            .payload(payload)
            .returning_console(console)
            .ctl_channel(control)
            .ctl_disk(&system.path, &sys_sha)
            .ctl_scratch_disk(&scratch.path)
            .ctl_workload_disk(&workload.path, &wl_sha);
        let vm = builder
            .build()
            .map_err(|e| BuildRefused::Placement(format!("krun build: {e:?}")))?;
        Ok(Box::new(HvfVm { vm, receipt }))
    }
}

#[cfg(test)]
mod tests {
    //! Host-executed checks for the HVF seam. fable-native-audit §6.3: this
    //! module previously had ZERO execution coverage anywhere (its `run`
    //! arm is aarch64-macOS-only and no host ever built the krun build path
    //! against the backend). These tests execute everything up to the
    //! platform gate on every host: the verified disk triple extraction, the
    //! receipt-pin reuse (still zero compiled-in identity), the owned-copy
    //! payload load, the builder chain, and the R4 descriptor ownership on
    //! the refusal path. They do NOT touch the one-way factory (direct
    //! `HvfConsumption` calls), so they compose with the backend crate's own
    //! factory tests in any order.

    use super::*;
    use dsmack_backend::disks::{create_scratch, open_verified_ro};
    use dsmack_backend::owned_verified::{VerifiedBootImages, VerifiedBootPins};
    use dsmack_backend::receipt::LaunchReceipt;
    use dsmack_backend::spec::LaunchSpec;
    use krun::api::vmm_builder::{ctl_disk_attach_order, verify_fresh_scratch};
    use sha2::{Digest, Sha256};
    use std::os::fd::FromRawFd;

    fn sha(b: &[u8]) -> String {
        format!("{:x}", Sha256::digest(b))
    }

    struct Fixture {
        dir: std::path::PathBuf,
        images: VerifiedBootImages,
        attached: Vec<AttachedDisk>,
        receipt: LaunchReceipt,
    }

    /// One fully-verified launch fixture: real backend disk verification
    /// (verify-on-open vda/vdc, O_EXCL fresh vdb) over real files, the
    /// matching admitted spec, and the receipt recorded from them.
    fn fixture(tag: &str) -> Fixture {
        let d = std::env::temp_dir().join(format!("dsmack-hvf-{}-{}", tag, std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let kernel = {
            let mut k = vec![0u8; 512];
            k[56..60].copy_from_slice(b"ARM\x64");
            k
        };
        let cmdline = "console=hvc0";
        let images = VerifiedBootImages::new(
            &kernel,
            None,
            cmdline,
            &VerifiedBootPins {
                kernel_sha256: &sha(&kernel),
                initrd_sha256: None,
                cmdline_sha256: &sha(cmdline.as_bytes()),
            },
        )
        .unwrap();
        let system = d.join("system.img");
        std::fs::write(&system, vec![0u8; 512]).unwrap();
        let workload = d.join("workload.img");
        std::fs::write(&workload, vec![1u8; 512]).unwrap();
        let attached = vec![
            open_verified_ro(
                DiskRole::System,
                system.to_str().unwrap(),
                &sha(&[0u8; 512]),
            )
            .unwrap(),
            create_scratch(d.join("scratch.img").to_str().unwrap()).unwrap(),
            open_verified_ro(
                DiskRole::Workload,
                workload.to_str().unwrap(),
                &sha(&[1u8; 512]),
            )
            .unwrap(),
        ];
        let spec = LaunchSpec {
            spec_sha256: sha(b"admitted-spec-doc"),
            kernel_sha256: sha(&kernel),
            initrd_sha256: None,
            cmdline: cmdline.to_string(),
            cmdline_sha256: sha(cmdline.as_bytes()),
            system_sha256: sha(&[0u8; 512]),
            verity_root_hash: sha(b"verity"),
            workload_sha256: sha(&[1u8; 512]),
            ram_mib: 512,
            vcpus: 1,
        };
        let receipt = LaunchReceipt::record(&spec, &images, &attached, "hvf-seam-test");
        Fixture {
            dir: d,
            images,
            attached,
            receipt,
        }
    }

    fn fd_is_open(fd: i32) -> bool {
        // SAFETY: borrowing a possibly-closed descriptor for an F_GETFD
        // probe is how the R4 contract itself must be observed; EBADF == closed.
        let rc = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        rc != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EBADF)
    }

    /// The full HVF wiring executes on every host UP TO the platform gate:
    /// krun's control profile refuses outside aarch64 macOS (before any VM),
    /// and the refusal must surface as the consumption Placement error with
    /// the caller's control descriptor closed exactly once (R4 through the
    /// HVF consumption refusal path — the first execution coverage of this
    /// module's build() anywhere).
    #[test]
    fn hvf_build_refuses_on_host_and_closes_control_fd() {
        let f = fixture("host-refusal");
        let mut fds = [0 as libc::c_int; 2];
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) },
            0
        );
        // SAFETY: fds[1] is a fresh owned descriptor from socketpair.
        let control = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        let console = f.dir.join("console.log");
        let console_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&console)
            .unwrap();
        let r = HvfConsumption.build(
            f.images,
            f.attached,
            control,
            console_file,
            f.receipt,
        );
        match r {
            Err(BuildRefused::Placement(m)) => {
                assert!(
                    m.contains("aarch64 macOS only"),
                    "expected the platform gate, got: {m}"
                );
            }
            Err(other) => panic!("expected host platform refusal, got {other}"),
            Ok(_) => panic!("expected host platform refusal, got Ok (VM built)"),
        }
        assert!(
            !fd_is_open(fds[1]),
            "refusal must close the control descriptor exactly once"
        );
        unsafe { libc::close(fds[0]) };
        let _ = std::fs::remove_dir_all(&f.dir);
    }

    /// F1 cross-crate pairing (fable-native-audit): the backend owns the
    /// fresh-inode create (O_EXCL 0600 EMPTY); krun's attach-side invariant
    /// must ACCEPT exactly that inode and nothing else. Before the fix,
    /// krun re-created O_EXCL on the backend's inode and refused EVERY v2
    /// launch at krun build.
    #[test]
    fn scratch_pairing_backend_create_then_krun_invariant() {
        let d = std::env::temp_dir().join(format!("dsmack-hvf-scratch-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("scratch.img").to_str().unwrap().to_string();
        // backend create → krun invariant accepts the backend's inode
        let attached = create_scratch(&p).unwrap();
        assert!(!attached.read_only);
        drop(attached);
        let sized = verify_fresh_scratch(&p).unwrap();
        // attach pre-sizes sparse; a SECOND attach-time verify refuses (the
        // invariant is attach-time only, never a mid-flight re-create)
        sized.set_len(2 << 30).unwrap();
        drop(sized);
        assert!(verify_fresh_scratch(&p).is_err());
        // and the backend itself refuses reuse of the now-existing inode
        assert!(matches!(
            create_scratch(&p),
            Err(dsmack_backend::disks::DiskError::ScratchPreExisting { .. })
        ));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// F3 cross-crate pairing (fable-native-audit): libkrun's attach plan is
    /// the backend's DiskRole order — vda system (ro), vdb scratch (rw),
    /// vdc workload (ro). Before the fix the plan attached the workload
    /// before the scratch, inverting the pinned guest contract.
    #[test]
    fn disk_role_attach_order_matches_backend_roles() {
        let sys = krun::api::vmm_builder::CtlDiskSpec {
            path: "vda.img".to_string(),
            expected_sha256_hex: "0".repeat(64),
        };
        let sc = krun::api::vmm_builder::CtlScratchSpec {
            path: "vdb.img".to_string(),
        };
        let wl = krun::api::vmm_builder::CtlDiskSpec {
            path: "vdc.img".to_string(),
            expected_sha256_hex: "0".repeat(64),
        };
        let plan = ctl_disk_attach_order(&sys, &sc, &wl);
        let roles = [DiskRole::System, DiskRole::Scratch, DiskRole::Workload];
        for (role, d) in roles.iter().zip(plan.iter()) {
            // role.name() is "system(vda)" / "scratch(vdb)" / "workload(vdc)"
            let dev = d.name.strip_prefix("dsmack-").unwrap();
            assert!(
                role.name().starts_with(dev),
                "attach slot {} does not match backend role {}",
                d.name,
                role.name()
            );
        }
        assert_eq!([plan[0].path.as_str(), plan[1].path.as_str(), plan[2].path.as_str()],
                   ["vda.img", "vdb.img", "vdc.img"]);
        assert_eq!(
            [plan[0].read_only, plan[1].read_only, plan[2].read_only],
            [true, false, true]
        );
    }
}
