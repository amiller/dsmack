//! Public RAW-kernel/marker-initrd fixture for the opt-in returning lifecycle: two complete
//! verified-payload VMs in one process, plus returning-profile rejection before VM construction.
//! code 0 means guest halt (PSCI SYSTEM_OFF/RESET), not workload success. No admission claim.
use devices::virtio::console::port_io::output_to_raw_fd_dup;
use krun::api::{
    ConsoleDevice, KernelFormat, MmioDeviceManager, Payload, VerifiedBootPins, VmmBuilder,
};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::time::Duration;

const CMDLINE: &str = "console=hvc0 rdinit=/init panic=-1";
const CMDLINE_SHA256: &str = "d13f063c25d4547f364646981048a517d813f45fe50a8f429c21cd6123412e6b";
/// assemble lane: the approved 6.12.113-0-virt kernel Image (unchanged pinned
/// bytes from the qualified closure; guest/CLOSURE.json kernel.sha256).
const KERNEL_SHA256: &str = "842b62e8b8bdfc07ec67a3a4d472620c86ad9897020d2ab4c069cac25c38e34e";
/// assemble lane: the pivot initrd (dm-verity bootstrap, dmsetup, bounded
/// busybox userland; virtio_console is built into the pinned kernel, so the
/// named dsmack-ctl port appears with virtio_mmio alone). REBUILT by repair2
/// (astra-gate repair2 R1) from the final reviewed bridge overlay: the init
/// bakes the REBUILT system disk's verity table/root (the repair2 disk fixes
/// the installed bridge_main.py MODE to 0755 — repair1's rebuild shipped it
/// 0644 and harness-init refuses to exec it). Built by
/// guest/tools/build_pivot_initrd.py; pins recorded in guest/CLOSURE.json.
const INITRD_SHA256: &str = "6975a86c3520bd8efae0777b25053b4329a5707e9b481307ba9c671ef5eb15c0";
const KERNEL_LIMIT: u64 = 64 << 20;
const INITRD_LIMIT: u64 = 8 << 20;
const READY: &[u8] = b"DSMACK_DIRECT_BOOT_READY";

/// signed-app-join: single source of truth for the compiled-in boot pins, shared with the
/// C ABI in capi.rs. Constants stay compiled in and caller-unmodifiable — identical to
/// the reviewed probe wrapper; only the accessor is new.
pub(crate) mod verified_bytes {
    use super::{CMDLINE_SHA256, INITRD_SHA256, KERNEL_SHA256};
    use krun::api::VerifiedBootPins;
    pub const CMDLINE: &str = super::CMDLINE;
    /// SHA-256 of the pinned authenticated system disk (full content, ext4 +
    /// verity tree): the bridge-containing closure — Alpine base + pinned
    /// Claude image + /sbin/harness-init + /opt/dsmack-bridge/* (guest-root
    /// control bridge) under one dm-verity root. REBUILT by repair2
    /// (astra-gate repair2 R1) so the installed bridge equals the TESTED
    /// source AND the installed MODES equal the pinned contract (bridge_main.py
    /// 0755 — bytes unchanged from repair1, verified by extract+stat against
    /// the image). Built by guest/tools/build_system_disk.py; verified by
    /// the control profile before any VM construction.
    pub const DISK_SHA256: &str = "8a26976e7bb9a28fd0c1d325829e37edbeb8017303ab9aa7d1f4bb8a011575f2";
    pub fn pins() -> VerifiedBootPins<'static> {
        VerifiedBootPins {
            kernel_sha256: KERNEL_SHA256,
            initrd_sha256: Some(INITRD_SHA256),
            cmdline_sha256: CMDLINE_SHA256,
        }
    }
}

pub mod capi;
// v2 control profile: the C ABI symbols (dsmack_ctl_join_* v2) live in the
// backend-v2 crate and are exported from this staticlib through it. This
// module provides the krun HVF Consumption and installs it as the platform
// factory (aarch64 macOS); the v1 ctl_capi.rs (compiled-in pins, single
// disk) is REPLACED — the legacy dsmack_join/1 returning ABI (capi.rs) is
// untouched.
pub mod hvf_consumption;

// dsmack v3 GENERIC native backend (F01): the HVF ConsumptionV3 adapter +
// `dsmack_ctl_v3_init`. Referencing the dsmack-backend-v3 crate here is what
// pulls its `#[no_mangle]` v3 C-ABI exports (dsmack_ctl_join_*_v3) into the
// archive — previously backend-v3 was an unreferenced dependency, so the
// linker dropped every v3 symbol and ConsumptionV3 defaulted to the mock.
pub mod hvf_consumption_v3;

fn read_bounded(path: &str, limit: u64) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    File::open(path)
        .and_then(|f| f.take(limit + 1).read_to_end(&mut buf))
        .map_err(|e| format!("read {path}: {e}"))?;
    if buf.len() as u64 > limit {
        return Err(format!("{path} exceeds {limit} bytes"));
    }
    Ok(buf)
}

fn verified(kpath: &str, ipath: &str) -> Result<Payload, String> {
    let (k, i) = (
        read_bounded(kpath, KERNEL_LIMIT)?,
        read_bounded(ipath, INITRD_LIMIT)?,
    );
    let pins = VerifiedBootPins {
        kernel_sha256: KERNEL_SHA256,
        initrd_sha256: Some(INITRD_SHA256),
        cmdline_sha256: CMDLINE_SHA256,
    };
    Payload::load_external_raw_verified(&k, Some(&i), CMDLINE, &pins)
        .map_err(|e| format!("verified payload: {e:?}"))
}

fn new_log(path: &str) -> Result<File, String> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("console log {path}: {e}"))
}

fn base(payload: Payload) -> Result<VmmBuilder<'static>, String> {
    Ok(VmmBuilder::new()
        .vcpus(1)
        .map_err(|e| format!("vcpus: {e:?}"))?
        .ram_mib(512)
        .map_err(|e| format!("memory: {e:?}"))?
        .payload(payload))
}

fn counts() -> Result<(usize, i32), String> {
    // The fd/thread census uses macOS proc_pidinfo; its numbers only matter
    // where the returning lifecycle runs (aarch64 macOS). Other hosts compile
    // this crate for unit coverage (A6/A4 boundary tests) and report the
    // census as unavailable instead of failing compilation.
    #[cfg(target_os = "macos")]
    {
        let fds = std::fs::read_dir("/dev/fd")
            .map_err(|e| format!("/dev/fd: {e}"))?
            .count();
        let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_taskinfo>() as i32;
        let n = unsafe {
            libc::proc_pidinfo(
                libc::getpid(),
                libc::PROC_PIDTASKINFO,
                0,
                (&raw mut info).cast(),
                size,
            )
        };
        if n != size {
            return Err(format!("proc_pidinfo returned {n}"));
        }
        Ok((fds, info.pti_threadnum))
    }
    #[cfg(not(target_os = "macos"))]
    Err("fd/thread census requires macOS".into())
}

/// One complete returning run. The console hash is taken only after run_returning returned,
/// i.e. after the console port workers were joined and every device owner was dropped.
fn returning_run(run: u32, kpath: &str, ipath: &str, log: &str) -> Result<u8, String> {
    let vm = base(verified(kpath, ipath)?)?
        .returning_console(new_log(log)?)
        .build()
        .map_err(|e| format!("run {run} build: {e:?}"))?;
    println!("DSMACK_STAGE returning_built run={run}");
    // run_returning exists only for the aarch64-macOS returning profile; other
    // hosts compile this crate for unit coverage only and never execute a VM.
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    let code = vm.run_returning();
    #[cfg(not(all(target_arch = "aarch64", target_os = "macos")))]
    let code: u8 = {
        drop(vm);
        0
    };
    let mut bytes = Vec::new();
    File::open(log)
        .and_then(|mut f| f.read_to_end(&mut bytes))
        .map_err(|e| format!("read {log}: {e}"))?;
    let (fds, threads) = counts()?;
    let halt = if code == 0 {
        "guest-halt"
    } else {
        "vcpu-error"
    };
    let ready = bytes.windows(READY.len()).any(|w| w == READY);
    println!(
        "DSMACK_STAGE vmm_returned run={run} code={code} halt={halt} console_sha256={:x} \
              console_bytes={} guest_ready_marker={ready} fds={fds} threads={threads}",
        Sha256::digest(&bytes),
        bytes.len()
    );
    Ok(code)
}

fn twice(kpath: &str, ipath: &str, dir: &str) -> Result<i32, String> {
    let before = counts()?;
    println!(
        "DSMACK_STAGE counts_before fds={} threads={}",
        before.0, before.1
    );
    let c1 = returning_run(1, kpath, ipath, &format!("{dir}/console-1.log"))?;
    let after1 = counts()?;
    let c2 = returning_run(2, kpath, ipath, &format!("{dir}/console-2.log"))?;
    let after2 = counts()?;
    let stable = after1 == after2;
    println!(
        "DSMACK_STAGE two_runs_complete codes={c1},{c2} counts_stable={stable} \
              after1={after1:?} after2={after2:?}"
    );
    Ok(if stable && c1 == 0 && c2 == 0 { 0 } else { 4 })
}

/// Only the case's exact expected refusal counts as a pass: every before-VM-construction
/// rejection is a `VmmError::BootError`, including the verified-boot cmdline guard ("verified
/// boot: …") alongside the returning-profile guards, so any substring/variant-loose match
/// would misclassify a correct refusal by a different guard.
fn expect_reject(
    name: &str,
    expected: &str,
    r: Result<krun::api::Vmm<'static>, krun::VmmError>,
) -> Result<(), String> {
    match r {
        Err(krun::VmmError::BootError(msg)) if msg == expected => {
            println!("DSMACK_STAGE rejected_before_vm case={name} error=BootError({msg:?})");
            Ok(())
        }
        Err(e) => Err(format!("{name}: rejected for another reason: {e:?}")),
        Ok(_) => Err(format!("{name}: returning profile unexpectedly built a VM")),
    }
}

/// Each case must be refused before VM construction; the final valid run then proves that no
/// HVF VM was left behind (hv_vm_create is process-wide and would fail).
fn reject(kpath: &str, ipath: &str, dir: &str) -> Result<i32, String> {
    let log = |n: &str| new_log(&format!("{dir}/reject-{n}.log"));
    let dev_log = log("dev")?;
    let mut console = ConsoleDevice::builder();
    console.add_console_port(
        "",
        output_to_raw_fd_dup(dev_log.as_raw_fd()).map_err(|e| format!("dup: {e}"))?,
    );
    let mut dm = MmioDeviceManager::new();
    dm.add(console.build().map_err(|e| format!("console: {e:?}"))?);
    expect_reject(
        "two-vcpus",
        "returning profile: exactly one vCPU",
        base(verified(kpath, ipath)?)?
            .vcpus(2)
            .map_err(|e| format!("{e:?}"))?
            .returning_console(log("vcpus")?)
            .build(),
    )?;
    expect_reject(
        "caller-devices",
        "returning profile: devices, consoles or options outside the profile",
        base(verified(kpath, ipath)?)?
            .devices(dm)
            .returning_console(log("devices")?)
            .build(),
    )?;
    expect_reject(
        "kernel-console",
        "verified boot: approved cmdline would be modified",
        base(verified(kpath, ipath)?)?
            .set_kernel_console("hvc0")
            .returning_console(log("kcon")?)
            .build(),
    )?;
    expect_reject(
        "shutdown-support",
        "returning profile: devices, consoles or options outside the profile",
        base(verified(kpath, ipath)?)?
            .shutdown_support(true)
            .returning_console(log("shutdown")?)
            .build(),
    )?;
    expect_reject(
        "nested",
        "returning profile: devices, consoles or options outside the profile",
        base(verified(kpath, ipath)?)?
            .nested_virt(true)
            .returning_console(log("nested")?)
            .build(),
    )?;
    let null = OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .map_err(|e| format!("/dev/null: {e}"))?;
    expect_reject(
        "non-regular-console",
        "returning profile: console must be a regular file",
        base(verified(kpath, ipath)?)?
            .returning_console(null)
            .build(),
    )?;
    let control = Payload::load_external(kpath, KernelFormat::Raw, Some(ipath), CMDLINE)
        .map_err(|e| format!("control: {e:?}"))?;
    expect_reject(
        "path-payload",
        "returning profile: verified owned payload required",
        base(control)?.returning_console(log("path")?).build(),
    )?;
    let code = returning_run(1, kpath, ipath, &format!("{dir}/console-after-reject.log"))?;
    Ok(if code == 0 { 0 } else { 4 })
}

fn run() -> Result<i32, String> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 5 {
        return Err("usage: DirectHVFReturning twice|reject KERNEL INITRD NEW_EMPTY_DIR".into());
    }
    let (mode, kpath, ipath, dir) = (args[1].as_str(), &args[2], &args[3], &args[4]);
    println!(
        "DSMACK_FIXTURE returning mode={mode} kernel_sha256={KERNEL_SHA256} initrd_sha256={INITRD_SHA256} \
              cmdline_sha256={CMDLINE_SHA256} cmdline={CMDLINE:?}"
    );
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_secs(60));
        // Bounded fixture: a hung guest or teardown terminates the whole process.
        unsafe { libc::_exit(124) }
    });
    match mode {
        "twice" => twice(kpath, ipath, dir),
        "reject" => reject(kpath, ipath, dir),
        _ => Err(format!("unknown mode {mode}")),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn dsmack_probe_main() -> i32 {
    match std::panic::catch_unwind(run) {
        Ok(Ok(code)) => code,
        Ok(Err(e)) => {
            eprintln!("DSMACK_RETURNING_ERROR: {e}");
            2
        }
        Err(_) => {
            eprintln!("DSMACK_RETURNING_ERROR: Rust panic");
            3
        }
    }
}
