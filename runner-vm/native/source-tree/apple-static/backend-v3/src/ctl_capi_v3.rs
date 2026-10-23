//! Control-profile C ABI, version 3 (include/dsmack_ctl_join_v3.h).
//!
//! v3 is an EXPLICITLY versioned successor to v2 (backend-v2/src/ctl_capi.rs):
//! new struct layouts, new entrypoints (`*_v3`), and `dsmack_ctl_join_abi_version`
//! returns 3. v2 memory is NEVER reinterpreted as v3 — a v2 caller linking this
//! library gets a version mismatch at init, not a silent struct re-read.
//!
//! What v3 adds over v2:
//!   - the device set grows from the vda/vdb/vdc triple to the five-device set
//!     vda/vdb/vdc/vdd/vde (disks_v3): vdb/vdd are fresh RW copies of admitted
//!     blank templates; vdd is finalized + hashed through its retained inode;
//!     vde is an OPTIONAL genuinely UNMEASURED private input;
//!   - a single BOUNDED, ALLOWLISTED generic virtio-net option over a
//!     caller-handed connected SOCK_STREAM fd (net.rs);
//!   - a run-result accessor returning the envelope-shaped result/console/
//!     runtime_input/lifecycle digests (receipt_v3::RunResultV3).
//!
//! VALIDATION ORDERING (the astra-gate timing finding): on the real HVF
//! backend the returning `VmmBuilder::build()` STARTS the vCPUs. Therefore
//! EVERY mandatory validation below — spec parse, owned-buffer boot verify,
//! disk verify/create, template verify, vde bounds, net fd validation, control
//! fd type — runs in `dsmack_ctl_join_vm_new_v3` BEFORE `consumption.build()`
//! is called, i.e. before any guest instruction executes. No post-constructor
//! check is relied upon to gate guest execution.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::consumption_v3::{self, GuestVmV3};
use crate::disks_v3::{self, AdmittedTemplate, AttachedDiskV3, DiskRole};
use crate::net::{self, NetTransport};
use crate::owned_verified::VerifiedBootImages;
use crate::receipt_v3::LaunchReceiptV3;
use crate::spec_v3;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

fn cancellation_registry() -> &'static Mutex<std::collections::HashMap<i64, Arc<AtomicBool>>> {
    static REGISTRY: OnceLock<Mutex<std::collections::HashMap<i64, Arc<AtomicBool>>>> =
        OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

/// May run concurrently with run/finalize. Does not dereference the VM handle.
#[unsafe(no_mangle)]
pub extern "C" fn dsmack_ctl_join_cancel_v3(handle: i64) -> i32 {
    let registry = cancellation_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    match registry.get(&handle) {
        Some(token) => {
            token.store(true, Ordering::Release);
            0
        }
        None => -1,
    }
}

pub const ERR_CAP_MIN: usize = 512;
pub const ABI_VERSION: i32 = 3;

/// `dsmack_ctl_launch_spec_v3` — MUST match include/dsmack_ctl_join_v3.h.
#[repr(C)]
pub struct DsmackCtlLaunchSpecV3 {
    pub spec_sha256: *const std::ffi::c_char,
    pub kernel_sha256: *const std::ffi::c_char,
    pub initrd_sha256: *const std::ffi::c_char, // NULL = no initrd
    pub cmdline: *const std::ffi::c_char,
    pub cmdline_sha256: *const std::ffi::c_char,
    pub system_sha256: *const std::ffi::c_char,
    pub verity_root_hash: *const std::ffi::c_char,
    pub workload_sha256: *const std::ffi::c_char,
    pub scratch_template_sha256: *const std::ffi::c_char,
    pub scratch_template_bytes: u64,
    pub result_template_sha256: *const std::ffi::c_char,
    pub result_template_bytes: u64,
    pub ram_mib: u32,
    pub vcpus: u32,
}

/// `dsmack_ctl_disk_set_v3` — MUST match include/dsmack_ctl_join_v3.h.
#[repr(C)]
pub struct DsmackCtlDiskSetV3 {
    pub system_path: *const std::ffi::c_char,           // vda ro
    pub scratch_template_path: *const std::ffi::c_char, // vdb base
    pub scratch_path: *const std::ffi::c_char,          // vdb fresh dest
    pub workload_path: *const std::ffi::c_char,         // vdc ro
    pub result_template_path: *const std::ffi::c_char,  // vdd base
    pub result_path: *const std::ffi::c_char,           // vdd fresh dest
    pub private_path: *const std::ffi::c_char,          // vde, NULL = none
}

pub(crate) fn err_set(err: *mut u8, err_cap: usize, msg: &str) {
    if err.is_null() || err_cap < ERR_CAP_MIN {
        return;
    }
    let bytes = msg.as_bytes();
    let n = bytes.len().min(err_cap - 1);
    // SAFETY: err writable for err_cap bytes (caller contract, checked above).
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), err, n);
        *err.add(n) = 0;
    }
}

fn cstr(p: *const std::ffi::c_char, what: &str) -> Result<String, String> {
    if p.is_null() {
        return Err(format!("{what}: null"));
    }
    // SAFETY: caller passes a valid NUL-terminated string for the whole call.
    unsafe { std::ffi::CStr::from_ptr(p) }
        .to_str()
        .map(str::to_string)
        .map_err(|_| format!("{what}: not UTF-8"))
}

/// A built control-profile VM and its evidence surfaces. The scratch/result
/// dest paths are retained on the handle so the lifecycle owner can recover the
/// fresh vdb private residue and locate the retained vdd result image after
/// teardown (the orphan/residue recovery policy lives in the lifecycle layer,
/// not in this primitive).
pub struct CtlVmV3 {
    pub(crate) vm: Box<dyn GuestVmV3>,
    pub(crate) receipt_json: String,
    pub(crate) result_json: Option<String>,
    cancellation: Arc<AtomicBool>,
    outputs: Vec<disks_v3::OutputHandle>,
    pub scratch_path: String,
    pub result_path: String,
}

impl CtlVmV3 {
    pub fn scratch_path(&self) -> &str {
        &self.scratch_path
    }
    pub fn result_path(&self) -> &str {
        &self.result_path
    }
}

/// Build the v3 control-profile VM. Returns an opaque handle > 0, or 0 on
/// refusal (err set). EVERY refusal happens BEFORE `consumption.build()` (i.e.
/// before any guest executes on HVF) and closes `control_fd` and `net_fd`
/// exactly once when they were valid descriptors.
///
/// # Safety
/// - `kernel`/`kernel_len`: readable non-null non-empty buffer for the call;
///   `initrd`/`initrd_len`: both null/zero or a readable non-null non-empty
///   buffer, matching the spec's initrd pin presence.
/// - `spec`, `disks`: fully initialized structs; char* null only where
///   documented (initrd_sha256, private_path) else valid NUL-terminated UTF-8.
/// - `console_path`: valid NUL-terminated UTF-8 path.
/// - `control_fd`: open socket/pipe; ownership moves in UNCONDITIONALLY.
/// - `net_fd`: -1 for no NIC, else an open connected SOCK_STREAM whose
///   ownership moves in UNCONDITIONALLY.
/// - `err`: null, or writable for `err_cap >= dsmack_ctl_join_err_cap_min_v3()`.
#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dsmack_ctl_join_vm_new_v3(
    kernel: *const u8,
    kernel_len: usize,
    initrd: *const u8,
    initrd_len: usize,
    spec: *const DsmackCtlLaunchSpecV3,
    disks: *const DsmackCtlDiskSetV3,
    console_path: *const std::ffi::c_char,
    control_fd: i32,
    net_fd: i32,
    err: *mut u8,
    err_cap: usize,
) -> i64 {
    unsafe {
        dsmack_ctl_join_vm_new_with_policy_v1(
            kernel,
            kernel_len,
            initrd,
            initrd_len,
            spec,
            disks,
            console_path,
            control_fd,
            net_fd,
            0,
            err,
            err_cap,
        )
    }
}

/// Additive prelaunch policy: 0 retains residue; every other value refuses.
/// # Safety
/// Same pointer and unconditional descriptor-transfer contract as vm_new_v3.
#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dsmack_ctl_join_vm_new_with_policy_v1(
    kernel: *const u8,
    kernel_len: usize,
    initrd: *const u8,
    initrd_len: usize,
    spec: *const DsmackCtlLaunchSpecV3,
    disks: *const DsmackCtlDiskSetV3,
    console_path: *const std::ffi::c_char,
    control_fd: i32,
    net_fd: i32,
    residue_policy: u32,
    err: *mut u8,
    err_cap: usize,
) -> i64 {
    let fail = |m: String, err: *mut u8, cap: usize| -> i64 {
        err_set(err, cap, &m);
        0
    };

    // F10: reject an ALIASED control/net pair BEFORE owning either. If the C
    // caller handed the same raw fd as both, constructing two OwnedFd values
    // would close it twice. Own it exactly once here to close it once, refuse.
    if let Err(e) = crate::framing::reject_aliased(control_fd, net_fd) {
        if control_fd >= 0 {
            // SAFETY: caller handed this fd over; own once so it closes once.
            let _once = unsafe { OwnedFd::from_raw_fd(control_fd) };
        }
        return fail(format!("{e}"), err, err_cap);
    }

    // Own BOTH descriptors FIRST so every refusal below closes them exactly
    // once (control via drop of `control`; net via drop of `net_owned`).
    let control = if control_fd >= 0 {
        // SAFETY: caller handed us control_fd unconditionally.
        Some(unsafe { OwnedFd::from_raw_fd(control_fd) })
    } else {
        None
    };
    // SAFETY: caller handed us net_fd unconditionally (or -1 = none).
    let net_owned = unsafe { net::own_raw(net_fd) };

    if residue_policy != 0 {
        return fail("residue policy refused before launch: only retain-residue (0) supported; residue-free unavailable".into(), err, err_cap);
    }

    let Some(control) = control else {
        // net_owned drops here (closed once) if it was present.
        return fail(format!("control fd {control_fd} invalid"), err, err_cap);
    };

    // F10: the header claims control_fd is a socket/pipe transport; enforce it.
    // A regular file / device masquerading as the control channel is refused
    // (control + net_owned both drop here, each closed exactly once).
    if let Err(e) = crate::framing::validate_control_transport(control.as_raw_fd()) {
        return fail(format!("{e}"), err, err_cap);
    }

    if kernel.is_null() {
        return fail("null kernel buffer".into(), err, err_cap);
    }
    if kernel_len == 0 {
        return fail("empty kernel buffer".into(), err, err_cap);
    }
    if spec.is_null() {
        return fail("null launch_spec".into(), err, err_cap);
    }
    if disks.is_null() {
        return fail("null disk set".into(), err, err_cap);
    }
    // SAFETY: caller contract — fully initialized structs, valid strings.
    let (spec_raw, disks_raw) = unsafe { (&*spec, &*disks) };
    let spec = match unsafe { spec_v3::launch_spec_from_raw(spec_raw) } {
        Ok(s) => s,
        Err(e) => return fail(format!("launch_spec: {e}"), err, err_cap),
    };

    // initrd presence must equal pin presence (A6 discipline).
    let initrd_slice: Option<&[u8]> = if initrd.is_null() {
        if initrd_len != 0 {
            return fail("initrd_len set with null initrd".into(), err, err_cap);
        }
        None
    } else {
        if initrd_len == 0 {
            return fail("empty initrd buffer".into(), err, err_cap);
        }
        // SAFETY: validated non-null non-empty; readable for the call.
        Some(unsafe { std::slice::from_raw_parts(initrd, initrd_len) })
    };
    if initrd_slice.is_some() != spec.initrd_sha256.is_some() {
        return fail(
            "initrd presence does not match initrd pin presence".into(),
            err,
            err_cap,
        );
    }

    // Read + bound every path BEFORE touching the filesystem.
    macro_rules! path {
        ($p:expr, $what:expr) => {
            match cstr($p, $what) {
                Ok(p) => p,
                Err(m) => return fail(m, err, err_cap),
            }
        };
    }
    let system_path = path!(disks_raw.system_path, "disks.system_path");
    let scratch_template_path = path!(
        disks_raw.scratch_template_path,
        "disks.scratch_template_path"
    );
    let scratch_path = path!(disks_raw.scratch_path, "disks.scratch_path");
    let workload_path = path!(disks_raw.workload_path, "disks.workload_path");
    let result_template_path = path!(disks_raw.result_template_path, "disks.result_template_path");
    let result_path = path!(disks_raw.result_path, "disks.result_path");
    for (p, what) in [
        (&scratch_path, "scratch_path"),
        (&result_path, "result_path"),
    ] {
        if p.len() > spec_v3::DISK_PATH_MAX_BYTES {
            return fail(
                format!(
                    "disks.{what} {} bytes exceeds the {}-byte evidence bound",
                    p.len(),
                    spec_v3::DISK_PATH_MAX_BYTES
                ),
                err,
                err_cap,
            );
        }
    }
    let private_path: Option<String> = if disks_raw.private_path.is_null() {
        None
    } else {
        Some(path!(disks_raw.private_path, "disks.private_path"))
    };

    // Namespace entries survive every refusal; owned descriptors close normally.
    // Report retained residue rather than claim race-prone garbage collection.
    let console = path!(console_path, "console_path");
    let mut pending: Vec<disks_v3::OutputHandle> = Vec::with_capacity(3);
    macro_rules! fail_pending {
        ($message:expr, $err:expr, $cap:expr $(,)?) => {{
            let message = $message;
            let residues: Vec<_> = pending.iter().map(|h| h.deferred_residue().name).collect();
            fail(format!("host cleanup deferred; residue-free policy unavailable; {message}; retained={residues:?}"), $err, $cap)
        }};
    }
    let log = match disks_v3::create_console_output(&console) {
        Ok((f, handle)) => {
            pending.push(handle);
            f
        }
        Err(e) => return fail_pending!(format!("console log {console}: {e}"), err, err_cap),
    };

    // R1: owned-buffer verified boot (the ONLY pin source is the admitted spec).
    // SAFETY: kernel validated non-null non-empty.
    let k = unsafe { std::slice::from_raw_parts(kernel, kernel_len) };
    let images = match VerifiedBootImages::new(k, initrd_slice, &spec.cmdline, &spec.pins()) {
        Ok(v) => v,
        Err(e) => {
            return fail_pending!(format!("verified boot: {e}"), err, err_cap);
        }
    };

    // The five-device set. Attach order: vda, vdb, vdc, vdd, [vde].
    let mut attached: Vec<AttachedDiskV3> = Vec::with_capacity(5);

    match disks_v3::open_verified_ro(DiskRole::System, &system_path, &spec.system_sha256) {
        Ok(d) => attached.push(d),
        Err(e) => {
            return fail_pending!(format!("{e}"), err, err_cap);
        }
    }
    let scratch_template = AdmittedTemplate {
        path: scratch_template_path,
        template_sha256: spec.scratch_template_sha256.clone(),
        template_bytes: spec.scratch_template_bytes,
    };
    match disks_v3::create_fresh_from_template(DiskRole::Scratch, &scratch_path, &scratch_template)
    {
        Ok((d, handle)) => {
            // Retain output identity for refusal diagnostics.
            pending.push(handle);
            attached.push(d);
        }
        Err(e) => {
            return fail_pending!(format!("{e}"), err, err_cap);
        }
    }
    match disks_v3::open_verified_ro(DiskRole::Workload, &workload_path, &spec.workload_sha256) {
        Ok(d) => attached.push(d),
        Err(e) => {
            return fail_pending!(format!("{e}"), err, err_cap);
        }
    }
    let result_template = AdmittedTemplate {
        path: result_template_path,
        template_sha256: spec.result_template_sha256.clone(),
        template_bytes: spec.result_template_bytes,
    };
    match disks_v3::create_fresh_from_template(DiskRole::Result, &result_path, &result_template) {
        Ok((d, handle)) => {
            pending.push(handle);
            attached.push(d);
        }
        // A FreshPreExisting refusal never published over the pre-existing
        // object (no-replace publish); the attempt's own staging inode was
        Err(e) => {
            return fail_pending!(format!("{e}"), err, err_cap);
        }
    }
    if let Some(p) = &private_path {
        match disks_v3::open_private_unmeasured(p) {
            Ok(d) => attached.push(d),
            Err(e) => {
                return fail_pending!(format!("{e}"), err, err_cap);
            }
        }
    }

    // Optional generic NIC: validate + own the fd (allowlisted transport only).
    let net: Option<NetTransport> = match net_owned {
        None => None,
        Some(fd) => match NetTransport::own_validated(fd) {
            Ok(t) => Some(t),
            Err((e, fd)) => {
                drop(fd); // closed exactly once
                return fail_pending!(format!("net: {e}"), err, err_cap);
            }
        },
    };
    let net_present = net.is_some();

    // F01: fail CLOSED if no native consumption factory was installed. This
    // runs BEFORE `control`/`net` move into build(), so on refusal both owned
    // descriptors drop (closed exactly once) at function exit and the fresh
    // in via install_mock_for_test; a production archive that never called
    // dsmack_ctl_v3_init is refused here instead of silently running the mock.
    let consumption = match consumption_v3::default_consumption() {
        Ok(c) => c,
        Err(e) => {
            return fail_pending!(format!("consumption: {e}"), err, err_cap);
        }
    };
    let receipt = LaunchReceiptV3::record(&spec, &attached, net_present, consumption.label());
    let receipt_json = receipt.to_json();

    // consumption.build() is where the real HVF backend starts the vCPUs. All
    // validation above is complete; `control` and `net` move in (closed once on
    // its refusal, alive in the handle on success).
    let vm = match consumption.build(images, attached, control, net, log, receipt) {
        Ok(vm) => vm,
        Err(e) => {
            return fail_pending!(format!("consumption: {e}"), err, err_cap);
        }
    };

    let cancellation = vm
        .cancellation_token()
        .unwrap_or_else(|| Arc::new(AtomicBool::new(false)));
    let handle = Box::into_raw(Box::new(CtlVmV3 {
        cancellation: cancellation.clone(),
        vm,
        receipt_json,
        result_json: None,
        outputs: pending,
        scratch_path,
        result_path,
    })) as i64;
    cancellation_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(handle, cancellation);
    handle
}

/// Real-guest run. On the mock returns -1 with the honest platform refusal
/// (no guest executed); on HVF this runs the returning lifecycle. Does NOT free
/// the handle (teardown is `dsmack_ctl_join_free_v3`).
///
/// # Safety
/// `handle` must be a live value from `dsmack_ctl_join_vm_new_v3`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dsmack_ctl_join_run_v3(handle: i64, err: *mut u8, err_cap: usize) -> i32 {
    if handle == 0 {
        err_set(err, err_cap, "run: zero handle");
        return -1;
    }
    // SAFETY: live CtlVmV3 pointer; borrowed, not consumed.
    let vm = unsafe { &mut *(handle as *mut CtlVmV3) };
    match vm.vm.run() {
        Ok(code) => code,
        Err(e) => {
            err_set(err, err_cap, &format!("run: {e}"));
            -1
        }
    }
}

/// Checked finalization of vdd + console (R06). Stores the run-result JSON in
/// the handle. 0 on success; -1 on refusal (err set) — a finalize refusal means
/// NO result is produced (flush/sync/identity/short-read all fail closed).
///
/// # Safety
/// `handle` must be a live value from `dsmack_ctl_join_vm_new_v3`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dsmack_ctl_join_finalize_v3(
    handle: i64,
    err: *mut u8,
    err_cap: usize,
) -> i32 {
    if handle == 0 {
        err_set(err, err_cap, "finalize: zero handle");
        return -1;
    }
    // SAFETY: live CtlVmV3 pointer; borrowed.
    let vm = unsafe { &mut *(handle as *mut CtlVmV3) };
    // F08: the finalize deadline is an ABSOLUTE instant that both (a) bounds the
    // call via the independent watchdog inside `finalize` (safe ownership on
    // timeout) and (b) drives cancellation — the cancel source is the deadline
    // itself, not the previous unconditional `never_cancel`. A finalize that
    // reaches the deadline is cancelled/failed closed, never silently unbounded.
    let deadline_instant = std::time::Instant::now()
        + std::time::Duration::from_secs(crate::finalize::FINALIZE_DEADLINE_SECONDS);
    let deadline = Some(deadline_instant);
    let cancellation = vm.cancellation.clone();
    let mut cancel_at_deadline = move || {
        cancellation.load(Ordering::Acquire) || std::time::Instant::now() >= deadline_instant
    };
    match vm.vm.finalize(&mut cancel_at_deadline, deadline) {
        Ok(r) => {
            vm.result_json = Some(r.to_json());
            0
        }
        Err(e) => {
            // F07: a finalize refusal (not halted, latched fault, failed flush/
            // sync/identity/short-read, or a repeated single-shot finalize)
            // INVALIDATES any previously produced result so no stale result_json
            // remains readable after a failure.
            vm.result_json = None;
            err_set(err, err_cap, &format!("finalize: {e}"));
            -1
        }
    }
}

unsafe fn copy_json(out: *mut u8, out_cap: usize, json: &str) -> i32 {
    if out.is_null() || out_cap == 0 {
        return -1;
    }
    let bytes = json.as_bytes();
    if bytes.len() + 1 > out_cap {
        return -1;
    }
    // SAFETY: out writable for out_cap bytes (caller contract).
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
        *out.add(bytes.len()) = 0;
    }
    0
}

/// Copy the launch receipt JSON (NUL-terminated). Never truncates: too-small
/// out_cap is a refusal. Handle not consumed.
///
/// # Safety
/// `handle` live; `out` writable for `out_cap` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dsmack_ctl_join_receipt_v3(
    handle: i64,
    out: *mut u8,
    out_cap: usize,
) -> i32 {
    if handle == 0 {
        return -1;
    }
    // SAFETY: live CtlVmV3 pointer; borrowed.
    let vm = unsafe { &*(handle as *const CtlVmV3) };
    unsafe { copy_json(out, out_cap, &vm.receipt_json) }
}

/// Copy the run-result JSON (NUL-terminated). -1 if finalize has not run yet or
/// out_cap too small. Handle not consumed.
///
/// # Safety
/// `handle` live; `out` writable for `out_cap` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dsmack_ctl_join_result_v3(
    handle: i64,
    out: *mut u8,
    out_cap: usize,
) -> i32 {
    if handle == 0 {
        return -1;
    }
    // SAFETY: live CtlVmV3 pointer; borrowed.
    let vm = unsafe { &*(handle as *const CtlVmV3) };
    match &vm.result_json {
        Some(j) => unsafe { copy_json(out, out_cap, j) },
        None => -1,
    }
}

/// Copy unsigned deferred-residue diagnostics. Does not imply quiescence or
/// successful execution. Query before free; no truncation and no filesystem IO.
/// # Safety
/// Live, exclusively borrowed handle; out writable for out_cap bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dsmack_ctl_join_residue_status_v1(
    handle: i64,
    out: *mut u8,
    out_cap: usize,
) -> i32 {
    if handle == 0 {
        return -1;
    }
    let vm = unsafe { &*(handle as *const CtlVmV3) };
    let mut status =
        String::from("host cleanup deferred; policy=retain-residue; quiescence=not-asserted\n");
    for output in &vm.outputs {
        status.push_str(&format!("{:?}\n", output.deferred_residue()));
    }
    unsafe { copy_json(out, out_cap, &status) }
}

/// Teardown: free the handle and close every owned descriptor (control, net,
/// console, vdd + retained dups) exactly once.
///
/// # Safety
/// `handle` must be a live value from `dsmack_ctl_join_vm_new_v3`, freed once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dsmack_ctl_join_free_v3(handle: i64) {
    if handle == 0 {
        return;
    }
    cancellation_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&handle);
    // SAFETY: handle came from vm_new_v3 and is freed exactly once.
    drop(unsafe { Box::from_raw(handle as *mut CtlVmV3) });
}

/// F06 — VERSIONED v3 ABI probe. v2 (backend-v2) exports the UNVERSIONED
/// `dsmack_ctl_join_abi_version`; when both crates are archived together those
/// identical `#[no_mangle]` names would be duplicate definitions. v3 therefore
/// exports a distinct `_v3`-suffixed symbol, so the combined archive carries
/// both probes without collision and a v3 consumer links the v3 probe
/// unambiguously. (The `ABI_VERSION` value is still 3.)
#[unsafe(no_mangle)]
pub extern "C" fn dsmack_ctl_join_abi_version_v3() -> i32 {
    ABI_VERSION
}

#[unsafe(no_mangle)]
pub extern "C" fn dsmack_ctl_join_err_cap_min_v3() -> usize {
    ERR_CAP_MIN
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;

    #[test]
    fn cancellation_uses_registry_without_dereferencing_running_vm() {
        let handle = -784421;
        assert_eq!(dsmack_ctl_join_cancel_v3(handle), -1);
        let token = Arc::new(AtomicBool::new(false));
        cancellation_registry()
            .lock()
            .unwrap()
            .insert(handle, token.clone());
        let caller = std::thread::spawn(move || dsmack_ctl_join_cancel_v3(handle));
        assert_eq!(caller.join().unwrap(), 0);
        assert!(token.load(Ordering::Acquire));
        cancellation_registry().lock().unwrap().remove(&handle);
        assert_eq!(dsmack_ctl_join_cancel_v3(handle), -1);
    }
}
