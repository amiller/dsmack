// Swift v2 binding for the general backend (dsmack_ctl_join_v2.h, ABI 2).
//
// mac-backend-implementation lane, 2026-10-21. Source-level integration
// material: like the v1 binding, this file is INERT until an independently
// reviewed v2 archive is linked; nothing here executes a VM on its own.
//
// What changed vs Backend.swift (v1): the app carries NO image identity
// anymore. The caller resolves the admitted launch_spec from the EXTERNAL
// admission policy + image manifest (the app-side admission core is the
// mac-integration lane's port of mac-general-prep launcher/*), and hands
// the verified bytes + spec + disk triple to the backend. The backend
// re-verifies every expectation against the bytes/devices it consumes and
// refuses before any VM exists (R1-R5).
//
// Preserved v1 disciplines: err buffer handling, control-fd ownership
// (the backend owns the descriptor on EVERY return), read-the-console-only-
// after-run, and the receipt surface (new in v2) read before run.

#if canImport(Darwin)
import CJoin
import Foundation

struct BackendV2Refused: Error, CustomStringConvertible {
    let description: String
    init(_ site: String, _ err: UnsafeMutablePointer<CChar>?) {
        let msg = err == nil ? "no detail" : String(cString: err!)
        description = "backend v2 refused at \(site): \(msg)"
    }
}

/// Initialize the linked archive's v2 consumption (krun HVF on aarch64
/// macOS). MUST be called once before the first `backendV2VmNew`; refuse to
/// proceed on false. Also the ABI-version check point.
func backendV2Init() throws {
    let v = dsmack_ctl_join_abi_version()
    guard v == 2 else {
        throw Fail("backend control ABI version \(v) != expected 2")
    }
    guard dsmack_ctl_v2_init() == 0 else {
        throw Fail("backend v2 consumption factory already installed or refused")
    }
}

/// Build the general control-profile VM from verified bytes + admitted
/// spec + disk triple. Returns an opaque handle > 0. Ownership of
/// `controlFd` moves into the archive on EVERY return (v1 R4 unchanged).
///
/// - `kernel`/`initrd`: caller-held verified bytes (read exactly once by
///   the backend, hashed against the spec pins there — R1).
/// - `spec`: the admitted launch spec resolved from the external policy +
///   image manifest (the app enforced admission BEFORE this call; parsing
///   never authorizes).
/// - `systemPath`/`scratchPath`/`workloadPath`: the vda/vdb/vdc triple.
///   scratchPath must NOT exist yet (the backend creates it fresh).
/// - `consoleLogPath`: O_EXCL diagnostics console (unchanged v1 discipline).
func backendV2VmNew(kernel: Data, initrd: Data?,
                    specSha256: String, kernelSha256: String, initrdSha256: String?,
                    cmdline: String, cmdlineSha256: String,
                    systemSha256: String, verityRootHash: String, workloadSha256: String,
                    ramMib: UInt32, vcpus: UInt32,
                    systemPath: String, scratchPath: String, workloadPath: String,
                    consoleLogPath: String, controlFd: Int32) throws -> Int64 {
    let errCap = dsmack_ctl_join_err_cap_min()
    let err = UnsafeMutablePointer<CChar>.allocate(capacity: errCap)
    defer { err.deallocate() }
    memset(err, 0, errCap)

    // Stable C-string storage for the WHOLE call (runtime lifetime repair,
    // mac-runtime-seam-repair lane). The prior compiled source assigned
    // `cX.withUnsafeBufferPointer { $0.baseAddress }` into the C struct
    // fields: that pointer is only valid INSIDE the closure, so every field
    // escaped a borrowed pointer whose storage the array no longer guarantees
    // once the closure returns (the "returning borrowed pointer / returning
    // borrowed struct" bug flagged by mac-compile-followthrough §6; C04 fixed
    // only the const-ness so it would compile, never the lifetime). We instead
    // own null-terminated HEAP copies that live until this function returns
    // (defer-freed), so every `const char *` the backend reads for the full
    // duration of dsmack_ctl_join_vm_new points at valid, immovable bytes.
    var owned: [UnsafeMutablePointer<CChar>] = []
    defer { for p in owned { p.deallocate() } }
    func cdup(_ s: String) -> UnsafePointer<CChar> {
        let bytes = Array(s.utf8CString)          // includes the trailing NUL
        let p = UnsafeMutablePointer<CChar>.allocate(capacity: bytes.count)
        bytes.withUnsafeBufferPointer { p.initialize(from: $0.baseAddress!, count: $0.count) }
        owned.append(p)
        return UnsafePointer(p)
    }
    func cdupMaybe(_ s: String?) -> UnsafePointer<CChar>? { s.map(cdup) }

    var spec = dsmack_ctl_launch_spec()
    spec.spec_sha256 = cdup(specSha256)
    spec.kernel_sha256 = cdup(kernelSha256)
    spec.initrd_sha256 = cdupMaybe(initrdSha256)
    spec.cmdline = cdup(cmdline)
    spec.cmdline_sha256 = cdup(cmdlineSha256)
    spec.system_sha256 = cdup(systemSha256)
    spec.verity_root_hash = cdup(verityRootHash)
    spec.workload_sha256 = cdup(workloadSha256)
    spec.ram_mib = ramMib
    spec.vcpus = vcpus
    var disks = dsmack_ctl_disk_set()
    disks.system_path = cdup(systemPath)
    disks.scratch_path = cdup(scratchPath)
    disks.workload_path = cdup(workloadPath)
    let cConsole = cdup(consoleLogPath)

    // initrd presence must match the initrd pin presence; the backend re-checks
    // this itself (refusal there is authoritative). Checked BEFORE the native
    // call, on the `initrd` Data VALUE (an empty Data is present-but-empty, not
    // nil) — not from a buffer base address.
    if (initrd == nil) != (initrdSha256 == nil) {
        throw Fail("initrd bytes/pin presence mismatch (caller-side)")
    }
    // E01 byte-buffer lifetime repair (matches BackendV3.swift / SWIFT01). The
    // prior source returned the initrd `baseAddress` OUT of its withUnsafeBytes
    // closure and passed it to the backend AFTER that closure had ended — a
    // dangling pointer. Nest both closures so the native call runs while BOTH
    // the kernel and initrd buffers are pinned; neither base pointer escapes.
    func callNative(_ kp: UnsafePointer<UInt8>?, _ klen: Int,
                    _ ip: UnsafePointer<UInt8>?, _ ilen: Int) throws -> Int64 {
        let h = dsmack_ctl_join_vm_new(
            kp, klen,
            ip, ilen,
            &spec, &disks,
            cConsole,
            controlFd, err, errCap)
        guard h != 0 else { throw BackendV2Refused("v2_build", err) }
        return h
    }
    let handle: Int64 = try kernel.withUnsafeBytes { (kb: UnsafeRawBufferPointer) -> Int64 in
        let kp = kb.bindMemory(to: UInt8.self).baseAddress
        if let initrd = initrd {
            return try initrd.withUnsafeBytes { (ib: UnsafeRawBufferPointer) -> Int64 in
                try callNative(kp, kb.count, ib.bindMemory(to: UInt8.self).baseAddress, ib.count)
            }
        } else {
            return try callNative(kp, kb.count, nil, 0)
        }
    }
    return handle
}

/// Copy the handle's launch receipt JSON (R5). The handle is NOT consumed;
/// call before `backendV2Run` (the handle is consumed by run).
func backendV2Receipt(handle: Int64) throws -> String {
    let cap = dsmack_ctl_join_receipt_cap_min()
    let out = UnsafeMutablePointer<CChar>.allocate(capacity: cap)
    defer { out.deallocate() }
    memset(out, 0, cap)
    guard dsmack_ctl_join_receipt(handle, out, cap) == 0 else {
        throw BackendV2Refused("receipt", nil)
    }
    return String(cString: out)
}

/// Run the whole lifecycle to completion (checked teardown). CONSUMES the
/// handle. Code 0 = guest halt (PSCI), never workload success. The console
/// log must be read only AFTER this returns.
func backendV2Run(handle: Int64) throws -> Int32 {
    let errCap = dsmack_ctl_join_err_cap_min()
    let err = UnsafeMutablePointer<CChar>.allocate(capacity: errCap)
    defer { err.deallocate() }
    memset(err, 0, errCap)
    let code = dsmack_ctl_join_run(handle, err, errCap)
    if code < 0 { throw BackendV2Refused("v2_run", err) }
    return code
}
#endif
