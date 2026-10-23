// Swift v3 binding for the general backend (dsmack_ctl_join_v3.h, ABI 3).
//
// loop40-swift-repair1 lane, 2026-10-22 (repair of speculative-native-swift-join).
// INTEGRATED app-join glue: compiled into the general `mar` executable target.
// It is still INERT on a host/mock build — it requires Darwin + the CJoin system
// library + an independently reviewed v3 apple-static archive linked in, plus the
// Hypervisor/DeviceCheck frameworks. Nothing here executes a VM, signs, or touches
// AppAttest. It is staged for the later Mac (Zed cross-build or Mini) compile AFTER
// an independent exact-source review.
//
// Relationship to BackendV2.swift:
//   * The E01 heap-pointer discipline (native-canonical-probe-repair1 /
//     mac-runtime-seam-repair) is PRESERVED VERBATIM here: every `const char *`
//     field handed to the backend points at an owned, null-terminated HEAP copy
//     that lives (defer-freed) for the WHOLE duration of the vm_new_v3 call, so
//     no borrowed pointer escapes its closure. Do NOT regress this to the
//     `cX.withUnsafeBufferPointer { $0.baseAddress }` form.
//   * The kernel/initrd BYTE-BUFFER lifetime is now also correct: the native
//     call runs INSIDE both `withUnsafeBytes` closures so neither base pointer
//     escapes its closure (SWIFT01 repair — see backendV3VmNew).
//   * controlFd/netFd ownership moves into the archive on EVERY native return;
//     a caller-side refusal BEFORE the native call closes them here, exactly
//     once, in a defer (SWIFT02 repair — see backendV3VmNew).
//   * v3 adds the RETURNING lifecycle split: run_v3 (proven halt) THEN a
//     SEPARATE checked finalize_v3 (R06) THEN result_v3. v2 fused these.
//   * v3 adds the five-role disk set (vda/vdb/vdc/vdd + optional vde) with
//     ADMITTED blank-template copies for the two fresh RW disks (vdb/vdd), and
//     an OPTIONAL bounded virtio-net descriptor (net_fd == -1 => no NIC).
//   * v3 uses the VERSIONED probe symbols (F06): dsmack_ctl_join_abi_version_v3
//     / dsmack_ctl_join_err_cap_min_v3, so a single archive can carry both the
//     frozen v2 and the v3 backend objects without a duplicate symbol. This is
//     the cross-lane-verified direction (CROSS-LANE-VERIFIED-FINDINGS abi_state:
//     "Version ABI probe symbols_v3/header/Swift calls ...; no duplicateexports").
//     SWIFT03 repair2: these names are the EXACT symbols the native-nat
//     implementer exports (backend-v3/src/ctl_capi_v3.rs:561,566 —
//     `dsmack_ctl_join_abi_version_v3` / `dsmack_ctl_join_err_cap_min_v3`). The
//     rejected repair1 called `dsmack_ctl_join_v3_abi_version` /
//     `dsmack_ctl_join_v3_err_cap_min` (the `_v3` infix form), which the archive
//     does NOT export — a guaranteed unresolved-symbol link failure. Reconciled
//     to the implementer's exported set; the vendored header is now the
//     implementer's byte-identical dsmack_ctl_join_v3.h.
//
// The app stays GENERAL: it carries no Claude/OAuth/marketplace/task/model
// policy. The caller resolves the admitted launch_spec from the EXTERNAL
// admission policy + image manifest and hands verified bytes + spec + the disk
// set to the backend, which re-verifies and refuses before any guest runs.

#if canImport(Darwin)
import CJoin
import Darwin
import Foundation

struct BackendV3Refused: Error, CustomStringConvertible {
    let description: String
    init(_ site: String, _ err: UnsafeMutablePointer<CChar>?) {
        let msg = err == nil ? "no detail" : String(cString: err!)
        description = "backend v3 refused at \(site): \(msg)"
    }
}

/// IG-01 (reported interface gap): the v3 header declares NO receipt/result
/// cap-min probe (v2 had `dsmack_ctl_join_receipt_cap_min`), yet mandates
/// "too-small out_cap is a refusal (-1)". The v3 receipt/result JSON is pure
/// metadata (digests, lengths, lifecycle) — the 16 MiB console and result BYTES
/// are never inlined, only their sha256+length — so a fixed, generous bound is
/// safe. We DO NOT retry-grow on -1, because -1 is overloaded (also "finalize
/// not run"): growing would mask a genuine refusal. If a reviewed v3 archive
/// later adds a cap-min probe, switch to it. See RESULT.md IG-01.
private let kV3MetaJsonCap = 64 * 1024

/// Initialize the linked archive's v3 consumption factory (krun HVF on aarch64
/// macOS). MUST be called once before the first `backendV3VmNew`; refuse to
/// proceed on anything but 0. Also the ABI-version check point. On a host/mock
/// build `dsmack_ctl_v3_init` is ABSENT (the mock platform needs no factory);
/// in the signed Mac archive the HVF adapter (hvf_consumption_v3.rs) provides
/// it. This binding targets the Mac archive, so it REQUIRES init to succeed.
func backendV3Init() throws {
    let v = dsmack_ctl_join_abi_version_v3()
    guard v == 3 else {
        throw Fail("backend control ABI version \(v) != expected 3")
    }
    guard dsmack_ctl_v3_init() == 0 else {
        throw Fail("backend v3 consumption factory already installed or refused")
    }
}

/// Build the general v3 control-profile VM from verified bytes + admitted spec
/// + the five-role disk set. Returns an opaque handle > 0. Ownership of
/// `controlFd` and `netFd` moves into the archive on EVERY native return (they
/// are closed exactly once there, including on refusal). Pass `netFd == -1` for
/// no NIC; otherwise it MUST be a connected SOCK_STREAM. `controlFd` and
/// `netFd` MUST be DISTINCT (an aliased pair is refused by the backend).
///
/// The two fresh RW dests (`scratchPath`, `resultPath`) must NOT pre-exist; the
/// backend creates them O_EXCL 0600 by byte-copying the admitted non-empty
/// template (`scratchTemplatePath`, `resultTemplatePath`) whose content+size it
/// verifies against the spec first.
func backendV3VmNew(kernel: Data, initrd: Data?,
                    specSha256: String, kernelSha256: String, initrdSha256: String?,
                    cmdline: String, cmdlineSha256: String,
                    systemSha256: String, verityRootHash: String, workloadSha256: String,
                    scratchTemplateSha256: String, scratchTemplateBytes: UInt64,
                    resultTemplateSha256: String, resultTemplateBytes: UInt64,
                    ramMib: UInt32, vcpus: UInt32,
                    systemPath: String,
                    scratchTemplatePath: String, scratchPath: String,
                    workloadPath: String,
                    resultTemplatePath: String, resultPath: String,
                    privatePath: String?,
                    consoleLogPath: String,
                    controlFd: Int32, netFd: Int32) throws -> Int64 {
    let errCap = dsmack_ctl_join_err_cap_min_v3()
    let err = UnsafeMutablePointer<CChar>.allocate(capacity: errCap)
    defer { err.deallocate() }
    memset(err, 0, errCap)

    // SWIFT02 (FD ownership repair). The backend consumes controlFd and netFd
    // on EVERY native return (success OR refusal), closing each exactly once.
    // But a caller-side refusal BEFORE the native call (the initrd/pin mismatch
    // below) never hands the descriptors to the backend, so THIS wrapper must
    // close them itself — exactly once, only if valid, and never twice if they
    // alias. We latch `nativeTookFds` the instant the native call returns; until
    // then the defer owns cleanup. (The prior source threw the mismatch inside
    // the kernel closure with NO descriptor cleanup, leaking both fds.)
    var nativeTookFds = false
    defer {
        if !nativeTookFds {
            // Pre-transfer refusal: close distinct, valid descriptors once each.
            if controlFd >= 0 { close(controlFd) }
            if netFd >= 0 && netFd != controlFd { close(netFd) }
        }
    }

    // E01 lifetime repair (PRESERVED from BackendV2.swift): own null-terminated
    // HEAP copies that live until this function returns, so every `const char *`
    // the backend reads for the full duration of dsmack_ctl_join_vm_new_v3
    // points at valid, immovable bytes — no borrowed pointer escapes a closure.
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

    var spec = dsmack_ctl_launch_spec_v3()
    spec.spec_sha256 = cdup(specSha256)
    spec.kernel_sha256 = cdup(kernelSha256)
    spec.initrd_sha256 = cdupMaybe(initrdSha256)
    spec.cmdline = cdup(cmdline)
    spec.cmdline_sha256 = cdup(cmdlineSha256)
    spec.system_sha256 = cdup(systemSha256)
    spec.verity_root_hash = cdup(verityRootHash)
    spec.workload_sha256 = cdup(workloadSha256)
    spec.scratch_template_sha256 = cdup(scratchTemplateSha256)
    spec.scratch_template_bytes = scratchTemplateBytes
    spec.result_template_sha256 = cdup(resultTemplateSha256)
    spec.result_template_bytes = resultTemplateBytes
    spec.ram_mib = ramMib
    spec.vcpus = vcpus

    var disks = dsmack_ctl_disk_set_v3()
    disks.system_path = cdup(systemPath)
    disks.scratch_template_path = cdup(scratchTemplatePath)
    disks.scratch_path = cdup(scratchPath)
    disks.workload_path = cdup(workloadPath)
    disks.result_template_path = cdup(resultTemplatePath)
    disks.result_path = cdup(resultPath)
    disks.private_path = cdupMaybe(privatePath)   // NULL => no vde (unmeasured)
    let cConsole = cdup(consoleLogPath)

    // Caller-side consistency refusal, performed BEFORE acquiring any buffer
    // pointer and BEFORE the native call (the backend re-checks this itself;
    // its refusal is authoritative). Presence is the presence of the `initrd`
    // Data VALUE, not of a buffer base address: an EMPTY (0-byte) initrd Data is
    // a present-but-empty image, distinct from `nil`. The SWIFT02 defer above
    // performs descriptor cleanup on this throw.
    if (initrd == nil) != (initrdSha256 == nil) {
        throw Fail("initrd bytes/pin presence mismatch (caller-side)")
    }

    // SWIFT01 (buffer-lifetime repair). Keep the native call INSIDE both the
    // kernel and the initrd `withUnsafeBytes` closures so neither base pointer
    // escapes its closure. The prior source returned `baseAddress` OUT of the
    // initrd closure and used it after that closure ended (dangling). We nest
    // the closures; the native call executes while BOTH buffers are pinned. For
    // the no-initrd case we pass (nil, 0) without opening an initrd closure.
    func callNative(_ kp: UnsafePointer<UInt8>?, _ klen: Int,
                    _ ip: UnsafePointer<UInt8>?, _ ilen: Int) throws -> Int64 {
        let h = dsmack_ctl_join_vm_new_v3(
            kp, klen,
            ip, ilen,
            &spec, &disks,
            cConsole,
            controlFd, netFd,
            err, errCap)
        // The backend now owns controlFd/netFd on this (any) return — the defer
        // must NOT also close them.
        nativeTookFds = true
        guard h != 0 else { throw BackendV3Refused("v3_build", err) }
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

/// Advance the returning lifecycle to a proven halt. Call exactly once BEFORE
/// finalize. Does NOT free the handle. Returns the VMM code (0 = PSCI halt, NOT
/// workload success); < 0 is a refusal.
func backendV3Run(handle: Int64) throws -> Int32 {
    let errCap = dsmack_ctl_join_err_cap_min_v3()
    let err = UnsafeMutablePointer<CChar>.allocate(capacity: errCap)
    defer { err.deallocate() }
    memset(err, 0, errCap)
    let code = dsmack_ctl_join_run_v3(handle, err, errCap)
    if code < 0 { throw BackendV3Refused("v3_run", err) }
    return code
}

/// Checked R06 finalization (flush/sync vdd+console before destruction,
/// retained-descriptor sync, fixed-size + I/O-vs-hash identity checks, bounded
/// pread of the EXACT result/console bytes). REFUSED until run reported a halt.
/// Any step failing is a refusal and NO result is produced. Does NOT free.
func backendV3Finalize(handle: Int64) throws {
    let errCap = dsmack_ctl_join_err_cap_min_v3()
    let err = UnsafeMutablePointer<CChar>.allocate(capacity: errCap)
    defer { err.deallocate() }
    memset(err, 0, errCap)
    guard dsmack_ctl_join_finalize_v3(handle, err, errCap) == 0 else {
        throw BackendV3Refused("v3_finalize", err)
    }
}

/// Copy the launch receipt JSON (dsmack-backend-v3/launch-receipt/1). Records
/// admitted template identities + vde PRESENCE only (never vde content/size).
/// Handle not consumed. Call after vm_new_v3, before free.
func backendV3Receipt(handle: Int64) throws -> String {
    let out = UnsafeMutablePointer<CChar>.allocate(capacity: kV3MetaJsonCap)
    defer { out.deallocate() }
    memset(out, 0, kV3MetaJsonCap)
    guard dsmack_ctl_join_receipt_v3(handle, out, kV3MetaJsonCap) == 0 else {
        throw BackendV3Refused("v3_receipt", nil)   // see IG-01
    }
    return String(cString: out)
}

/// Copy the run-result JSON (dsmack-backend-v3/run-result/1): result_disk,
/// console, runtime_input (presence only, never vde content/size/hash), and
/// lifecycle (vmm_code, run_ms, backend_abi). REFUSED (-1) until finalize ran.
/// Handle not consumed.
func backendV3Result(handle: Int64) throws -> String {
    let out = UnsafeMutablePointer<CChar>.allocate(capacity: kV3MetaJsonCap)
    defer { out.deallocate() }
    memset(out, 0, kV3MetaJsonCap)
    guard dsmack_ctl_join_result_v3(handle, out, kV3MetaJsonCap) == 0 else {
        throw BackendV3Refused("v3_result", nil)    // -1 => finalize not run, or IG-01
    }
    return String(cString: out)
}

/// Teardown: free the handle and close every owned descriptor exactly once.
func backendV3Free(handle: Int64) {
    dsmack_ctl_join_free_v3(handle)
}
#endif
