// signed-app-join: Swift binding for the reviewed returning-lifecycle HVF backend
// (libdsmack_hvf_returning.a, UNSIGNED INTEGRATION FIXTURE build `6859510d…f433a`).
//
// REVIEW GATE: this binding and the archive behind it are source-level integration
// work. They require independent exact source review before ANY execution or signing;
// the frozen, review-authorized artifact remains batch3/leak-fix/artifacts
// `9a5af5d6…0ea03` (probe-only, dsmack_probe_main). Nothing here runs a VM on its own.
//
// Pins (kernel/initrd/cmdline SHA-256) are compiled into the archive and are NOT
// caller-suppliable: the app mirrors them below only to state the expectation it
// enforces on its own inputs BEFORE calling the backend (read-once, capped, pinned,
// same discipline as the v1 kernel path in main.swift). The backend re-verifies the
// same pins inside the verified payload; a mismatch is a refusal there too.

#if canImport(Darwin)
import CJoin
import Foundation

let backendKernelSHA256 = "842b62e8b8bdfc07ec67a3a4d472620c86ad9897020d2ab4c069cac25c38e34e"
// repair2 (astra-gate repair2 R1): REBUILT pivot initrd — bakes the rebuilt
// system disk's verity table/root; guest/CLOSURE.json records the closure.
let backendInitrdSHA256 = "6975a86c3520bd8efae0777b25053b4329a5707e9b481307ba9c671ef5eb15c0"
let backendCmdline = "console=hvc0 rdinit=/init panic=-1"
let backendCmdlineSHA256 = "d13f063c25d4547f364646981048a517d813f45fe50a8f429c21cd6123412e6b"
// The control-profile archive this binary is linked against; the build script refuses
// to proceed on mismatch. NOT the frozen review-gate archive (9a5af5d6…0ea03,
// probe-only). R2-ARCHIVE-IDENTITY-CLOSURE (morning-20261020 source repair): the
// actual current archive is the overnight4-repair target-join build (A7 memory
// lifetime + console-teardown latch changes vs repair2). A .a hash is
// build-dependent (ar member mtimes), so the packet records this exact build's
// hash; any relink requires updating it via the packet.
// packet/check-archive-identity-closure.py verifies this constant (and every
// other archive-identity site) against the actual archive bytes BEFORE build.
let backendArchiveSHA256 = "8e6cf876fa676f7b052f181c4c118fbc4f5e67fdc7c7a75a7aac64e03a0ec4ec"

struct BackendRefused: Error, CustomStringConvertible {
    let description: String
    init(_ site: String, _ err: UnsafeMutablePointer<CChar>?) {
        let msg = err == nil ? "no detail" : String(cString: err!)
        description = "backend refused at \(site): \(msg)"
    }
}

/// One complete returning-lifecycle run of the joined HVF backend:
/// verified-payload build (refusals before any VM exists) -> run_returning (which
/// performs checked stop_returning + finish_returning: observer drain, bounded vCPU
/// joins, drop-owners -> vm.destroy() -> drop guest memory) -> return the VMM code.
/// Code 0 means guest halt (PSCI SYSTEM_OFF/RESET), never workload success.
/// The console log must be read only AFTER this returns; output commitments are taken
/// over the final bytes, after checked teardown.
func backendRun(kernel: Data, initrd: Data, consoleLogPath: String) throws -> Int32 {
    let errCap = dsmack_join_err_cap_min()
    let err = UnsafeMutablePointer<CChar>.allocate(capacity: errCap)
    defer { err.deallocate() }
    memset(err, 0, errCap)

    let handle = try kernel.withUnsafeBytes { kb in
        try initrd.withUnsafeBytes { ib in
            let h = dsmack_join_vm_new(
                kb.bindMemory(to: UInt8.self).baseAddress, kb.count,
                ib.bindMemory(to: UInt8.self).baseAddress, ib.count,
                consoleLogPath, err, errCap)
            guard h != 0 else { throw BackendRefused("build", err) }
            return h
        }
    }
    let code = dsmack_join_run(handle, err, errCap)
    if code < 0 { throw BackendRefused("run", err) }
    return code
}
#endif

// --- control-profile ABI: the v1 C ABI (dsmack_ctl_join.h) is RETIRED ---
// mac-native-fixes lane, 2026-10-21 (fable-native-audit F2): integration
// patch 0002 removed the v1 control ABI from the archive (the compiled-pin
// control profile it served is replaced, not extended), so the v1 Swift
// wrappers that lived here (backendCtlAbiVersion / backendCtlCheckAbi /
// backendCtlVmNew / backendCtlRun, and the ctl-only mirrored pins
// backendDiskSHA256 / backendDiskManifestSHA256 /
// backendCtlAbiVersionExpected) are retired WITH it — keeping them would
// have bound the v2 symbols with v1 argument layouts. The complete v2
// binding is BackendV2.swift (dsmack_ctl_join_v2.h, ABI version 2): the
// mirrored pins are gone from the app entirely, because in v2 every image
// digest arrives in the externally admitted launch_spec (zero compiled-in
// image identity) and the backend re-verifies all of it (R1-R5).
// The dsmack_join/1 returning ABI above is untouched.
