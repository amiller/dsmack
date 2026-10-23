import Containerization
import ContainerizationArchive
import CryptoKit
import DeviceCheck
import Foundation
import marAttest
import marControl
import Synchronization
import SystemPackage

// mar enroll <out> <challenge>
// mar run <out> <base> <config.json> <image.oci.tar> <input> <challenge> <keyId> [<host-socket>]
// mar hvf-fixture <out> <kernel> <initrd> <challenge> <keyId>
// mar hvf-control <out> <kernel> <initrd> <disk> <challenge> <keyId>
// mar hvf-v2 <out> <session.json> <challenge> <keyId>
//     (generic v2 launch: external admitted inputs -> admission core -> BackendV2)
// Every statement field is computed here from bytes this process read or observed; nothing comes from argv but paths.
//
// hvf-control attest wiring (new HVF profile, dsmack-hvf-control-statement/1):
// when the signed-app gate is open — the keyId directory stages keyId.txt +
// enrollment.cbor + enroll-client-data.bin — the OBSERVED run facts (root
// terminal record verbatim, actual stdout/stderr/guest trace, raw control
// transcript, host trace/lifecycle, derived checker verdict over the exact
// prompt bytes) go through marAttest ControlAttestFlow -> HvFControlEmit
// receipt -> REAL DCAppAttestService.generateAssertion over sha256(exact
// control_statement bytes) -> offline ECDSA verification with counter binding
// -> counter store advance. NO legacy/VZ statement exists on this path. The
// assertion producer is the ONLY DeviceCheck call site here; with the gate
// closed, nothing changes: the summary records attest.status = waiting.
// REVIEW GATE: the backend archive and this mode are UNSIGNED INTEGRATION FIXTURE work —
// exact source review must precede any execution or signing. The existing v1 `run` mode,
// its statement domain and every v1 check are untouched (the v1 qualification surface
// does not move). The fixture emits backend-fixture.json + the console log only: no
// statement.json, no assertion, no task receipt. A returning code 0 is a guest HALT
// (PSCI), never a task success; there is no control channel or terminal record on this
// path, so nothing here can claim a completed task.

// Kata 3.17.0 vmlinux-6.12.28, the runner's pin. Any other kernel is refused.
let kernelSHA256 = "67bac9f416af4cdc9b151e4ba4962d6515e0ad7acc53816761cf964aa6af6ea0"
let initfsReference = "ghcr.io/apple/containerization/vminit@sha256:4551a4627a8575ee625e139fa8a1fbdc5b09f06d03c8dc2c3863dcd2e33e98af"

struct Fail: Error, CustomStringConvertible { let description: String; init(_ s: String) { description = s } }
func hex(_ d: some Sequence<UInt8>) -> String { d.map { String(format: "%02x", $0) }.joined() }
func sha256hex(_ d: Data) -> String { hex(SHA256.hash(data: d)) }
func canonical(_ o: Any) throws -> Data { try JSONSerialization.data(withJSONObject: o, options: [.sortedKeys, .withoutEscapingSlashes]) }
// Each input is read once, through a size cap; every later use (hash, VM, statement) is of those bytes.
func read(_ p: String, max: Int) throws -> Data {
    let d = try FileHandle(forReadingFrom: URL(fileURLWithPath: p)).read(upToCount: max + 1) ?? Data()
    guard d.count <= max else { throw Fail("\(p) exceeds \(max) bytes") }
    return d
}
let guestSocket = "/run/upstream.sock", socketMode: CModeT = 0o600, outputLimit = 1 << 24

// Host-side diagnostics only, never part of the statement; run.sh keeps these in the launch logs.
func note(_ s: String) { FileHandle.standardError.write(Data("mar: \(s)\n".utf8)) }

// Containerization's socket relay writes with write(2) on sockets without SO_NOSIGPIPE; ignored, a closed peer gives EPIPE.
signal(SIGPIPE, SIG_IGN)

// --- dsmack-runtimehook/1: optional supervisor observation hook ----------
// Writes an atomic JSON heartbeat (phase + pid + wall clock) so an outer
// qualification supervisor can distinguish a stalled run from slow progress
// and correlate its external fd/thread/RSS samples with run phases. Purely
// observational: no influence on execution, no channel bytes, no secrets;
// without DSMACK_RUNTIME_HEARTBEAT set the hook is completely inert.
struct RuntimeHook {
    let url: URL?
    let pid: Int32 = getpid()
    var lastBeat: Double = 0.0
    init() {
        let path = ProcessInfo.processInfo.environment["DSMACK_RUNTIME_HEARTBEAT"] ?? ""
        url = path.isEmpty ? nil : URL(fileURLWithPath: path)
    }
    mutating func beat(_ phase: String, _ extra: [String: Any] = [:]) {
        guard let url = url else { return }
        let now = Date().timeIntervalSince1970
        guard now - lastBeat >= 1.0 else { return }   // throttled to 1 Hz
        lastBeat = now
        var doc: [String: Any] = ["schema": "dsmack-runtimehook/1", "phase": phase,
                                  "pid": pid, "now": now]
        for (k, v) in extra { doc[k] = v }
        guard let data = try? JSONSerialization.data(withJSONObject: doc,
                                                     options: [.sortedKeys]) else { return }
        try? data.write(to: url, options: [.atomic])
    }
}
var runtimeHook = RuntimeHook()

let a = CommandLine.arguments
// The exact supported mode syntax; shared by the --help/-h path and the
// argument-count guard so the two can never drift.
let usageText = "usage: mar enroll <out> <challenge> | mar run <out> <base> <config> <oci.tar> <input> <challenge> <keyId> [<host-socket>] | mar hvf-fixture <out> <kernel> <initrd> <challenge> <keyId> | mar hvf-v2 <out> <session.json> <challenge> <keyId> | mar hvf-v3 <out> <session.json> <challenge> <keyId>"
// Agent-friendly help (cross-lane joined-reviewed-native-swift-compile smoke fix,
// carried into owned main.swift per owner FEEDBACK): `mar --help` / `mar -h` print
// the supported mode syntax to stdout and exit 0 BEFORE the argument-count failure.
// This path launches nothing — no out dir, no DeviceCheck, no VM, no network, no
// credentials — so it is safe to invoke credential-free. A missing/short argv still
// fails closed with the SAME usage text.
if a.count >= 2, a[1] == "--help" || a[1] == "-h" {
    print(usageText)
    exit(0)
}
guard a.count >= 3 else { throw Fail(usageText) }
let out = URL(fileURLWithPath: a[2])
guard !FileManager.default.fileExists(atPath: out.path) else { throw Fail("\(out.path) already exists") }
// APP-SCOPE-02-R1-DIRECTORY: OUT is a FRESH FINAL COMPONENT created under an ESTABLISHED
// parent — withIntermediateDirectories:false, so this creates ONLY `out` and refuses if
// its parent does not already exist. Requiring an established parent (rather than silently
// materializing a chain of new ancestors) is what lets performDurableRetention retain and
// fsync that single parent so the newly created OUT directory ENTRY is itself durable, and
// re-confirm the OUT-in-parent no-follow mapping around the sync. A missing parent fails
// closed here instead of creating ancestors whose own parent entries would be unsynchronized.
try FileManager.default.createDirectory(at: out, withIntermediateDirectories: false)
// 0700 keeps other users out; it is not a boundary against a process running as this same user.
try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: out.path)
func save(_ name: String, _ d: Data) throws { try d.write(to: out.appendingPathComponent(name), options: .atomic) }

func challenge(_ p: String) throws -> String {
    let c = try read(p, max: 32)
    guard c.count == 32 else { throw Fail("challenge must be 32 bytes, got \(c.count)") }
    return hex(c)
}

// --- Shared lifecycle state (A5): initialized BEFORE any mode dispatch ---
// Every mode — enroll, hvf-fixture, run — enters with the trace chain, cancellation
// state, scratch registry and bounded supervision already live. The previous layout
// dispatched hvf-fixture before these initializers ran and exited inside the fixture
// body, so on that path trace/cancellation helpers read uninitialized state and the
// signal sources and whole-run watchdog were never installed (astra-gate A5).
// Host-observed lifecycle trace: h_i = sha256(h_{i-1} hex ‖ canonical(event_i)), h_0 = 64 zeros.
let started = ContinuousClock.now
var traceLines = Data(), head = String(repeating: "0", count: 64), seq = 0
func trace(_ event: String, _ data: [String: Any] = [:]) throws {
    let ms = Int((ContinuousClock.now - started) / .milliseconds(1))
    let line = try canonical(data.merging(["seq": seq, "event": event, "t_ms": ms]) { x, _ in x })
    head = sha256hex(Data(head.utf8) + line)
    traceLines += line + Data("\n".utf8)
    seq += 1
}

let stopReason = Mutex<String?>(nil)
// The reason a signal handler asked us to stop, if any; only the watchdog reads it, so no
// async work ever happens in the raw handler itself.
let signalReason = Mutex<String?>(nil)
// Set only after publication/teardown completes. Retain paths under a lock so reporting
// and lifecycle observations do not race access to the scratch list.
let runFinished = Mutex(false)
let scratchPaths = Mutex<[String]>([])
func checkCancellation() throws {
    guard signalReason.withLock({ $0 == nil }), !FileManager.default.fileExists(atPath: out.appendingPathComponent("cancel.request").path)
    else { throw Fail("execution cancelled") }
}
func own(_ u: URL) -> URL { scratchPaths.withLock { $0.append(u.path) }; return u }
func dropScratch() {
    reportDeferredResidue(paths: scratchPaths.withLock { $0 })
}

// --- Bounded whole-run lifetime (A5): supervision installed BEFORE dispatch ---
// Cooperative cancellation (watchdog kill, Task.cancel) bounds the guest, but it cannot
// bound a stuck library call: an image load, initfs build, container create/start, or a
// synchronous backend call that never returns would otherwise hang this process forever.
// Each mode sets its whole-run deadline below BEFORE entering its blocking phase (the
// run mode first sets a provisional bound, then tightens it to the guest deadline plus
// the fixed setup/teardown allowance once the config is validated).
let setupAllowanceSeconds = 600, fixtureDeadlineSeconds = 900
let runDeadline = Mutex<ContinuousClock.Instant?>(nil)
func setRunDeadline(_ instant: ContinuousClock.Instant) { runDeadline.withLock { $0 = instant } }

// SIGTERM/SIGINT: the default handlers are removed and Dispatch signal sources note the
// request in signalReason. Handlers run no async work; the watchdog's 100 ms poll picks the
// reason up and fails the run without publishing a receipt. SIGPIPE was
// already ignored above.
for sig in [SIGTERM, SIGINT] { signal(sig, SIG_IGN) }
let signalSources: [DispatchSourceSignal] = [SIGTERM, SIGINT].map { sig in
    let src = DispatchSource.makeSignalSource(signal: sig, queue: DispatchQueue(label: "mar-signals"))
    src.setEventHandler {
        let name = sig == SIGTERM ? "sigterm" : "sigint"
        signalReason.withLock { if $0 == nil { $0 = name } }
        note("received \(name.uppercased()); stopping the guest, no complete receipt will be written")
    }
    src.resume()
    return src
}

// Final fallback: if the run is still alive at the deadline — a library or backend call
// stuck past the watchdog's reach — exit the process hard. No receipt is written on this
// path: nothing was observed to completion. Blocking cleanup is skipped on this last-resort
// path. The Mac must separately qualify that owner death reclaims the VZ virtual machine,
// helper processes and HVF contexts (VMCleanup), so nothing outlives a hard exit even
// without an explicit delete.
Thread.detachNewThread {
    var cancelledAt: ContinuousClock.Instant? = nil
    while !runFinished.withLock({ $0 }) {
        if (signalReason.withLock({ $0 != nil }) || FileManager.default.fileExists(atPath: out.appendingPathComponent("cancel.request").path)) && cancelledAt == nil { cancelledAt = .now }
        let deadline = runDeadline.withLock { $0 }
        if deadline.map({ ContinuousClock.now >= $0 }) == true || cancelledAt.map({ ContinuousClock.now >= $0 + .seconds(10) }) == true {
            note("hard execution/cancellation deadline reached; exiting without a completed receipt")
            // Do not block the final deadline on filesystem cleanup. VM teardown on owner
            // death is separately qualified; leftover scratch is operator-owned cleanup.
            _exit(2)
        }
        Thread.sleep(forTimeInterval: 0.1)
    }
}

if a[1] == "enroll", a.count == 4 {
    let svc = DCAppAttestService.shared
    guard svc.isSupported else { throw Fail("App Attest unsupported in this process; refusing to run") }
    setRunDeadline(started + .seconds(setupAllowanceSeconds))
    let clientData = try canonical(["domain": "minimal-attested-run-enroll/1", "challenge": try challenge(a[3])])
    let key = try await svc.generateKey()
    try save("keyId.txt", Data(key.utf8))
    try save("clientData.bin", clientData)
    try save("attestation.cbor", try await svc.attestKey(key, clientDataHash: Data(SHA256.hash(data: clientData))))
    runFinished.withLock { $0 = true }
    exit(0)
}

// --- hvf-fixture: one returning-lifecycle run of the joined HVF backend (UNSIGNED
// --- INTEGRATION FIXTURE; exact source review precedes any execution or signing).
// The v1 `run` mode and its statement are untouched. Emits backend-fixture.json +
// trace + console log only — never statement.json or an assertion: a returning halt
// is not workload success and this domain is unknown to every receipt profile.
// A5: dispatched only after the shared lifecycle state above is initialized and the
// signal sources + whole-run watchdog are live; the dispatch sets the fixed fixture
// deadline BEFORE backendRun is entered, so a stalled backend (backendRun is a
// synchronous C call) and a cancellation are both bounded by the watchdog with no
// receipt on either path. This path never touches DeviceCheck: svc/isSupported are
// evaluated on the enroll/run paths only (astra-gate A8 note).
func runHvFFixture(kernelPath: String, initrdPath: String, challengePath: String, keyIdPath: String) throws {
    do {
        try checkCancellation()
        // Read-once, capped, pinned boot bytes — the same discipline as the v1 kernel
        // path; the backend re-verifies the same compiled-in pins on its side.
        let kernelBytes = try read(kernelPath, max: 1 << 26)
        guard sha256hex(kernelBytes) == backendKernelSHA256 else { throw Fail("kernel sha256 \(sha256hex(kernelBytes)) != \(backendKernelSHA256)") }
        let initrdBytes = try read(initrdPath, max: 8 << 20)
        guard sha256hex(initrdBytes) == backendInitrdSHA256 else { throw Fail("initrd sha256 \(sha256hex(initrdBytes)) != \(backendInitrdSHA256)") }
        let fixtureChallenge = try challenge(challengePath)
        let fixtureKeyId = String(decoding: try read(keyIdPath, max: 1024), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        try trace("backend_inputs_pinned", ["kernel_sha256": backendKernelSHA256, "initrd_sha256": backendInitrdSHA256, "cmdline_sha256": backendCmdlineSHA256])

        // The console log is created O_EXCL by the backend inside OUT and kept as
        // evidence (NOT registered as scratch): the VM writes diagnostics there and
        // nothing else. No control channel exists on this path.
        let consolePath = out.appendingPathComponent("console-1.log").path
        let startedAt = ContinuousClock.now
        let code = try backendRun(kernel: kernelBytes, initrd: initrdBytes, consoleLogPath: consolePath)
        try checkCancellation()   // between backend return and publication only
        // Console commitments are taken over the FINAL bytes, read only after
        // dsmack_join_run returned — i.e. after checked teardown (observer drain,
        // bounded joins, vm.destroy, guest memory dropped), never from a live guest.
        let consoleBytes = try FileHandle(forReadingFrom: URL(fileURLWithPath: consolePath)).read(upToCount: outputLimit + 1) ?? Data()
        let consoleCut = consoleBytes.count > outputLimit
        try trace("backend_returned", ["vmm_code": Int(code), "console_sha256": sha256hex(consoleBytes.prefix(outputLimit)), "console_bytes": consoleBytes.count, "console_truncated": consoleCut])

        let fixture = try canonical([
            "domain": "minimal-attested-backend-fixture/1",
            "challenge": fixtureChallenge,
            "key_id": fixtureKeyId,
            "backend_archive_sha256": backendArchiveSHA256,
            "pins": ["kernel_sha256": backendKernelSHA256, "initrd_sha256": backendInitrdSHA256,
                     "cmdline": backendCmdline, "cmdline_sha256": backendCmdlineSHA256],
            "backend": ["abi": "dsmack_join/1", "run_ms": Int((ContinuousClock.now - startedAt) / .milliseconds(1))],
            "console": ["sha256": sha256hex(consoleBytes.prefix(outputLimit)), "bytes": consoleBytes.count, "truncated": consoleCut],
            "outcome": code == 0 && !consoleCut ? "backend_run_returned_guest_halt" : "backend_run_refused_or_vcpu_error",
            "vmm_code": Int(code),
            "trace": ["head": head, "events": seq],
        ] as [String: Any])
        try save("backend-fixture.json", fixture)
        try save("trace.jsonl", traceLines)
        dropScratch()
        runFinished.withLock { $0 = true }
        exit(0)
    } catch {
        try? save("trace.jsonl", traceLines)
        note("hvf-fixture failed: \(error)")
        dropScratch()
        runFinished.withLock { $0 = true }
        throw error
    }
}
if a[1] == "hvf-fixture" {
    guard a.count == 7 else { throw Fail("hvf-fixture usage: mar hvf-fixture <out> <kernel> <initrd> <challenge> <keyId>") }
    // Whole-run bound for the fixture: pinned tiny guest + teardown inside this fixed
    // deadline (no config on this path); set BEFORE the backend is entered (A5).
    setRunDeadline(started + .seconds(fixtureDeadlineSeconds))
    try runHvFFixture(kernelPath: a[3], initrdPath: a[4], challengePath: a[5], keyIdPath: a[6])
    exit(0)
}
// --- hvf-control: the control-profile session over the joined backend ABI ---
// RETIRED with the v1 control ABI (mac-native-fixes lane, 2026-10-21;
// fable-native-audit F2). Integration patch 0002 REMOVED the v1
// dsmack_ctl_join C ABI from the archive (compiled-in pins are replaced, not
// extended), so a v1-shaped call here no longer has a symbol to bind, and
// binding the v2 `dsmack_ctl_join_vm_new` with a v1 argument layout would be
// memory-unsafe. The v2 launch takes the ADMITTED launch_spec (external
// policy + image manifest digests); its app-side resolution is the
// mac-integration lane's port of mac-general-prep launcher/* (fable-native-audit
// F7 seam) — deliberately NOT approximated here, because a caller-invented
// spec with no admission core would fake the very authorization this ABI
// refuses to imply. The complete v2 binding (BackendV2.swift:
// backendV2Init / backendV2VmNew / backendV2Receipt / backendV2Run — ABI-2
// checked, v1 err-buffer and control-fd ownership disciplines preserved) is
// in the tree and ready for that lane. The hvf-fixture path (dsmack_join/1)
// is untouched and stays the source-level fixture path.
/// Fail-closed retirement of the v1-shaped control session: every call is
/// refused BEFORE any channel, console or VM exists, naming the exact seam
/// that completes the v2 path. No summary, trace or receipt is produced —
/// this mode launches nothing until the v2 admission core lands.
func runHvFControl(kernelPath: String, initrdPath: String, diskPath: String,
                   challengePath: String, keyIdPath: String) throws -> Never {
    throw Fail("hvf-control v1 launch is retired with the v1 control ABI "
        + "(integration patch 0002 removed dsmack_ctl_join v1 from the archive). "
        + "The v2 control profile requires the admitted launch_spec resolved by "
        + "the app-side admission core (mac-integration lane; fable-native-audit "
        + "F7); the ready v2 binding is BackendV2.swift "
        + "(backendV2Init/backendV2VmNew/backendV2Receipt/backendV2Run). "
        + "Nothing was launched and no evidence was emitted.")
}
if a[1] == "hvf-control" {
    guard a.count == 8 else { throw Fail("hvf-control usage: mar hvf-control <out> <kernel> <initrd> <disk> <challenge> <keyId>") }
    try runHvFControl(kernelPath: a[3], initrdPath: a[4], diskPath: a[5], challengePath: a[6], keyIdPath: a[7])
    exit(0)
}
// --- hvf-v2: the COMPLETE generic v2 launch entry point (mac-app-join lane,
// --- 2026-10-21; fable-native-audit F7 seam closed). External admitted
// --- inputs (session document -> admission policy, image manifest, dstack
// --- checksum manifest + metadata, contract10 admission document, workload
// --- disk) -> app-side admission core -> BackendV2 (krun HVF factory) ->
// --- observed consumed tuple + lifecycle/output statement + REAL
// --- DCAppAttestService assertion. Generic app: no Claude/task/marketplace
// --- policy, zero compiled image pins (a new admitted base image is a
// --- policy edit + manifest, never a rebuild or re-sign). Fail-closed like
// --- the v1 `run` mode: App Attest unsupported refuses before anything is
// --- built; no statement or assertion exists on any failure path.
if a[1] == "hvf-v2" {
    guard a.count == 6 else { throw Fail("hvf-v2 usage: mar hvf-v2 <out> <session.json> <challenge> <keyId>") }
    // Same DeviceCheck discipline as the v1 run mode (astra-gate A8): the
    // isSupported check is evaluated on this attesting path only, BEFORE
    // anything is built, and generateAssertion is the ONLY other call.
    let svc = DCAppAttestService.shared
    guard svc.isSupported else { throw Fail("App Attest unsupported in this process; refusing to run") }
    // Provisional bound; V2Launch tightens it to the resolved runtime bound
    // once the external documents are parsed (watchdog already live — A5).
    setRunDeadline(started + .seconds(3600 + setupAllowanceSeconds))
    try await runHvFV2(out: out, sessionPath: a[3], challengeHex: try challenge(a[4]),
                       keyId: String(decoding: try read(a[5], max: 1024), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines))
    exit(0)
}
// --- hvf-v3: the COMPLETE generic v3 launch entry point (loop40-swift-repair1
// --- lane, 2026-10-22; SWIFT03/SWIFT04). Same external admitted-input pipeline
// --- as hvf-v2, driving BackendV3 (five-role disk set vda/vdb/vdc/vdd + optional
// --- vde, optional bounded virtio-net fd) through the RETURNING lifecycle split
// --- (run_v3 -> checked finalize_v3 -> result_v3), then composing BOTH the
// --- launch receipt-evidence assertion AND the authenticated run-result envelope
// --- + result assertion, with durable complete retention before any cleanup.
// --- Same fail-closed DeviceCheck discipline (A8) as the run/v2 modes.
if a[1] == "hvf-v3" {
    guard a.count == 6 else { throw Fail("hvf-v3 usage: mar hvf-v3 <out> <session.json> <challenge> <keyId>") }
    let svc = DCAppAttestService.shared
    guard svc.isSupported else { throw Fail("App Attest unsupported in this process; refusing to run") }
    setRunDeadline(started + .seconds(3600 + setupAllowanceSeconds))
    try await runHvFV3(out: out, sessionPath: a[3], challengeHex: try challenge(a[4]),
                       keyId: String(decoding: try read(a[5], max: 1024), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines))
    exit(0)
}
guard a[1] == "run", a.count == 9 || a.count == 10 else { throw Fail("unknown mode or argument count") }
let svc = DCAppAttestService.shared
guard svc.isSupported else { throw Fail("App Attest unsupported in this process; refusing to run") }
// Provisional whole-run bound while the config is read and validated; tightened to the
// exact guest-contained deadline immediately after the config checks below (A5: the
// watchdog is already live, so even a stuck config parse is bounded).
setRunDeadline(started + .seconds(3600 + setupAllowanceSeconds))
let base = URL(fileURLWithPath: a[3]), runChallenge = try challenge(a[7])
let keyId = String(decoding: try read(a[8], max: 1024), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)

// (trace chain state initialized above, before dispatch — A5)

struct Config: Decodable { let image: String; let argv: [String]; let env: [String]; let cpus: Int; let memory_mib: Int; let timeout_seconds: Int; let upstream_socket: Bool }
let configBytes = try read(a[4], max: 65536)
let configObject = try JSONSerialization.jsonObject(with: configBytes)
// Canonical bytes only: re-serialization drops duplicate keys and normalizes numbers, so either makes the bytes differ.
guard try canonical(configObject) == configBytes else { throw Fail("config is not canonical JSON") }
let keys = Set((configObject as? [String: Any] ?? [:]).keys)
guard keys == ["image", "argv", "env", "cpus", "memory_mib", "timeout_seconds", "upstream_socket"] else { throw Fail("config keys \(keys.sorted())") }
let config = try JSONDecoder().decode(Config.self, from: configBytes)
func printable(_ s: String) -> Bool { s.utf8.count <= 4096 && s.utf8.allSatisfy { (0x20...0x7e).contains($0) } }
func matches(_ s: String, _ re: String) -> Bool { s.range(of: re, options: .regularExpression) != nil }
guard config.image.utf8.count <= 255, matches(config.image, "^[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}$") else { throw Fail("image must be a digest-pinned reference") }
guard (1...64).contains(config.argv.count), config.argv.allSatisfy(printable), config.argv[0].hasPrefix("/") else { throw Fail("argv: 1-64 printable ASCII strings, absolute argv[0]") }
let envNames = config.env.map { $0.prefix { $0 != "=" } }
guard config.env.count <= 64, config.env.allSatisfy({ printable($0) && matches($0, "^[A-Z_][A-Z0-9_]{0,63}=") }), Set(envNames).count == envNames.count
else { throw Fail("env: at most 64 unique NAME=value printable ASCII entries") }
guard (1...4).contains(config.cpus), (128...4096).contains(config.memory_mib), (1...3600).contains(config.timeout_seconds)
else { throw Fail("limits: cpus 1-4, memory_mib 128-4096, timeout_seconds 1-3600") }
// The host end is untrusted transport chosen by the operator; only its presence and the guest mapping are recorded.
guard (a.count == 10) == config.upstream_socket else { throw Fail("host socket argument must be given iff upstream_socket") }
let hostSocket = config.upstream_socket ? URL(fileURLWithPath: a[9]) : nil
if let hostSocket {
    let type = try FileManager.default.attributesOfItem(atPath: hostSocket.path)[.type] as? FileAttributeType
    guard type == .typeSocket else { throw Fail("\(hostSocket.path) is not a Unix socket") }
}
try trace("config_loaded", ["config_sha256": sha256hex(configBytes)])

// The whole run — setup, guest and teardown — must finish inside this deadline: the
// guest's own timeout plus the fixed setup/teardown allowance, so it strictly contains
// the guest deadline. The watchdog installed before dispatch enforces it (A5).
setRunDeadline(started + .seconds(config.timeout_seconds + setupAllowanceSeconds))

// --- Archive admission (before ContainerizationArchive or the image store see any of it) ---
// Only a plain ustar stream of directories and regular files with relative, normalized paths
// is admitted. Hard links, symlinks, devices, fifos, sparse files and the PAX/GNU extension
// entries (long names among them) are refused explicitly rather than interpreted. Every OCI
// descriptor must name a blob the archive actually carries, at its stated size, hashing to
// its stated digest; every blobs/sha256/<name> file must also hash to its own file name.
let maxTarEntries = 4096, maxLayers = 64
let maxIndexBytes = 1 << 16, maxManifestBytes = 1 << 20, maxConfigBytes = 1 << 20

struct TarEntry { let isDir: Bool; let size: Int; let offset: Int }

func tarName(_ d: Data, _ base: Int, _ off: Int, _ len: Int) throws -> String {
    var bytes: [UInt8] = []
    for i in 0..<len {
        let b = d[base + off + i]
        if b == 0 { break }
        guard (0x20...0x7e).contains(b) else { throw Fail("tar: entry name has a non-printable byte") }
        bytes.append(b)
    }
    return String(decoding: bytes, as: UTF8.self)
}

func tarOctal(_ d: Data, _ base: Int, _ off: Int, _ len: Int) throws -> Int {
    var v = 0, seen = false
    for i in 0..<len {
        let b = d[base + off + i]
        if b == 0 || b == 0x20 { if seen { break }; continue }
        guard (0x30...0x37).contains(b) else { throw Fail("tar: malformed numeric field (base-256 and non-octal are unsupported)") }
        v = v &* 8 &+ Int(b &- 0x30)
        seen = true
        guard v <= 1 << 40 else { throw Fail("tar: numeric field out of range") }
    }
    return v
}

func checkTarName(_ name: String) throws {
    guard !name.isEmpty else { throw Fail("tar: empty entry name") }
    guard !name.hasPrefix("/") else { throw Fail("tar: absolute path \(name) refused") }
    let parts = name.split(separator: "/", omittingEmptySubsequences: false)
    guard parts.allSatisfy({ $0 != "." && $0 != ".." && !$0.isEmpty }) else { throw Fail("tar: path \(name) is not normalized") }
}

func parseTar(_ tar: Data) throws -> [String: TarEntry] {
    let base = tar.startIndex
    var entries: [String: TarEntry] = [:]
    var off = 0, total = 0, ended = false
    guard tar.count % 512 == 0 else { throw Fail("tar: length is not block aligned") }
    while off + 512 <= tar.count {
        var blank = true
        for i in 0..<512 where tar[base + off + i] != 0 { blank = false; break }
        if blank {
            guard off + 1024 <= tar.count, tar.dropFirst(off).allSatisfy({ $0 == 0 }) else { throw Fail("tar: invalid end marker or trailing data") }
            ended = true
            break
        }
        var sum = 0
        for i in 0..<512 { sum += (148..<156).contains(i) ? 0x20 : Int(tar[base + off + i]) }
        guard try tarOctal(tar, base, off + 148, 8) == sum else { throw Fail("tar: header checksum mismatch at byte \(off)") }
        // Bytes 257..264 must be exactly ASCII "ustar", a NUL, then "00": a plain ustar
        // version field, so no GNU/glibc "ustar  \0" variant slips through.
        let magic = (0..<8).map { tar[base + off + 257 + $0] }
        guard Array(magic[0..<5]) == Array("ustar".utf8), magic[5] == 0x00, magic[6] == 0x30, magic[7] == 0x30
        else { throw Fail("tar: not a ustar archive (magic/version bytes 257-264)") }
        let type = tar[base + off + 156]
        switch type {
        case 0x30, 0x00, 0x35: break
        case 0x31: throw Fail("tar: hard link entry refused")
        case 0x32: throw Fail("tar: symlink entry refused")
        case 0x33, 0x34, 0x36: throw Fail("tar: device or fifo entry refused")
        case 0x37: throw Fail("tar: contiguous-file entry refused")
        case 0x78: throw Fail("tar: pax extended header refused (long names unsupported)")
        case 0x67: throw Fail("tar: pax global header refused")
        case 0x4C: throw Fail("tar: GNU long-name entry refused (long names unsupported)")
        case 0x4B: throw Fail("tar: GNU long-link entry refused (long names unsupported)")
        default: throw Fail("tar: unsupported entry type \(type)")
        }
        let size = try tarOctal(tar, base, off + 124, 12)
        var name = try tarName(tar, base, off, 100)
        let prefix = try tarName(tar, base, off + 345, 155)
        if !prefix.isEmpty { name = prefix + "/" + name }
        if type == 0x35 && name.hasSuffix("/") { name.removeLast() }
        try checkTarName(name)
        let allowedFile = name == "index.json" || name == "oci-layout" || matches(name, "^blobs/sha256/[0-9a-f]{64}$")
        let allowedDir = name == "blobs" || name == "blobs/sha256"
        guard type == 0x35 ? allowedDir : allowedFile else { throw Fail("tar: unexpected OCI path \(name)") }
        guard entries[name] == nil else { throw Fail("tar: duplicate entry \(name)") }
        guard entries.count < maxTarEntries else { throw Fail("tar: more than \(maxTarEntries) entries") }
        guard size <= 1 << 30 else { throw Fail("tar: entry \(name) claims \(size) bytes") }
        let data = off + 512, padded = (size + 511) / 512 * 512
        guard data + padded <= tar.count else { throw Fail("tar: entry \(name) is truncated") }
        total += size
        guard total <= 1 << 30 else { throw Fail("tar: contents exceed the archive cap") }
        entries[name] = TarEntry(isDir: type == 0x35, size: size, offset: data)
        off = data + padded
    }
    guard ended, !entries.isEmpty else { throw Fail("tar: missing end marker or no entries") }
    return entries
}

// Content addressing is checked for every blob, named or not: an archive cannot smuggle a
// planted blob under a digest it does not hash to.
func checkBlobNames(_ tar: Data, _ entries: [String: TarEntry]) throws {
    let base = tar.startIndex
    for (name, e) in entries where !e.isDir {
        let parts = name.split(separator: "/")
        guard parts.count == 3, parts[0] == "blobs", parts[1] == "sha256" else { continue }
        let want = String(parts[2])
        guard want.count == 64 else { throw Fail("oci: blobs/sha256/\(want) is not a sha256 hex name") }
        let got = sha256hex(tar[base + e.offset ..< base + e.offset + e.size])
        guard got == want.lowercased() else { throw Fail("oci: blob blobs/sha256/\(want) holds sha256:\(got)") }
    }
}

func tarJSON(_ tar: Data, _ e: TarEntry, _ max: Int, _ what: String) throws -> [String: Any] {
    guard e.size <= max else { throw Fail("\(what): \(e.size) bytes exceeds the \(max) byte cap") }
    let base = tar.startIndex
    let slice = tar[base + e.offset ..< base + e.offset + e.size]
    guard let o = try JSONSerialization.jsonObject(with: Data(slice)) as? [String: Any] else { throw Fail("\(what): not a JSON object") }
    return o
}

func checkDescriptor(_ d: Any, _ entries: [String: TarEntry], _ tar: Data, _ what: String) throws -> TarEntry {
    guard let o = d as? [String: Any], let digest = o["digest"] as? String else { throw Fail("\(what): descriptor without a digest") }
    guard digest.hasPrefix("sha256:"), digest.count == 71 else { throw Fail("\(what): digest \(digest) is not sha256:<64 hex>; only sha256 is supported") }
    guard let size = o["size"] as? Int, size >= 0 else { throw Fail("\(what): descriptor \(digest) has no usable size") }
    let name = "blobs/sha256/" + String(digest.dropFirst(7))
    guard let e = entries[name], !e.isDir else { throw Fail("\(what): blob \(name) is missing from the archive") }
    guard e.size == size else { throw Fail("\(what): blob \(name) is \(e.size) bytes, descriptor says \(size)") }
    let base = tar.startIndex
    let got = sha256hex(tar[base + e.offset ..< base + e.offset + e.size])
    guard "sha256:" + got == digest else { throw Fail("\(what): blob \(name) holds sha256:\(got)") }
    return e
}

func validateOCIArchive(_ tar: Data) throws -> String {
    let entries = try parseTar(tar)
    try checkBlobNames(tar, entries)
    guard let indexEntry = entries["index.json"], !indexEntry.isDir else { throw Fail("oci: index.json missing") }
    let index = try tarJSON(tar, indexEntry, maxIndexBytes, "index.json")
    let manifests = (index["manifests"] as? [Any]) ?? []
    guard manifests.count == 1, let m = manifests.first else { throw Fail("oci: index must hold exactly one manifest") }
    let manifestEntry = try checkDescriptor(m, entries, tar, "index manifest")
    let manifestTypes = ["application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"]
    if let mediaType = (m as? [String: Any])?["mediaType"] as? String, !manifestTypes.contains(mediaType) {
        throw Fail("oci: unsupported manifest mediaType \(mediaType)")
    }
    let manifest = try tarJSON(tar, manifestEntry, maxManifestBytes, "manifest")
    guard (manifest["schemaVersion"] as? Int) == 2 else { throw Fail("oci: manifest schemaVersion must be 2") }
    guard let cfg = manifest["config"] else { throw Fail("oci: manifest has no config descriptor") }
    _ = try checkDescriptor(cfg, entries, tar, "manifest config")
    let layers = (manifest["layers"] as? [Any]) ?? []
    guard (1...maxLayers).contains(layers.count) else { throw Fail("oci: manifest has \(layers.count) layers; 1-\(maxLayers) expected") }
    for (i, layer) in layers.enumerated() { _ = try checkDescriptor(layer, entries, tar, "layer \(i)") }
    if let layout = entries["oci-layout"], !layout.isDir {
        let o = try tarJSON(tar, layout, 4096, "oci-layout")
        guard (o["imageLayoutVersion"] as? String) == "1.0.0" else { throw Fail("oci: unsupported imageLayoutVersion") }
    }
    let p = manifestEntry
    return "sha256:" + sha256hex(tar[tar.startIndex + p.offset ..< tar.startIndex + p.offset + p.size])
}

// Everything below stages work assets inside this run's OUT and drops them again on every
// exit path. stdout.bin, stderr.bin and trace.jsonl are kept when a run fails; statement.json
// and assertion.cbor are written only on the success path, so a failure leaves no receipt.
// Keeps the first outputLimit bytes and flags anything beyond; a flagged run is reported incomplete, never as whole output.
final class Capture: Writer, @unchecked Sendable {
    let lock = NSLock(); var data = Data(), truncated = false
    func write(_ d: Data) throws { lock.withLock {
        if data.count + d.count > outputLimit { truncated = true }
        data.append(d.prefix(outputLimit - data.count))
    } }
    func close() throws {}
    var snapshot: (Data, Bool) { lock.withLock { (data, truncated) } }
}

let stdout = Capture(), stderr = Capture()

do {
    try checkCancellation()
    // The kernel is copied into the out dir and hashed from the bytes written; VZ boots that copy.
    let kernelBytes = try read(base.appendingPathComponent("vmlinux-arm64").path, max: 1 << 26)
    guard sha256hex(kernelBytes) == kernelSHA256 else { throw Fail("kernel sha256 \(sha256hex(kernelBytes)) != \(kernelSHA256)") }
    let kernel = own(out.appendingPathComponent("vmlinux-arm64"))
    try kernelBytes.write(to: kernel)
    try trace("kernel_measured", ["kernel_sha256": kernelSHA256])

    // A fresh per-run image store in OUT/work. MAR_BASE/store is never opened, so a preplanted
    // persistent CAS or rootfs cannot be reused for this run.
    let work = own(out.appendingPathComponent("work"))
    try FileManager.default.createDirectory(at: work, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    let storePath = work.appendingPathComponent("store")
    try? FileManager.default.createDirectory(at: storePath, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: storePath.path)
    let store = try ImageStore(path: storePath)

    // The archive is staged into the fresh out dir and read back only from those bytes; the
    // caller's file is not reopened.
    let ociBytes = try read(a[5], max: 1 << 30)
    let ociStaged = own(out.appendingPathComponent("image.oci.tar"))
    try ociBytes.write(to: ociStaged)
    let manifestDigest = try validateOCIArchive(ociBytes)
    guard config.image.hasSuffix("@" + manifestDigest) else { throw Fail("OCI manifest digest \(manifestDigest) does not match \(config.image)") }
    let layout = own(out.appendingPathComponent("oci-layout"))
    _ = try ArchiveReader(file: ociStaged).extractContents(to: layout)
    let loaded = try await store.load(from: layout)
    try checkCancellation()
    // APP-SCOPE-01 (APP-RETENTION-BOUNDARY-DECISION.json "APP01"): the legacy
    // `FileManager.default.removeItem(at: layout)` here was an automatic, pathname-
    // based deletion of a same-UID scratch target with no enforced ownership
    // boundary (0700/random names are not a same-user exclusion). Under
    // NATIVE-NONDESTRUCTIVE-CLEANUP-DECISION.json the signed app must not
    // destructively unlink an uncertain same-UID namespace target, so the deletion
    // is removed. `layout` is already registered via own() above, so it is preserved
    // and reported as deferred/unconfirmed residue by dropScratch() on every exit
    // path (the actual non-destructive cleanup boundary). No namespace exclusion is
    // invented; a possible host replacement at this pathname survives unmolested.
    guard loaded.count == 1 else { throw Fail("OCI archive holds \(loaded.count) images; expected 1") }
    let manifests = try await loaded[0].index().manifests
    guard manifests.count == 1, manifests[0].digest == manifestDigest else { throw Fail("OCI manifest digest does not match \(config.image)") }
    _ = try await store.tag(existing: loaded[0].reference, new: config.image)
    try trace("image_loaded", ["oci_archive_sha256": sha256hex(ociBytes), "manifest_digest": manifestDigest])

    // Fresh initfs per run. The pinned vminit may be fetched by the library into this run's
    // fresh store; initialization is not yet fully offline. See README.
    let initfsURL = own(out.appendingPathComponent("initfs.ext4"))
    let initfs = try await store.getInitImage(reference: initfsReference).initBlock(at: initfsURL, for: .linuxArm)
    try checkCancellation()
    let initfsSHA = sha256hex(try Data(contentsOf: initfsURL))
    try trace("initfs_built", ["initfs_reference": initfsReference, "initfs_sha256": initfsSHA])

    struct Stdin: ReaderStream { let s: AsyncStream<Data>; func stream() -> AsyncStream<Data> { s } }
    let input = try read(a[6], max: 1 << 24)
    let (stdinStream, stdinInput) = AsyncStream.makeStream(of: Data.self)
    stdinInput.yield(input)
    stdinInput.finish()
    try trace("input_staged", ["input_sha256": sha256hex(input), "input_bytes": input.count])

    var manager = try ContainerManager(kernel: Kernel(path: kernel, platform: .linuxArm), initfs: initfs, root: store.path)
    let id = "mar-" + UUID().uuidString.lowercased()
    let observed = Mutex<(Int, [String])>((-1, []))
    let container = try await manager.create(id, reference: config.image, rootfsSizeInBytes: 1024.mib(), networking: false) { c in
        c.cpus = config.cpus
        c.memoryInBytes = UInt64(config.memory_mib).mib()
        c.process.arguments = config.argv
        // Deterministic replacement, not append: any base-image variable whose name a config
        // entry names is dropped first, so the configured value always wins and each NAME
        // appears exactly once, in config order after the surviving base entries.
        let configuredNames = Set(envNames)
        c.process.environmentVariables =
            c.process.environmentVariables.filter { !configuredNames.contains($0.prefix { $0 != "=" }) } + config.env
        c.process.stdin = Stdin(s: stdinStream)
        c.process.stdout = stdout
        c.process.stderr = stderr
        if let hostSocket {
            c.sockets = [UnixSocketConfiguration(source: hostSocket, destination: URL(fileURLWithPath: guestSocket), permissions: FilePermissions(rawValue: socketMode))]
        }
        guard c.interfaces.isEmpty else { throw Fail("guest would get a network interface: \(c.interfaces)") }
        guard c.sockets.map(\.destination.path) == (hostSocket == nil ? [] : [guestSocket]) else { throw Fail("unexpected guest sockets \(c.sockets)") }
        observed.withLock { $0 = (c.interfaces.count, c.sockets.map(\.destination.path)) }
    }
    let (interfaces, sockets) = observed.withLock { $0 }
    let isolation: [String: Any] = ["networking": false, "interfaces": interfaces, "sockets": sockets.map { ["destination": $0, "mode": Int(socketMode)] as [String: Any] }]
    // The guest is ours from here on: whatever happens, it is stopped, killed if needed, and
    // deleted before this run's scratch store is dropped.
    var watchdog: Task<Void, Never>? = nil
    var waiter: Task<Void, Never>? = nil
    var observedExitCode: Int? = nil
    var observedReason: String? = nil
    do {
        try checkCancellation()
        try await container.create()
        try checkCancellation()
        try trace("vm_created", isolation.merging(["cpus": config.cpus, "memory_mib": config.memory_mib]) { x, _ in x })
        try checkCancellation()
        try await container.start()
        try checkCancellation()
        try trace("vm_started")
        // Unstructured tasks report through a first-result stream. A task group would
        // wait for a non-cooperative losing child and could itself hang during cancellation.
        let (exitEvents, result) = AsyncThrowingStream<Int, Error>.makeStream()
        waiter = Task {
            do {
                let status = try await container.wait()
                result.yield(Int(status.exitCode))
                result.finish()
            } catch { result.finish(throwing: error) }
        }
        watchdog = Task {
            do {
                let deadline = ContinuousClock.now + .seconds(config.timeout_seconds)
                while true {
                    if signalReason.withLock({ $0 != nil }) || FileManager.default.fileExists(atPath: out.appendingPathComponent("cancel.request").path) {
                        throw Fail("execution cancelled")
                    }
                    let reason: String? = ContinuousClock.now >= deadline ? "timeout" :
                        (stdout.snapshot.1 || stderr.snapshot.1) ? "output_limit" : nil
                    if let reason {
                        try Task.checkCancellation()
                        stopReason.withLock { $0 = reason }
                        try Task.checkCancellation()
                        try await container.kill(.kill)
                        return
                    }
                    try await Task.sleep(for: .milliseconds(100))
                }
            } catch {
                if !(error is CancellationError) { result.finish(throwing: error) }
            }
        }
        var iterator = exitEvents.makeAsyncIterator()
        guard let code = try await iterator.next() else { throw Fail("no observed exit status") }
        observedExitCode = code
        watchdog?.cancel()
        waiter?.cancel()
        // A cancellation observed concurrently with natural exit still suppresses a receipt.
        guard signalReason.withLock({ $0 == nil }), !FileManager.default.fileExists(atPath: out.appendingPathComponent("cancel.request").path)
        else { throw Fail("execution cancelled") }
        let reason = stopReason.withLock { $0 } ?? "exited"
        observedReason = reason
        try trace("guest_exited", ["exit_code": code, "reason": reason])
        try await container.stop()
    } catch {
        watchdog?.cancel()
        waiter?.cancel()
        try? await container.kill(.kill)
        try? await container.stop()
        try? manager.delete(id)
        note("guest \(id) after failure: \(error)")
        throw error
    }
    try manager.delete(id)
    guard let exitCode = observedExitCode else { throw Fail("guest has no observed exit status") }
    guard let reason = observedReason else { throw Fail("guest has no observed termination reason") }
    let ((so, soCut), (se, seCut)) = (stdout.snapshot, stderr.snapshot)
    let outcome = reason == "exited" && !soCut && !seCut ? "complete" : "incomplete"
    try trace("vm_stopped")
    try save("stdout.bin", so)
    try save("stderr.bin", se)
    try save("trace.jsonl", traceLines)

    let statement = try canonical([
        "domain": "minimal-attested-run/1",
        "challenge": runChallenge,
        "key_id": keyId,
        "config_sha256": sha256hex(configBytes),
        "pins": ["kernel_sha256": kernelSHA256, "initfs_reference": initfsReference, "initfs_sha256": initfsSHA],
        "image": ["reference": config.image, "manifest_digest": manifestDigest, "oci_archive_sha256": sha256hex(ociBytes)],
        "input": ["sha256": sha256hex(input), "bytes": input.count],
        "isolation": isolation,
        "output": ["limit_bytes": outputLimit, "stdout_sha256": sha256hex(so), "stdout_bytes": so.count, "stdout_truncated": soCut,
                   "stderr_sha256": sha256hex(se), "stderr_bytes": se.count, "stderr_truncated": seCut],
        "outcome": outcome,
        "termination": ["exit_code": exitCode, "reason": reason],
        "trace": ["head": head, "events": seq],
    ] as [String: Any])
    guard signalReason.withLock({ $0 == nil }), !FileManager.default.fileExists(atPath: out.appendingPathComponent("cancel.request").path)
    else { throw Fail("execution cancelled before assertion") }
    let assertion = try await svc.generateAssertion(keyId, clientDataHash: Data(SHA256.hash(data: statement)))
    guard signalReason.withLock({ $0 == nil }), !FileManager.default.fileExists(atPath: out.appendingPathComponent("cancel.request").path)
    else { throw Fail("execution cancelled before publication") }
    try save("keyId.txt", Data(keyId.utf8))
    try save("assertion.cbor", assertion)
    try save("statement.json", statement)
    dropScratch()
    runFinished.withLock { $0 = true }
} catch {
    // Evidence first, then the scratch assets: what was observed stays, nothing that looks
    // like a result is written, and the guest and work store do not outlive the run.
    try? save("stdout.bin", stdout.snapshot.0)
    try? save("stderr.bin", stderr.snapshot.0)
    try? save("trace.jsonl", traceLines)
    note("run failed: \(error)")
    dropScratch()
    runFinished.withLock { $0 = true }
    throw error
}
