import CryptoKit
import DeviceCheck
import Foundation
import Synchronization

// mar enroll <out> <challenge>
// mar hvf-v3 <out> <session.json> <challenge> <keyId>
// Every statement field is computed here from bytes this process read or observed; nothing comes from argv but paths.

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

// Host-side diagnostics only, never part of the statement.
func note(_ s: String) { FileHandle.standardError.write(Data("mar: \(s)\n".utf8)) }

// A closed socket peer gives EPIPE instead of killing the process.
signal(SIGPIPE, SIG_IGN)

let a = CommandLine.arguments
let usageText = "usage: mar enroll <out> <challenge> | mar hvf-v3 <out> <session.json> <challenge> <keyId>"
if a.count >= 2, a[1] == "--help" || a[1] == "-h" {
    print(usageText)
    exit(0)
}
guard a.count >= 3 else { throw Fail(usageText) }
let out = URL(fileURLWithPath: a[2])
guard !FileManager.default.fileExists(atPath: out.path) else { throw Fail("\(out.path) already exists") }
// OUT must be a fresh final component under an existing parent, so performDurableRetention
// can fsync that parent and make the new OUT entry durable.
try FileManager.default.createDirectory(at: out, withIntermediateDirectories: false)
// 0700 keeps other users out; it is not a boundary against a process running as this same user.
try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: out.path)
func save(_ name: String, _ d: Data) throws { try d.write(to: out.appendingPathComponent(name), options: .atomic) }

func challenge(_ p: String) throws -> String {
    let c = try read(p, max: 32)
    guard c.count == 32 else { throw Fail("challenge must be 32 bytes, got \(c.count)") }
    return hex(c)
}

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

// Whole-run deadline: bounds stuck library or synchronous backend calls the cooperative
// cancellation checks cannot reach.
let setupAllowanceSeconds = 600
let runDeadline = Mutex<ContinuousClock.Instant?>(nil)
func setRunDeadline(_ instant: ContinuousClock.Instant) { runDeadline.withLock { $0 = instant } }

// SIGTERM/SIGINT: the default handlers are removed and Dispatch signal sources note the
// request in signalReason. Handlers run no async work; the watchdog's 100 ms poll picks the
// reason up and fails the run without publishing a receipt.
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

// If the run is still alive at the deadline, exit hard without writing a receipt.
Thread.detachNewThread {
    var cancelledAt: ContinuousClock.Instant? = nil
    while !runFinished.withLock({ $0 }) {
        if (signalReason.withLock({ $0 != nil }) || FileManager.default.fileExists(atPath: out.appendingPathComponent("cancel.request").path)) && cancelledAt == nil { cancelledAt = .now }
        let deadline = runDeadline.withLock { $0 }
        if deadline.map({ ContinuousClock.now >= $0 }) == true || cancelledAt.map({ ContinuousClock.now >= $0 + .seconds(10) }) == true {
            note("hard execution/cancellation deadline reached; exiting without a completed receipt")
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

if a[1] == "hvf-v3" {
    guard a.count == 6 else { throw Fail("hvf-v3 usage: mar hvf-v3 <out> <session.json> <challenge> <keyId>") }
    let svc = DCAppAttestService.shared
    guard svc.isSupported else { throw Fail("App Attest unsupported in this process; refusing to run") }
    setRunDeadline(started + .seconds(3600 + setupAllowanceSeconds))
    try await runHvFV3(out: out, sessionPath: a[3], challengeHex: try challenge(a[4]),
                       keyId: String(decoding: try read(a[5], max: 1024), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines))
    exit(0)
}
throw Fail(usageText)
