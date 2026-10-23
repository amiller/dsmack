// Astra-gate repair2 R2 tests: the ACTUAL success-path finalization the
// hvf-control executable calls (marControl.SessionFinalize.run), executed
// against a temporary run directory — not a library golden or a reimplementation:
//   * the frozen trace snapshot's file bytes == the lifecycle artifactsCollected
//     commitment == the summary trace head (one representation, re-derived here
//     from the saved bytes alone);
//   * the final `control_session_complete` event is INSIDE the committed/saved
//     trace (the repair1 defect committed a pre-event digest);
//   * console overflow is REFUSED (no prefix hash paired with a full count);
//   * the exact-limit console is accepted (no false rejection);
//   * every committed artifact file is written from exactly the committed bytes.
import XCTest
@testable import marControl

final class SessionFinalizeTests: XCTestCase {
    private let limit = 64

    private func tempDir(_ name: String) throws -> URL {
        let d = FileManager.default.temporaryDirectory
            .appendingPathComponent("sf-finalize-\(name)-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        return d
    }

    private func makeFacts(control: Data, stdout: Data, stderr: Data) -> SessionFinalizationFacts {
        let record = TerminalRecord(
            fields: ["output": ["exit_status": 0], "trace": ["head": String(repeating: "a", count: 64)]],
            status: "completed", exitStatus: 0, authenticatorHex: String(repeating: "0", count: 160),
            artifacts: [], provider: ["streams": 0, "bytes_up": 0, "bytes_down": 0])
        return SessionFinalizationFacts(
            runId: String(repeating: "5", count: 32), nonceHex: String(repeating: "7", count: 32),
            vmmCode: 0, framesIn: 2, bytesIn: 42, controlBytes: control,
            stdout: stdout, stderr: stderr, retainerFrames: 3, retainerBytes: control.count,
            terminalFrames: 1, postTerminalBytes: 0,
            terminalPayloadSHA256: SHA256.hex(control), terminalRecord: record,
            taskSHA256: SHA256.hex(Data("task".utf8)), taskBytesCount: 4,
            frameKinds: ["3": 3], challenge: String(repeating: "c", count: 64),
            keyId: "test-key", profile: ControlEmit.profile, statementSchema: ControlEmit.schema,
            backendArchiveSHA256: String(repeating: "b", count: 64), ctlAbiVersion: 1,
            pins: ["kernel_sha256": String(repeating: "k", count: 64),
                   "initrd_sha256": String(repeating: "i", count: 64),
                   "disk_sha256": String(repeating: "d", count: 64),
                   "cmdline_sha256": String(repeating: "m", count: 64)],
            runMs: 17, attestMissing: ["enrollment.cbor"], attestReason: "test reason")
    }

    /// The host-trace the app maintains: h_i = sha256(hex(h_{i-1}) ‖ canonical(event)).
    private final class HostTrace {
        private(set) var bytes = Data()
        private(set) var head = String(repeating: "0", count: 64)
        private(set) var events = 0
        func append(_ event: String, _ data: [String: Any]) throws {
            let line = try ControlJSON.canonical(data.merging(["seq": events, "event": event]) { x, _ in x })
            head = SHA256.hex(Data(head.utf8) + line)
            bytes += line + Data("\n".utf8)
            events += 1
        }
        var snapshot: SessionTraceSnapshot { SessionTraceSnapshot(bytes: bytes, head: head, events: events) }
    }

    /// Re-derive the head from saved bytes alone (independent of the app chain).
    private func headOfSavedTrace(_ bytes: Data) -> String {
        var head = String(repeating: "0", count: 64)
        for line in bytes.split(separator: UInt8(ascii: "\n")) {
            head = SHA256.hex(Data(head.utf8) + Data(line))
        }
        return head
    }

    private func artifactRows(in lifecycle: Data) throws -> [[Any]] {
        let rows = lifecycle.split(separator: UInt8(ascii: "\n")).map {
            (try? JSONSerialization.jsonObject(with: Data($0))) as? [String: Any] ?? [:]
        }
        let collected = rows.filter { ($0["stage"] as? String) == "artifacts_collected" }
        XCTAssertEqual(collected.count, 1, "exactly one artifacts_collected row")
        return collected[0]["files"] as? [[Any]] ?? []
    }

    private func row(_ rows: [[Any]], _ name: String) -> (sha: String, bytes: Int) {
        let hit = rows.first { ($0[0] as? String) == name }
        XCTAssertNotNil(hit, "artifact row for \(name)")
        return (hit![1] as! String, hit![2] as! Int)
    }

    private func run(_ facts: SessionFinalizationFacts, consolePath: String,
                     trace: HostTrace) throws -> (summary: Data, saved: [(String, Data)]) {
        var saved: [(String, Data)] = []
        let summary = try SessionFinalize.run(
            consolePath: consolePath, outputLimit: limit, facts: facts,
            appendFinalTrace: { () -> SessionTraceSnapshot in
                try trace.append("control_session_complete",
                                 ["vmm_code": Int(facts.vmmCode), "terminal_authenticated": true])
                return trace.snapshot
            },
            save: { name, data in saved.append((name, data)) })
        return (summary, saved)
    }

    private func summaryObject(_ data: Data) throws -> [String: Any] {
        try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    func testSuccessPathArtifactSetIsConsistent() throws {
        let dir = try tempDir("success")
        let consoleBytes = Data("guest console line\nsecond line\n".utf8)
        let consolePath = dir.appendingPathComponent("console-1.log").path
        try consoleBytes.write(to: dir.appendingPathComponent("console-1.log"))
        var trace = HostTrace()
        try trace.append("session_sent", ["frames_in": 2])   // pre-existing host events
        let facts = makeFacts(control: Data("control-stream-0123456789".utf8),
                              stdout: Data("out-bytes".utf8), stderr: Data("err-bytes".utf8))
        let (summary, saved) = try run(facts, consolePath: consolePath, trace: trace)

        // Every committed artifact is saved; console-1.log is not re-written by
        // the finalizer (the VMM already placed it at its final path).
        let byName = Dictionary<String, Data>(uniqueKeysWithValues: saved.map { ($0.0, $0.1) })
        XCTAssertEqual(Set(byName.keys),
                       ["control.rec", "stdout.bin", "stderr.bin", "trace.jsonl", "lifecycle.jsonl"])

        // trace.jsonl: saved bytes == frozen snapshot bytes, the final event is
        // inside them, and the head re-derives from the saved bytes alone.
        XCTAssertEqual(byName["trace.jsonl"], trace.snapshot.bytes)
        let savedTrace = try XCTUnwrap(byName["trace.jsonl"])
        XCTAssertTrue(String(decoding: savedTrace, as: UTF8.self).contains("control_session_complete"),
                      "the final trace event must be inside the committed trace")
        XCTAssertEqual(headOfSavedTrace(savedTrace), trace.snapshot.head)

        // lifecycle.jsonl: the artifacts_collected row commits exactly the
        // saved bytes (and the console file's exact bytes).
        let rows = try artifactRows(in: byName["lifecycle.jsonl"]!)
        XCTAssertEqual(rows.count, 5)
        XCTAssertEqual(row(rows, "control.rec").sha, SHA256.hex(facts.controlBytes))
        XCTAssertEqual(row(rows, "control.rec").bytes, facts.controlBytes.count)
        XCTAssertEqual(row(rows, "stdout.bin").sha, SHA256.hex(facts.stdout))
        XCTAssertEqual(row(rows, "stderr.bin").sha, SHA256.hex(facts.stderr))
        XCTAssertEqual(row(rows, "trace.jsonl").sha, SHA256.hex(savedTrace))
        XCTAssertEqual(row(rows, "trace.jsonl").bytes, savedTrace.count)
        XCTAssertEqual(row(rows, "console-1.log").sha, SHA256.hex(consoleBytes))
        XCTAssertEqual(row(rows, "console-1.log").bytes, consoleBytes.count)

        // Summary: trace block == frozen snapshot; lifecycle block == the
        // recorder over those same rows; channel counters echo the facts.
        let o = try summaryObject(summary)
        let traceBlock = try XCTUnwrap(o["trace"] as? [String: Any])
        XCTAssertEqual(traceBlock["head"] as? String, trace.snapshot.head)
        XCTAssertEqual(traceBlock["events"] as? Int, trace.snapshot.events)
        let lifecycleBlock = try XCTUnwrap(o["lifecycle"] as? [String: Any])
        let savedLifecycle = try XCTUnwrap(byName["lifecycle.jsonl"])
        XCTAssertEqual(lifecycleBlock["head"] as? String, headOfSavedLifecycle(savedLifecycle))
        XCTAssertEqual(lifecycleBlock["events"] as? Int,
                       savedLifecycle.split(separator: UInt8(ascii: "\n")).count)
        let channel = try XCTUnwrap(o["channel"] as? [String: Any])
        XCTAssertEqual(channel["frames_in"] as? Int, 2)
        XCTAssertEqual(channel["guest_frames"] as? Int, 3)
        let terminal = try XCTUnwrap(o["terminal"] as? [String: Any])
        XCTAssertEqual(terminal["authenticated"] as? Bool, true)
        XCTAssertEqual(terminal["status"] as? String, "completed")
        let attest = try XCTUnwrap(o["attest"] as? [String: Any])
        XCTAssertEqual(attest["status"] as? String, "waiting", "no admission claim without the signed-app gate")
    }

    /// Independent re-derivation of the lifecycle head from the saved lines.
    private func headOfSavedLifecycle(_ bytes: Data) -> String {
        var head = String(repeating: "0", count: 64)
        for line in bytes.split(separator: UInt8(ascii: "\n")) {
            head = SHA256.hex(Data(head.utf8) + Data(line))
        }
        return head
    }

    func testConsoleOverflowIsRefusedNotPrefixHashed() throws {
        let dir = try tempDir("overflow")
        let consolePath = dir.appendingPathComponent("console-1.log").path
        try Data(repeating: UInt8(ascii: "x"), count: limit + 1).write(to: dir.appendingPathComponent("console-1.log"))
        let trace = HostTrace()
        var saved: [(String, Data)] = []
        XCTAssertThrowsError(try SessionFinalize.run(
            consolePath: consolePath, outputLimit: limit,
            facts: makeFacts(control: Data([0x63]), stdout: Data(), stderr: Data()),
            appendFinalTrace: { () -> SessionTraceSnapshot in
                try trace.append("control_session_complete", ["vmm_code": 0])
                return trace.snapshot
            },
            save: { name, data in saved.append((name, data)) }))
        { error in
            guard case SessionFinalizeError.consoleOverflow(let bytes, let capped) = error else {
                return XCTFail("expected consoleOverflow, got \(error)")
            }
            XCTAssertEqual(bytes, self.limit + 1)
            XCTAssertEqual(capped, self.limit)
        }
        XCTAssertTrue(saved.isEmpty, "no artifact may be committed from an over-limit console")
    }

    func testExactLimitConsoleIsAccepted() throws {
        let dir = try tempDir("exact")
        let consolePath = dir.appendingPathComponent("console-1.log").path
        try Data(repeating: UInt8(ascii: "y"), count: limit).write(to: dir.appendingPathComponent("console-1.log"))
        let facts = makeFacts(control: Data([0x63]), stdout: Data(), stderr: Data())
        let (summary, saved) = try run(facts, consolePath: consolePath, trace: HostTrace())
        let byName = Dictionary<String, Data>(uniqueKeysWithValues: saved.map { ($0.0, $0.1) })
        let rows = try artifactRows(in: byName["lifecycle.jsonl"]!)
        XCTAssertEqual(row(rows, "console-1.log").bytes, limit)
        XCTAssertEqual(row(rows, "console-1.log").sha, SHA256.hex(Data(repeating: UInt8(ascii: "y"), count: limit)))
        XCTAssertEqual(try summaryObject(summary)["domain"] as? String, "dsmack-control-session/1")
    }
}
