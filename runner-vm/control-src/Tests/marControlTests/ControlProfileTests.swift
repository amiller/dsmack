// Control-profile emit-path unit tests. The expected bytes come from
// GoldenVectors.swift, generated from tests/golden/control-profile.json, whose
// contents were produced AND accepted by the real sibling-lane code (verifier
// parser + channel codec). If any assertion here fails, the Swift emit path has
// drifted from the contract — that is a bug here, never a reason to regenerate
// the golden bytes to match.
import XCTest
@testable import marControl

final class ControlProfileTests: XCTestCase {

    // MARK: digests and CRC

    func testCRC32KnownAnswer() {
        XCTAssertEqual(CRC32.checksum("123456789".utf8), Golden.crc32KnownAnswer)
        XCTAssertEqual(CRC32.checksum(Golden.stdout), Golden.crc32Stdout)
        XCTAssertEqual(CRC32.checksum(Golden.terminalPayload), Golden.crc32TerminalPayload)
    }

    func testSHA256Golden() {
        XCTAssertEqual(SHA256.hex(Golden.task), Golden.taskSHA256)
        XCTAssertEqual(SHA256.hex(Data()), Golden.sha256Empty)
        // the trace chain rule, exercised on the golden trace bytes
        var head = String(repeating: "0", count: 64)
        for line in Golden.traceLines.split(separator: 0x0a) {
            head = SHA256.hex(Data(head.utf8) + line)
        }
        XCTAssertEqual(head, Golden.traceHead)
    }

    // MARK: host frame encoding is wire-identical to the channel lane's codec

    func testEncodeHostFrameMatchesRealCodec() throws {
        let sessionStart = try DSMX.encodeHostFrame(kind: .sessionStart, payload: Golden.sessionStartPayload)
        XCTAssertEqual(sessionStart, Golden.sessionStartFrame)
        let taskInput = try DSMX.encodeHostFrame(kind: .taskInput, payload: Golden.taskInputPayload)
        XCTAssertEqual(taskInput, Golden.taskInputFrame)
    }

    func testEncodeRejectsWrongDirectionAndOversize() {
        XCTAssertThrowsError(try DSMX.encodeHostFrame(kind: .resultTerminal, payload: Data()))
        XCTAssertThrowsError(try DSMX.encodeHostFrame(kind: .outputChunk, payload: Data()))
        XCTAssertThrowsError(try DSMX.encodeHostFrame(kind: .taskInput, payload: Data(count: DSMX.defaultMaxRecord + 1)))
    }

    // MARK: guest-stream scanning (structure only; CRC/HMAC stay with the verifier)

    func testScanGoldenControlRec() throws {
        let scan = try DSMX.scanGuestStream(Golden.controlRec)
        XCTAssertEqual(scan.frames, 4)
        XCTAssertEqual(scan.bytes, Golden.controlRec.count)
        XCTAssertEqual(scan.terminalFrames, 1)
        XCTAssertEqual(scan.postTerminalBytes, 0)
    }

    func testScanFailClosed() throws {
        XCTAssertThrowsError(try DSMX.scanGuestStream(Golden.controlRec.dropLast(3)))           // truncated body
        XCTAssertThrowsError(try DSMX.scanGuestStream(Data("XXXX".utf8) + Golden.controlRec.dropFirst(4)))
        XCTAssertThrowsError(try DSMX.scanGuestStream(Golden.sessionStartFrame))                 // host->guest kind
        var oversize = Golden.controlRec.prefix(8)                                              // keep DSMX+v1+kind1
        oversize.append(Data([0xff, 0xff, 0xff, 0xff]))                                          // u32be length
        XCTAssertThrowsError(try DSMX.scanGuestStream(Data(oversize)))
        // any byte after the terminal is counted, never accepted
        let post = try DSMX.scanGuestStream(Golden.controlRec + Data([0x00]))
        XCTAssertEqual(post.postTerminalBytes, 1)
    }

    func testRetainerLiveFeedStopsAtTerminal() throws {
        let retainer = ControlRetainer()
        var odd = 1
        var off = Golden.controlRec.startIndex
        while off < Golden.controlRec.endIndex {           // feed in irregular chunks
            let n = min(odd, Golden.controlRec.distance(from: off, to: Golden.controlRec.endIndex))
            try retainer.feed(Golden.controlRec.subdata(in: off..<Golden.controlRec.index(off, offsetBy: n)))
            off = Golden.controlRec.index(off, offsetBy: n); odd = odd % 7 + 1
        }
        try retainer.close()
        XCTAssertEqual(retainer.retained, Golden.controlRec)
        XCTAssertEqual(retainer.frames, 4)
        XCTAssertEqual(retainer.terminalFrames, 1)
        XCTAssertEqual(retainer.postTerminalBytes, 0)
    }

    func testRetainerFailsClosed() throws {
        let after = ControlRetainer()
        try after.feed(Golden.controlRec)
        XCTAssertThrowsError(try after.feed(Data([0x00])))       // byte after terminal
        let noTerminal = ControlRetainer()
        let terminalFrameLength = 16 + Golden.terminalPayload.count + 4
        try noTerminal.feed(Golden.controlRec.prefix(Golden.controlRec.count - terminalFrameLength))
        XCTAssertThrowsError(try noTerminal.close())             // missing terminal is never success
        let truncated = ControlRetainer()
        try truncated.feed(Golden.controlRec.prefix(20))
        XCTAssertThrowsError(try truncated.close())
    }

    // MARK: lifecycle record matches the verifier's schema and chain

    func testLifecycleStagesFieldsAndNoBooleans() throws {
        let recorder = LifecycleRecorder()
        try recorder.sessionStarted(runId: Golden.runId)
        try recorder.taskInputCommitted(taskSHA256: Golden.taskSHA256, taskBytes: Golden.taskBytes)
        try recorder.channelClosed(framesIn: Golden.framesIn, bytesIn: Golden.bytesIn,
                                   framesOut: 4, bytesOut: Golden.controlRec.count,
                                   terminalFrames: 1, postTerminalBytes: 0)
        try recorder.artifactsCollected(files: [("stderr.bin", SHA256.hex(Golden.stderr), Golden.stderr.count),
                                                ("statement.json", SHA256.hex(Golden.statement), Golden.statement.count),
                                                ("stdout.bin", SHA256.hex(Golden.stdout), Golden.stdout.count),
                                                ("trace.jsonl", SHA256.hex(Golden.traceLines), Golden.traceLines.count)])
        try recorder.deviceClosed()
        try recorder.vmStopped(stopReason: Golden.stopReason)
        XCTAssertEqual(recorder.events, 6)

        let objects = try recorder.lines.split(separator: 0x0a).map { try JSONSerialization.jsonObject(with: $0) as! [String: Any] }
        let stageOrder = ["session_started", "task_input_committed", "channel_closed",
                          "artifacts_collected", "device_closed", "vm_stopped"]
        let expected: [String: Set<String>] = [
            "session_started": ["run_id", "seq", "stage"],
            "task_input_committed": ["task_sha256", "task_bytes", "seq", "stage"],
            "channel_closed": ["frames_in", "bytes_in", "frames_out", "bytes_out",
                               "terminal_frames", "post_terminal_bytes", "seq", "stage"],
            "artifacts_collected": ["files", "seq", "stage"],
            "device_closed": ["endpoint", "close_kind", "seq", "stage"],
            "vm_stopped": ["stop_reason", "exit_path", "seq", "stage"],
        ]
        XCTAssertEqual(objects.map { $0["stage"] as! String }, stageOrder)
        for o in objects { XCTAssertEqual(Set(o.keys), expected[o["stage"] as! String]) }
        // boolean detection must not use `is Bool`: NSNumber bridging reports
        // true for integer 0/1 too. CFBoolean is the only real boolean.
        for o in objects where o["stage"] as! String != "artifacts_collected" {
            for v in o.values {
                if let n = v as? NSNumber {
                    XCTAssertFalse(CFGetTypeID(n) == CFBooleanGetTypeID(), "lifecycle events admit no boolean")
                }
            }
        }
        XCTAssertEqual(objects[4]["endpoint"] as! String, "unix:host-socket(0600)")
        XCTAssertEqual(objects[4]["close_kind"] as! String, "channel-eof")
        XCTAssertEqual(objects[5]["exit_path"] as! String, "returning")
    }

    func testLifecycleRejectsBadInputs() {
        let recorder = LifecycleRecorder()
        XCTAssertThrowsError(try recorder.sessionStarted(runId: "NOT-HEX"))
        XCTAssertThrowsError(try recorder.taskInputCommitted(taskSHA256: "abc", taskBytes: 1))
        XCTAssertThrowsError(try recorder.taskInputCommitted(taskSHA256: Golden.taskSHA256, taskBytes: -1))
        XCTAssertThrowsError(try recorder.channelClosed(framesIn: -1, bytesIn: 0, framesOut: 0,
                                                        bytesOut: 0, terminalFrames: 0, postTerminalBytes: 0))
        XCTAssertThrowsError(try recorder.artifactsCollected(files: [("x", "zz", 1)]))
    }

    // MARK: the full emit path reproduces the golden receipt bytes

    private func goldenAttest() -> ControlAttestFacts {
        ControlAttestFacts(keyId: Golden.keyId, appId: Golden.appId, nonceHex: Golden.nonce,
                           counter: Golden.counter, runChallenge: Golden.runChallenge,
                           exitStatus: 0, terminationReason: "exited",
                           checkerKind: Golden.checkerKind, checkerVerdict: "pass",
                           enrollClientData: Golden.enrollClientData,
                           enrollmentCbor: Golden.enrollmentCbor)
    }

    private func goldenFacts(recording: Data = Golden.controlRec) -> ControlRunFacts {
        ControlRunFacts(runId: Golden.runId, taskSHA256: Golden.taskSHA256,
                        taskBytes: Golden.taskBytes, framesIn: Golden.framesIn,
                        bytesIn: Golden.bytesIn, stopReason: Golden.stopReason,
                        stdout: Golden.stdout, stderr: Golden.stderr,
                        traceLines: Golden.traceLines, statement: Golden.statement,
                        controlRecording: recording, bootManifest: Golden.bootManifest)
    }

    func testEmitWritesExactGoldenBytes() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("marControlTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        let recorder = LifecycleRecorder()
        try recorder.sessionStarted(runId: Golden.runId)                       // live, at channel open
        try recorder.taskInputCommitted(taskSHA256: Golden.taskSHA256,         // live, when the task is staged
                                        taskBytes: Golden.taskBytes)
        let asserted = try ControlEmit.writeEvidence(into: dir, recorder: recorder,
                                                     facts: goldenFacts(), attest: goldenAttest())

        // assertion.cbor covers sha256(the control statement bytes), NOT statement.json
        XCTAssertEqual(asserted, Golden.controlStatement)
        XCTAssertEqual(recorder.lines, Golden.lifecycle)
        XCTAssertEqual(recorder.head, Golden.lifecycleHead)
        func read(_ n: String) throws -> Data { try Data(contentsOf: dir.appendingPathComponent(n)) }
        XCTAssertEqual(try read("stdout.bin"), Golden.stdout)
        XCTAssertEqual(try read("stderr.bin"), Golden.stderr)
        XCTAssertEqual(try read("trace.jsonl"), Golden.traceLines)
        XCTAssertEqual(try read("statement.json"), Golden.statement)
        XCTAssertEqual(try read("lifecycle.jsonl"), Golden.lifecycle)
        XCTAssertEqual(try read("control.rec"), Golden.controlRec)
        XCTAssertEqual(try read("boot_manifest.json"), Golden.bootManifest)
        XCTAssertEqual(try read("control_statement.json"), Golden.controlStatement)
        XCTAssertEqual(try read("enroll-client-data.bin"), Golden.enrollClientData)
        XCTAssertEqual(try read("enrollment.cbor"), Golden.enrollmentCbor)
        // exactly the library's 10 files: keyId.txt + assertion.cbor are the
        // app layer's, completing the verifier's 12-file CONTROL_FILES set
        let present = try FileManager.default.contentsOfDirectory(atPath: dir.path).sorted()
        XCTAssertEqual(present, ControlEmit.libraryFiles.sorted())
        try? FileManager.default.removeItem(at: dir)
    }

    func testControlStatementSchemaAndCommitments() throws {
        let obj = try JSONSerialization.jsonObject(with: Golden.controlStatement) as! [String: Any]
        XCTAssertEqual(Set(obj.keys), ["schema", "profile", "identity", "run", "environment", "task",
                                       "transcript", "outcome", "lifecycle", "output", "legacy_statement_sha256"])
        XCTAssertEqual(obj["schema"] as! String, "dsmack-control-statement/1")
        XCTAssertEqual(obj["profile"] as! String, "dsmack-owned-boot-verity-control/1")
        XCTAssertEqual(Set((obj["identity"] as! [String: Any]).keys), ["key_id", "app_id"])
        XCTAssertEqual(Set((obj["run"] as! [String: Any]).keys), ["run_id", "nonce", "counter", "run_challenge_sha256"])
        XCTAssertEqual(Set((obj["environment"] as! [String: Any]).keys), ["manifest_sha256"])
        XCTAssertEqual(Set((obj["transcript"] as! [String: Any]).keys),
                       ["trace_head", "trace_events", "terminal_sha256", "control_frames", "control_bytes"])
        XCTAssertEqual(Set((obj["outcome"] as! [String: Any]).keys),
                       ["status", "exit_status", "termination_reason", "checker"])
        XCTAssertEqual(Set(((obj["outcome"] as! [String: Any])["checker"] as! [String: Any]).keys), ["kind", "verdict"])
        XCTAssertEqual(Set((obj["lifecycle"] as! [String: Any]).keys), ["head", "events"])
        XCTAssertEqual(Set((obj["output"] as! [String: Any]).keys), ["stdout", "stderr"])
        // the signed statement commits to the FINAL lifecycle head/event count
        let lc = obj["lifecycle"] as! [String: Any]
        XCTAssertEqual(lc["head"] as! String, Golden.lifecycleHead)
        XCTAssertEqual(lc["events"] as! Int, 6)
        // ... the legacy statement, manifest and terminal payload digests
        XCTAssertEqual(obj["legacy_statement_sha256"] as! String, SHA256.hex(Golden.statement))
        let env = obj["environment"] as! [String: Any]
        XCTAssertEqual(env["manifest_sha256"] as! String, SHA256.hex(Golden.bootManifest))
        let tr = obj["transcript"] as! [String: Any]
        XCTAssertEqual(tr["terminal_sha256"] as! String, SHA256.hex(Golden.terminalPayload))
        XCTAssertEqual(tr["trace_head"] as! String, Golden.traceHead)
        // no boolean anywhere in the signed statement (`is Bool` is unusable:
        // NSNumber bridges integers 0/1 to Bool; only CFBoolean is a boolean)
        func noBool(_ v: Any) {
            if let n = v as? NSNumber {
                XCTAssertFalse(CFGetTypeID(n) == CFBooleanGetTypeID(), "boolean claim in signed statement")
            }
            if let d = v as? [String: Any] { d.values.forEach(noBool) }
            if let a = v as? [Any] { a.forEach(noBool) }
        }
        noBool(obj)
    }

    func testStatusBiconditional() {
        // 'completed' iff exit_status == 0 AND checker.verdict == 'pass'
        for (exit, verdict, want) in [(0, "pass", "completed"), (0, "fail", "failed"),
                                      (1, "pass", "failed"), (1, "fail", "failed")] {
            var a = goldenAttest()
            a = ControlAttestFacts(keyId: a.keyId, appId: a.appId, nonceHex: a.nonceHex,
                                   counter: a.counter, runChallenge: a.runChallenge,
                                   exitStatus: exit, terminationReason: a.terminationReason,
                                   checkerKind: a.checkerKind, checkerVerdict: verdict,
                                   enrollClientData: a.enrollClientData, enrollmentCbor: a.enrollmentCbor)
            let scan = try! DSMX.scanGuestStream(Golden.controlRec)
            let recorder = LifecycleRecorder()
            _ = try? recorder.sessionStarted(runId: Golden.runId)
            let cs = try! ControlEmit.buildControlStatement(facts: goldenFacts(), attest: a,
                                                            scan: scan, recorder: recorder)
            let obj = try! JSONSerialization.jsonObject(with: cs) as! [String: Any]
            let out = obj["outcome"] as! [String: Any]
            XCTAssertEqual(out["status"] as! String, want, "exit=\(exit) verdict=\(verdict)")
        }
    }

    func testEmitFailsClosedOnBadRetainedStream() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("marControlTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let recorder = LifecycleRecorder()
        try recorder.sessionStarted(runId: Golden.runId)
        try recorder.taskInputCommitted(taskSHA256: Golden.taskSHA256, taskBytes: Golden.taskBytes)
        XCTAssertThrowsError(try ControlEmit.writeEvidence(into: dir, recorder: recorder,
                                                           facts: goldenFacts(recording: Golden.controlRec + Data([0x00])),
                                                           attest: goldenAttest()))          // byte after terminal
        XCTAssertThrowsError(try ControlEmit.writeEvidence(into: dir, recorder: recorder,
                                                           facts: goldenFacts(recording: Golden.controlRec.dropLast(10)),
                                                           attest: goldenAttest()))          // truncated terminal
        XCTAssertThrowsError(try ControlEmit.writeEvidence(into: dir, recorder: recorder,
                                                           facts: goldenFacts(recording: Data()),
                                                           attest: goldenAttest()))          // nothing retained
        // The channel scan precedes every write, so a refused emit leaves no
        // receipt-like bytes behind at all.
        var left = try FileManager.default.contentsOfDirectory(atPath: dir.path).sorted()
        XCTAssertEqual(left, [])

        // Invalid attest facts are also refused before any write.
        var bad = goldenAttest()
        bad = ControlAttestFacts(keyId: bad.keyId, appId: bad.appId, nonceHex: "not-hex",
                                 counter: bad.counter, runChallenge: bad.runChallenge,
                                 exitStatus: bad.exitStatus, terminationReason: bad.terminationReason,
                                 checkerKind: bad.checkerKind, checkerVerdict: bad.checkerVerdict,
                                 enrollClientData: bad.enrollClientData, enrollmentCbor: bad.enrollmentCbor)
        XCTAssertThrowsError(try ControlEmit.writeEvidence(into: dir, recorder: recorder,
                                                           facts: goldenFacts(), attest: bad))
        bad = ControlAttestFacts(keyId: bad.keyId, appId: "no-dot", nonceHex: Golden.nonce,
                                 counter: 0, runChallenge: bad.runChallenge,
                                 exitStatus: bad.exitStatus, terminationReason: "crashed",
                                 checkerKind: bad.checkerKind, checkerVerdict: "maybe",
                                 enrollClientData: Data(), enrollmentCbor: bad.enrollmentCbor)
        XCTAssertThrowsError(try ControlEmit.writeEvidence(into: dir, recorder: recorder,
                                                           facts: goldenFacts(), attest: bad))
        left = try FileManager.default.contentsOfDirectory(atPath: dir.path).sorted()
        XCTAssertEqual(left, [])
        try? FileManager.default.removeItem(at: dir)
    }
}
