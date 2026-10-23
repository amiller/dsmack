// The NEW HVF control-profile statement (dsmack-hvf-control-statement/1) —
// the byte-exact Swift mirror of verifier/hvf_control.py (same schema, same
// canonical form, same receipt file set). The OLD dsmack-control-statement/1
// path (ControlEmit.writeEvidence) keeps serving the legacy VZ fixture profile
// unchanged.
//
// Contract: the host-observed statement is built AFTER the task ran and the VM
// tore down checked. It binds the approved actual boot pins, the task input,
// the RAW control transcript, the GUEST-SEALED root terminal record (spliced
// verbatim — its float timestamps must never pass through JSON re-
// serialization), the actual output / reconstructed result document / guest
// trace, the host's OWN trace + lifecycle, and the attest identity facts.
// The checker verdict is DERIVED here from the exact prompt bytes — never
// trusted, never hardcoded.
import Foundation

/// The deterministic public-task checker: recomputes the sha256 chain from the
/// EXACT task prompt bytes and compares with the observed stdout document.
public enum PublicTaskChecker {
    public static let kind = "dsmack-public-task-checker/1"
    public static let taskSchema = "dsmack-public-fixture/1"
    public static let resultSchema = "dsmack-public-fixture-result/1"

    public struct Verdict: Equatable {
        public let verdict: String        // pass | fail
        public let digest1: String
        public let digest2: String
        public let resultDocument: Data?  // canonical result.json bytes when pass
        public let promptBytes: Int
    }

    public static func verify(taskBytes: Data, stdout: Data) -> Verdict {
        func fail(_ d1: String = String(repeating: "0", count: 64),
                  _ d2: String = String(repeating: "0", count: 64)) -> Verdict {
            Verdict(verdict: "fail", digest1: d1, digest2: d2, resultDocument: nil, promptBytes: 0)
        }
        guard let task = (try? PyJSON.parse(taskBytes)) as? [String: Any],
              task["schema"] as? String == taskSchema,
              let prompt = task["prompt"] as? String, !prompt.isEmpty else {
            return fail()
        }
        let promptData = Data(prompt.utf8)
        let d1 = SHA256.hex(promptData)
        let d2 = SHA256.hex(Data(d1.utf8) + Data(":".utf8) + promptData)
        let expected: [String: Any] = ["schema": resultSchema, "task_schema": taskSchema,
                                       "prompt_bytes": promptData.count,
                                       "digest_1": d1, "digest_2": d2]
        guard stdout.count >= 1, stdout.last == 0x0a else { return fail(d1, d2) }
        let body = stdout.subdata(in: stdout.startIndex..<stdout.index(before: stdout.endIndex))
        guard let doc = (try? PyJSON.parse(body)) as? [String: Any],
          TerminalAuth.pyEqual(doc, expected), (try? PyJSON.canonical(doc)) == body else {
            return fail(d1, d2)
        }
        return Verdict(verdict: "pass", digest1: d1, digest2: d2,
                       resultDocument: body, promptBytes: promptData.count)
    }
}

/// The facts of one OBSERVED hvf-control run, all read/collected by this
/// process before the statement exists.
public struct HvFRunFacts {
    public let runId: String
    public let nonceHex: String
    public let counter: Int                      // predicted assertion counter
    public let runChallenge: Data
    public let taskBytes: Data
    public let controlRecording: Data            // RAW retained guest->host stream
    public let controlFrames: Int
    public let terminalPayload: Data             // root terminal record, VERBATIM bytes
    public let stdout: Data
    public let stderr: Data
    public let guestTrace: Data                  // the sealed guest workload trace
    public let hostTraceLines: Data              // the host's OWN trace chain bytes
    public let hostTraceHead: String
    public let hostTraceEvents: Int
    public let framesIn: Int                     // host->guest frames actually sent
    public let bytesIn: Int
    public let manifestSHA256: String            // approved actual boot manifest digest
    public let pins: [String: String]            // kernel/initrd/disk/cmdline/archive sha256
    public let ctlAbiVersion: Int

    public init(runId: String, nonceHex: String, counter: Int, runChallenge: Data,
                taskBytes: Data, controlRecording: Data, controlFrames: Int,
                terminalPayload: Data, stdout: Data, stderr: Data, guestTrace: Data,
                hostTraceLines: Data, hostTraceHead: String, hostTraceEvents: Int,
                framesIn: Int, bytesIn: Int,
                manifestSHA256: String, pins: [String: String], ctlAbiVersion: Int) {
        self.runId = runId; self.nonceHex = nonceHex; self.counter = counter
        self.runChallenge = runChallenge; self.taskBytes = taskBytes
        self.controlRecording = controlRecording; self.controlFrames = controlFrames
        self.terminalPayload = terminalPayload; self.stdout = stdout; self.stderr = stderr
        self.guestTrace = guestTrace; self.hostTraceLines = hostTraceLines
        self.hostTraceHead = hostTraceHead; self.hostTraceEvents = hostTraceEvents
        self.framesIn = framesIn; self.bytesIn = bytesIn
        self.manifestSHA256 = manifestSHA256; self.pins = pins
        self.ctlAbiVersion = ctlAbiVersion
    }
}

public enum HvFControlEmitError: Error, Equatable {
    case uncleanStream(terminalFrames: Int, postTerminalBytes: Int)
    case checkerFailed
    case terminalArtifactMismatch
    case badFact(String)
    case emptyFact(String)
}

public enum HvFControlEmit {
    public static let schema = "dsmack-hvf-control-statement/1"
    public static let profile = "dsmack-owned-boot-verity-hvf/1"

    /// Read-once validated RAW run-challenge bytes. The statement's
    /// run_challenge_sha256 commits to THESE bytes — the verifier's own
    /// challenge file — never to their hex rendering: hashing the hex text
    /// instead was repair2 finding R2-A2-CHALLENGE (two different digests,
    /// the receipt could never verify).
    public static func validatedRunChallenge(atPath path: String, byteCount: Int = 32) throws -> Data {
        guard let handle = try? FileHandle(forReadingFrom: URL(fileURLWithPath: path)) else {
            throw HvFControlEmitError.badFact("run challenge unreadable: \(path)")
        }
        defer { try? handle.close() }
        let d = (try? handle.read(upToCount: byteCount + 1)) ?? Data()
        guard d.count == byteCount else {
            throw HvFControlEmitError.badFact(
                "run challenge must be \(byteCount) bytes, got \(d.count)")
        }
        return d
    }
    /// Exactly the files a completed receipt holds; the app layer adds
    /// keyId.txt, assertion.cbor, enroll-client-data.bin, enrollment.cbor.
    public static let libraryFiles = ["boot_manifest.json", "control.rec", "control_statement.json",
                                      "guest-trace.log", "host-trace.jsonl", "lifecycle.jsonl",
                                      "result.json", "stderr.bin", "stdout.bin", "terminal.json"]
    public static let receiptFiles = libraryFiles + ["assertion.cbor", "enroll-client-data.bin",
                                                     "enrollment.cbor", "keyId.txt"]

    /// Validate the observed facts, run the checker, write the receipt core,
    /// and return the exact control-statement bytes (the bytes the App Attest
    /// assertion must cover). All validation happens BEFORE the first write.
    /// `stopReason` is the CALLER'S CHECKED teardown observation (F7): this
    /// emitter never manufactures one during serialization — it only records
    /// what the flow verified, and refuses anything but a guest-requested
    /// stop (host halt is not success authority; mirrors the verifier rule).
    public static func writeReceipt(into dir: URL, recorder: LifecycleRecorder,
                                    keyId: String, appId: String,
                                    facts: HvFRunFacts,
                                    stopReason: String) throws -> Data {
        // 1. Stream truth (structure only; the HMAC check is the app-internal
        //    TerminalAuth step, already performed on these same bytes).
        let scan = try DSMX.scanGuestStream(facts.controlRecording)
        guard scan.terminalFrames == 1, scan.postTerminalBytes == 0 else {
            throw HvFControlEmitError.uncleanStream(terminalFrames: scan.terminalFrames,
                                                    postTerminalBytes: scan.postTerminalBytes)
        }
        guard !facts.terminalPayload.isEmpty, !facts.hostTraceLines.isEmpty,
              !facts.hostTraceHead.isEmpty, !facts.manifestSHA256.isEmpty else {
            throw HvFControlEmitError.emptyFact("facts")
        }
        for (k, v) in facts.pins {
            guard v.count == 64 else { throw HvFControlEmitError.badFact("pin \(k)") }
        }
        // 2. The guest terminal record seals exactly the single result.json
        //    artifact over the stdout this process collected; the checker
        //    verdict is derived from the exact prompt bytes.
        guard let record = (try? PyJSON.parse(facts.terminalPayload)) as? [String: Any],
              record["status"] as? String == "completed",
              record["exit_status"] as? Int == 0 else {
            throw HvFControlEmitError.checkerFailed
        }
        let verdict = PublicTaskChecker.verify(taskBytes: facts.taskBytes, stdout: facts.stdout)
        guard verdict.verdict == "pass", let resultDoc = verdict.resultDocument else {
            throw HvFControlEmitError.checkerFailed
        }
        let guestTraceEvents = guestTraceEventCount(facts.guestTrace)
        guard guestTraceEvents >= 1 else { throw HvFControlEmitError.badFact("guest_trace") }
        // 3. Host lifecycle: channel closed, artifacts over the exact bytes
        //    about to be written, device closed, VM stopped — the teardown
        //    rows carry the caller's checked observation, never a literal
        //    invented here (F7).
        guard stopReason == "guest-requested" else {
            throw HvFControlEmitError.badFact("stop_reason \(stopReason) is not guest-requested")
        }
        try recorder.channelClosed(framesIn: facts.framesIn, bytesIn: facts.bytesIn,
                                   framesOut: scan.frames, bytesOut: scan.bytes,
                                   terminalFrames: scan.terminalFrames,
                                   postTerminalBytes: scan.postTerminalBytes)
        try recorder.artifactsCollected(files: [
            ("guest-trace.log", SHA256.hex(facts.guestTrace), facts.guestTrace.count),
            ("result.json", SHA256.hex(resultDoc), resultDoc.count),
            ("stderr.bin", SHA256.hex(facts.stderr), facts.stderr.count),
            ("stdout.bin", SHA256.hex(facts.stdout), facts.stdout.count),
        ])
        try recorder.deviceClosed()
        try recorder.vmStopped(stopReason: stopReason)

        // 4. The statement, over the final lifecycle head, with the guest-sealed
        //    terminal record spliced in VERBATIM.
        let statement = try buildStatement(keyId: keyId, appId: appId, facts: facts,
                                           verdict: verdict, resultDoc: resultDoc,
                                           guestTraceEvents: guestTraceEvents,
                                           recorder: recorder)

        // 5. Everything validated — write the receipt core.
        try write("stdout.bin", facts.stdout, into: dir)
        try write("stderr.bin", facts.stderr, into: dir)
        try write("guest-trace.log", facts.guestTrace, into: dir)
        try write("result.json", resultDoc, into: dir)
        try write("control.rec", facts.controlRecording, into: dir)
        try write("terminal.json", facts.terminalPayload, into: dir)
        try write("host-trace.jsonl", facts.hostTraceLines, into: dir)
        try write("lifecycle.jsonl", recorder.lines, into: dir)
        let bootManifest: [String: Any] = ["profile": profile,
                                           "kernel_sha256": facts.pins["kernel_sha256"] ?? "",
                                           "initrd_sha256": facts.pins["initrd_sha256"] ?? "",
                                           "disk_sha256": facts.pins["disk_sha256"] ?? "",
                                           "cmdline_sha256": facts.pins["cmdline_sha256"] ?? "",
                                           "archive_sha256": facts.pins["archive_sha256"] ?? "",
                                           "manifest_sha256": facts.manifestSHA256]
        try write("boot_manifest.json", try ControlJSON.canonical(bootManifest), into: dir)
        try write("control_statement.json", statement, into: dir)
        return statement
    }

    /// Byte-exact mirror of hvf_control.build: same keys, same canonical form,
    /// same raw-bytes splice of the guest terminal record.
    static func buildStatement(keyId: String, appId: String, facts: HvFRunFacts,
                               verdict: PublicTaskChecker.Verdict,
                               resultDoc: Data, guestTraceEvents: Int,
                               recorder: LifecycleRecorder) throws -> Data {
        guard let recordObj = (try? PyJSON.parse(facts.terminalPayload)) as? [String: Any] else {
            throw HvFControlEmitError.badFact("terminal record unparseable")
        }
        guard let resultObj = (try? PyJSON.parse(resultDoc)) as? [String: Any],
              let promptBytes = resultObj["prompt_bytes"] as? Int,
              let docD1 = resultObj["digest_1"] as? String,
              let docD2 = resultObj["digest_2"] as? String,
              resultObj["schema"] as? String == PublicTaskChecker.resultSchema else {
            throw HvFControlEmitError.badFact("result document")
        }
        let pins = facts.pins
        let obj: [String: Any] = [
            "schema": schema,
            "profile": profile,
            "identity": ["key_id": keyId, "app_id": appId],
            "run": ["run_id": facts.runId, "nonce": facts.nonceHex, "counter": facts.counter,
                    "run_challenge_sha256": SHA256.hex(facts.runChallenge)],
            "environment": ["manifest_sha256": facts.manifestSHA256,
                            "kernel_sha256": pins["kernel_sha256"] ?? "",
                            "initrd_sha256": pins["initrd_sha256"] ?? "",
                            "disk_sha256": pins["disk_sha256"] ?? "",
                            "cmdline_sha256": pins["cmdline_sha256"] ?? "",
                            "archive_sha256": pins["archive_sha256"] ?? "",
                            "ctl_abi_version": facts.ctlAbiVersion],
            "task": ["sha256": SHA256.hex(facts.taskBytes), "bytes": facts.taskBytes.count],
            "transcript": ["control_sha256": SHA256.hex(facts.controlRecording),
                           "control_bytes": facts.controlRecording.count,
                           "control_frames": facts.controlFrames,
                           "terminal_sha256": SHA256.hex(facts.terminalPayload)],
            "terminal": ["record": "HVFTERMINALRECORDPLACEHOLDER"],
            "guest": ["trace_sha256": SHA256.hex(facts.guestTrace),
                      "trace_bytes": facts.guestTrace.count,
                      "trace_events": guestTraceEvents],
            "output": ["stdout": ["sha256": SHA256.hex(facts.stdout), "bytes": facts.stdout.count],
                       "stderr": ["sha256": SHA256.hex(facts.stderr), "bytes": facts.stderr.count]],
            "result": ["sha256": SHA256.hex(resultDoc), "bytes": resultDoc.count,
                       "schema": PublicTaskChecker.resultSchema,
                       "prompt_bytes": promptBytes, "digest_1": docD1, "digest_2": docD2],
            "outcome": ["status": "completed", "exit_status": 0,
                        "termination_reason": "exited",
                        "checker": ["kind": PublicTaskChecker.kind, "verdict": verdict.verdict,
                                    "digest_1": verdict.digest1, "digest_2": verdict.digest2]],
            "host_trace": ["head": facts.hostTraceHead, "events": facts.hostTraceEvents],
            "lifecycle": ["head": recorder.head, "events": recorder.events],
        ]
        var raw = try ControlJSON.canonical(obj)
        guard let markerRange = raw.range(of: Data("\"HVFTERMINALRECORDPLACEHOLDER\"".utf8)) else {
            throw HvFControlEmitError.badFact("record marker")
        }
        raw.replaceSubrange(markerRange, with: facts.terminalPayload)
        return raw
    }

    static func guestTraceEventCount(_ data: Data) -> Int {
        guard !data.isEmpty else { return 0 }
        return data.filter { $0 == 0x0a }.count
    }

    static func write(_ name: String, _ bytes: Data, into dir: URL) throws {
        try bytes.write(to: dir.appendingPathComponent(name), options: .atomic)
    }
}
