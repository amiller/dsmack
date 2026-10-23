// Control-profile evidence emit path, aligned to
// ../verifier-repair/CONTRACT.json (dsmack-control-statement/1) and the
// verifier's own assembler reference (verifier/control_statement.build).
//
// Write order and commitment order (all validation happens BEFORE the first
// byte is written, so a refused emit leaves the receipt directory empty):
//   scan retained control stream -> channel_closed -> artifacts_collected
//   (rows recomputed from the exact bytes about to be written) ->
//   device_closed -> vm_stopped -> build control_statement.json over the FINAL
//   lifecycle head -> write the 10 library-owned files -> return the control
//   statement bytes. The app layer then asserts over sha256(those bytes) and
//   writes keyId.txt + assertion.cbor; enrollment.cbor / enroll-client-data.bin
//   are staged here read-once from the enroll directory. Exactly the 12
// CONTROL_FILES end up in the receipt dir — nothing else may write there.
import Foundation

/// Identity/run/checker facts the signed control statement commits to.
/// Sources: keyId/appId from the enroll receipt, nonce = digest observed for
/// this run, counter = the App Attest assertion counter (see APP-CONTRACT
/// AS-4 for how the app recovers it), checker kind/verdict from the task
/// checker outcome, exit status/termination from the backend terminal record.
public struct ControlAttestFacts {
    public let keyId: String
    public let appId: String                 // TEAMID.bundle-id
    public let nonceHex: String              // 64 lowercase hex
    public let counter: Int                  // 1...2^31
    public let runChallenge: Data            // raw bytes of this run's challenge
    public let exitStatus: Int               // -1...256
    public let terminationReason: String     // exited | timeout | output_limit
    public let checkerKind: String
    public let checkerVerdict: String        // pass | fail
    /// Exact bytes produced at enroll time, staged read-once. The verifier
    /// recomputes clientData from ITS OWN enroll challenge and requires byte
    /// equality — the app cannot check that locally; it stages the bytes it used.
    public let enrollClientData: Data
    public let enrollmentCbor: Data

    public init(keyId: String, appId: String, nonceHex: String, counter: Int,
                runChallenge: Data, exitStatus: Int, terminationReason: String,
                checkerKind: String, checkerVerdict: String,
                enrollClientData: Data, enrollmentCbor: Data) {
        self.keyId = keyId
        self.appId = appId
        self.nonceHex = nonceHex
        self.counter = counter
        self.runChallenge = runChallenge
        self.exitStatus = exitStatus
        self.terminationReason = terminationReason
        self.checkerKind = checkerKind
        self.checkerVerdict = checkerVerdict
        self.enrollClientData = enrollClientData
        self.enrollmentCbor = enrollmentCbor
    }
}

public struct ControlRunFacts {
    public let runId: String
    public let taskSHA256: String
    public let taskBytes: Int
    public let framesIn: Int                 // host->guest frames sent
    public let bytesIn: Int
    public let stopReason: String            // "guest-requested" for admission
    public let stdout: Data
    public let stderr: Data
    public let traceLines: Data              // trace.jsonl bytes
    public let statement: Data               // legacy v1 statement.json bytes
    public let controlRecording: Data        // retained guest->host stream
    public let bootManifest: Data            // operator-staged manifest bytes

    public init(runId: String, taskSHA256: String, taskBytes: Int, framesIn: Int,
                bytesIn: Int, stopReason: String, stdout: Data, stderr: Data,
                traceLines: Data, statement: Data, controlRecording: Data,
                bootManifest: Data) {
        self.runId = runId
        self.taskSHA256 = taskSHA256
        self.taskBytes = taskBytes
        self.framesIn = framesIn
        self.bytesIn = bytesIn
        self.stopReason = stopReason
        self.stdout = stdout
        self.stderr = stderr
        self.traceLines = traceLines
        self.statement = statement
        self.controlRecording = controlRecording
        self.bootManifest = bootManifest
    }
}

public enum ControlEmit {
    public static let schema = "dsmack-control-statement/1"
    public static let profile = "dsmack-owned-boot-verity-control/1"
    public static let endpoint = "unix:host-socket(0600)"
    public static let closeKind = "channel-eof"
    public static let exitPath = "returning"
    public static let statuses: Set<String> = ["completed", "failed"]
    public static let checkerVerdicts: Set<String> = ["pass", "fail"]
    public static let terminationReasons: Set<String> = ["exited", "timeout", "output_limit"]
    public static let terminalArtifacts = ["stderr.bin", "statement.json", "stdout.bin", "trace.jsonl"]
    /// The files this library writes; the app layer adds keyId.txt and
    /// assertion.cbor to complete the verifier's 12-file CONTROL_FILES set.
    public static let libraryFiles = ["stderr.bin", "stdout.bin", "trace.jsonl", "statement.json",
                                      "lifecycle.jsonl", "control.rec", "boot_manifest.json",
                                      "control_statement.json", "enroll-client-data.bin", "enrollment.cbor"]

    /// Emits the control-profile receipt core and returns the control
    /// statement bytes — the exact bytes assertion.cbor must cover
    /// (clientDataHash = sha256(return value)).
    public static func writeEvidence(into dir: URL, recorder: LifecycleRecorder,
                                     facts: ControlRunFacts, attest: ControlAttestFacts) throws -> Data {
        // 1. Channel truth first: the retained guest stream must scan clean
        //    (structure only; HMAC/CRC verification stays with the verifier).
        let scan = try DSMX.scanGuestStream(facts.controlRecording)
        guard scan.terminalFrames == 1, scan.postTerminalBytes == 0 else {
            throw ControlEmitError.badRetainedStream
        }

        // 2. Validate every attest fact BEFORE anything is written.
        try validateAttest(attest)
        guard !facts.statement.isEmpty, !facts.bootManifest.isEmpty else {
            throw ControlEmitError.emptyFacts
        }

        // 3. Live lifecycle events up to channel close (run_id/task already
        //    recorded by the mode at their real observation points).
        try recorder.channelClosed(framesIn: facts.framesIn, bytesIn: facts.bytesIn,
                                   framesOut: scan.frames, bytesOut: scan.bytes,
                                   terminalFrames: scan.terminalFrames,
                                   postTerminalBytes: scan.postTerminalBytes)

        // 4. Artifact rows recomputed from the exact bytes about to be written.
        try recorder.artifactsCollected(files: [
            ("stderr.bin", SHA256.hex(facts.stderr), facts.stderr.count),
            ("statement.json", SHA256.hex(facts.statement), facts.statement.count),
            ("stdout.bin", SHA256.hex(facts.stdout), facts.stdout.count),
            ("trace.jsonl", SHA256.hex(facts.traceLines), facts.traceLines.count),
        ])
        try recorder.deviceClosed()
        try recorder.vmStopped(stopReason: facts.stopReason)

        // 5. The signed control statement, over the FINAL lifecycle head.
        let controlStatement = try buildControlStatement(facts: facts, attest: attest, scan: scan,
                                                         recorder: recorder)

        // 6. All validation passed — write everything.
        try write("stdout.bin", facts.stdout, into: dir)
        try write("stderr.bin", facts.stderr, into: dir)
        try write("trace.jsonl", facts.traceLines, into: dir)
        try write("statement.json", facts.statement, into: dir)
        try write("lifecycle.jsonl", recorder.lines, into: dir)
        try write("control.rec", facts.controlRecording, into: dir)
        try write("boot_manifest.json", facts.bootManifest, into: dir)
        try write("control_statement.json", controlStatement, into: dir)
        try write("enroll-client-data.bin", attest.enrollClientData, into: dir)
        try write("enrollment.cbor", attest.enrollmentCbor, into: dir)
        return controlStatement
    }

    /// Mirrors verifier/control_statement.build: exact top-level key set, exact
    /// per-section key sets, status derived from the contract biconditional
    /// ('completed' iff exit_status == 0 AND checker.verdict == 'pass').
    static func buildControlStatement(facts: ControlRunFacts, attest: ControlAttestFacts,
                                      scan: (frames: Int, bytes: Int, terminalFrames: Int, postTerminalBytes: Int),
                                      recorder: LifecycleRecorder) throws -> Data {
        let status = (attest.exitStatus == 0 && attest.checkerVerdict == "pass") ? "completed" : "failed"
        let terminalPayload = try DSMX.terminalPayload(of: facts.controlRecording)
        let obj: [String: Any] = [
            "schema": schema,
            "profile": profile,
            "identity": ["key_id": attest.keyId, "app_id": attest.appId],
            "run": [
                "run_id": facts.runId,
                "nonce": attest.nonceHex,
                "counter": attest.counter,
                "run_challenge_sha256": SHA256.hex(attest.runChallenge),
            ],
            "environment": ["manifest_sha256": SHA256.hex(facts.bootManifest)],
            "task": ["sha256": facts.taskSHA256, "bytes": facts.taskBytes],
            "transcript": [
                "trace_head": traceHead(of: facts.traceLines),
                "trace_events": traceEventCount(of: facts.traceLines),
                "terminal_sha256": SHA256.hex(terminalPayload),
                "control_frames": scan.frames,
                "control_bytes": scan.bytes,
            ],
            "outcome": [
                "status": status,
                "exit_status": attest.exitStatus,
                "termination_reason": attest.terminationReason,
                "checker": ["kind": attest.checkerKind, "verdict": attest.checkerVerdict],
            ],
            "lifecycle": ["head": recorder.head, "events": recorder.events],
            "output": [
                "stdout": ["sha256": SHA256.hex(facts.stdout), "bytes": facts.stdout.count],
                "stderr": ["sha256": SHA256.hex(facts.stderr), "bytes": facts.stderr.count],
            ],
            "legacy_statement_sha256": SHA256.hex(facts.statement),
        ]
        return try ControlJSON.canonical(obj)
    }

    static func validateAttest(_ a: ControlAttestFacts) throws {
        guard a.keyId.count > 0, a.keyId.count <= 200,
              a.keyId.allSatisfy({ $0.isASCII && !$0.isWhitespace && !$0.isNewline }) else {
            throw ControlEmitError.badKeyId
        }
        guard a.appId.count >= 5, a.appId.count <= 255, a.appId.contains(".") else {
            throw ControlEmitError.badAppId
        }
        guard Self.isDigest(a.nonceHex) else { throw ControlEmitError.badNonce }
        guard a.counter >= 1, a.counter <= 1 << 31 else { throw ControlEmitError.badCounter }
        guard a.exitStatus >= -1, a.exitStatus <= 256 else { throw ControlEmitError.badExitStatus }
        guard terminationReasons.contains(a.terminationReason) else {
            throw ControlEmitError.badTerminationReason
        }
        guard checkerVerdicts.contains(a.checkerVerdict) else { throw ControlEmitError.badCheckerVerdict }
        guard !a.checkerKind.isEmpty,
              a.checkerKind.allSatisfy({ $0.isASCII && !$0.isWhitespace && !$0.isNewline }) else {
            throw ControlEmitError.badCheckerKind
        }
        guard !a.runChallenge.isEmpty, !a.enrollClientData.isEmpty, !a.enrollmentCbor.isEmpty else {
            throw ControlEmitError.emptyEnrollEvidence
        }
    }

    static func isDigest(_ s: String) -> Bool {
        s.count == 64 && s.allSatisfy { ($0 >= "0" && $0 <= "9") || ($0 >= "a" && $0 <= "f") }
    }

    /// The trace chain rule, identical to the v1 statement's: h_i =
    /// sha256(h_{i-1} as hex ‖ line_i), h_0 = 64 zeros, over trace.jsonl lines.
    static func traceHead(of traceLines: Data) -> String {
        var head = String(repeating: "0", count: 64)
        var line = Data()
        for byte in traceLines {
            if byte == 0x0a {
                head = SHA256.hex(Data(head.utf8) + line)
                line = Data()
            } else {
                line.append(byte)
            }
        }
        return head
    }

    static func traceEventCount(of traceLines: Data) -> Int {
        guard !traceLines.isEmpty else { return 0 }
        return traceLines.filter { $0 == 0x0a }.count
    }

    static func write(_ name: String, _ bytes: Data, into dir: URL) throws {
        try bytes.write(to: dir.appendingPathComponent(name), options: .atomic)
    }
}

public enum ControlEmitError: Error, Equatable {
    case badRetainedStream
    case emptyFacts
    case badKeyId
    case badAppId
    case badNonce
    case badCounter
    case badExitStatus
    case badTerminationReason
    case badCheckerVerdict
    case badCheckerKind
    case emptyEnrollEvidence
}
