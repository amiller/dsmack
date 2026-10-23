// Success-path session finalization (astra-gate repair2 R2).
//
// The repair1 gate found the hvf-control success path publishing three
// unreconcilable representations of the host trace: the lifecycle
// artifactsCollected row committed a digest taken BEFORE the final
// `control_session_complete` event was appended, the summary published the
// AFTER head, and trace.jsonl itself was never written on success at all —
// plus a console artifact that hashed a capped prefix while reporting the
// full byte count. This module is the ONE finalization sequence the
// executable actually runs, ordered so the inconsistency is structurally
// impossible:
//
//   1. the host appends its final trace event and freezes the snapshot
//      (bytes + head + count) — nothing may append afterwards;
//   2. the console is read once; overflow of the output limit is REFUSED
//      (fail-closed) instead of hashing a prefix of a longer stream;
//   3. the lifecycle rows are emitted, and the artifactsCollected row
//      commits digests/byte-counts over exactly the bytes that are about
//      to be saved (trace.jsonl from the frozen snapshot, console-1.log at
//      its already-final console path);
//   4. every artifact file is written from those same bytes;
//   5. the summary composes its trace/lifecycle blocks from the frozen
//      snapshot and the recorder state — file bytes == lifecycle commitment
//      == summary head, always.
//
// The caller supplies the terminal-authenticated facts (verifyTerminal must
// already have passed — no summary is composed otherwise) and a save
// closure, so tests execute this exact production sequence against a
// temporary directory.

import Foundation

/// The frozen host-trace snapshot every representation is derived from.
public struct SessionTraceSnapshot {
    public let bytes: Data
    public let head: String
    public let events: Int
    public init(bytes: Data, head: String, events: Int) {
        self.bytes = bytes
        self.head = head
        self.events = events
    }
}

/// The observed session facts the finalization records. All digests are over
/// bytes this process collected; `terminalRecord` is the authenticated
/// terminal (verifyTerminal already passed) — never a synthesized one.
public struct SessionFinalizationFacts {
    public var runId: String
    public var nonceHex: String
    public var vmmCode: Int32
    public var framesIn: Int, bytesIn: Int           // host->guest sent
    public var controlBytes: Data                    // retained guest->host stream
    public var stdout: Data, stderr: Data
    public var retainerFrames: Int, retainerBytes: Int
    public var terminalFrames: Int, postTerminalBytes: Int
    public var terminalPayloadSHA256: String
    public var terminalRecord: TerminalRecord
    public var taskSHA256: String, taskBytesCount: Int
    public var frameKinds: [String: Int]
    // summary echo fields (verified inputs and compiled-in pins)
    public var challenge: String
    public var keyId: String
    public var profile: String
    public var statementSchema: String
    public var backendArchiveSHA256: String
    public var ctlAbiVersion: Int
    public var pins: [String: String]
    public var runMs: Int
    public var attestMissing: [String]
    public var attestReason: String
    public init(runId: String, nonceHex: String, vmmCode: Int32,
                framesIn: Int, bytesIn: Int, controlBytes: Data,
                stdout: Data, stderr: Data,
                retainerFrames: Int, retainerBytes: Int,
                terminalFrames: Int, postTerminalBytes: Int,
                terminalPayloadSHA256: String, terminalRecord: TerminalRecord,
                taskSHA256: String, taskBytesCount: Int, frameKinds: [String: Int],
                challenge: String, keyId: String, profile: String,
                statementSchema: String, backendArchiveSHA256: String,
                ctlAbiVersion: Int, pins: [String: String], runMs: Int,
                attestMissing: [String], attestReason: String) {
        self.runId = runId; self.nonceHex = nonceHex; self.vmmCode = vmmCode
        self.framesIn = framesIn; self.bytesIn = bytesIn
        self.controlBytes = controlBytes; self.stdout = stdout; self.stderr = stderr
        self.retainerFrames = retainerFrames; self.retainerBytes = retainerBytes
        self.terminalFrames = terminalFrames; self.postTerminalBytes = postTerminalBytes
        self.terminalPayloadSHA256 = terminalPayloadSHA256
        self.terminalRecord = terminalRecord
        self.taskSHA256 = taskSHA256; self.taskBytesCount = taskBytesCount
        self.frameKinds = frameKinds
        self.challenge = challenge; self.keyId = keyId; self.profile = profile
        self.statementSchema = statementSchema
        self.backendArchiveSHA256 = backendArchiveSHA256
        self.ctlAbiVersion = ctlAbiVersion; self.pins = pins; self.runMs = runMs
        self.attestMissing = attestMissing; self.attestReason = attestReason
    }
}

public enum SessionFinalizeError: Error, CustomStringConvertible {
    case consoleOverflow(bytes: Int, limit: Int)
    public var description: String {
        switch self {
        case .consoleOverflow(let bytes, let limit):
            return "console-1.log overflow: \(bytes) bytes exceeds the \(limit)-byte output limit; refusing to hash a prefix while reporting the full count"
        }
    }
}

public enum SessionFinalize {
    /// The one success-path finalization. Returns the composed summary bytes
    /// (backend-session.json contents); every artifact file has already been
    /// saved through `save` when it returns.
    public static func run(
        consolePath: String,
        outputLimit: Int,
        facts: SessionFinalizationFacts,
        appendFinalTrace: () throws -> SessionTraceSnapshot,
        save: (_ name: String, _ bytes: Data) throws -> Void
    ) throws -> Data {
        // 1. Final trace event FIRST; the snapshot is frozen here and nothing
        //    may append to the host trace afterwards.
        let snap = try appendFinalTrace()

        // 2. Console: read once, refuse overflow outright. No prefix hashing
        //    paired with a full-count report, ever. console-1.log lives at its
        //    final path already (the VMM writes it there), so the committed
        //    digest describes the file the artifact set actually retains.
        let consoleFinal = try FileHandle(forReadingFrom: URL(fileURLWithPath: consolePath))
            .read(upToCount: outputLimit + 1) ?? Data()
        guard consoleFinal.count <= outputLimit else {
            throw SessionFinalizeError.consoleOverflow(bytes: consoleFinal.count, limit: outputLimit)
        }

        // 3. Lifecycle record from the OBSERVED session facts. Counter
        //    directions follow the recorder/verifier contract: frames/bytes
        //    IN are host->guest sent, OUT are the retained guest->host stream.
        //    The artifactsCollected row commits the frozen snapshot and the
        //    exact bytes saved below.
        let rec = LifecycleRecorder()
        try rec.sessionStarted(runId: facts.runId)
        try rec.taskInputCommitted(taskSHA256: facts.taskSHA256, taskBytes: facts.taskBytesCount)
        try rec.channelClosed(framesIn: facts.framesIn, bytesIn: facts.bytesIn,
                              framesOut: facts.retainerFrames, bytesOut: facts.retainerBytes,
                              terminalFrames: facts.terminalFrames,
                              postTerminalBytes: facts.postTerminalBytes)
        try rec.artifactsCollected(files: [
            (name: "control.rec", sha256: SHA256.hex(facts.controlBytes), bytes: facts.controlBytes.count),
            (name: "console-1.log", sha256: SHA256.hex(consoleFinal), bytes: consoleFinal.count),
            (name: "stderr.bin", sha256: SHA256.hex(facts.stderr), bytes: facts.stderr.count),
            (name: "stdout.bin", sha256: SHA256.hex(facts.stdout), bytes: facts.stdout.count),
            (name: "trace.jsonl", sha256: SHA256.hex(snap.bytes), bytes: snap.bytes.count),
        ])
        try rec.deviceClosed()
        try rec.vmStopped(stopReason: facts.vmmCode == 0 ? "guest-requested" : "vcpu-error")
        try save("lifecycle.jsonl", rec.lines)

        // 4. Every artifact file written from exactly the committed bytes.
        try save("control.rec", facts.controlBytes)
        try save("stdout.bin", facts.stdout)
        try save("stderr.bin", facts.stderr)
        try save("trace.jsonl", snap.bytes)

        // 5. Summary from the same frozen state — one representation.
        let terminalOutput = facts.terminalRecord.fields["output"] ?? [:] as [String: Any]
        let terminalTrace = facts.terminalRecord.fields["trace"] ?? [:] as [String: Any]
        return try ControlJSON.canonical([
            "domain": "dsmack-control-session/1",
            "note": "session record, NOT a receipt: no statement/assertion without the signed-app gate",
            "challenge": facts.challenge, "key_id": facts.keyId,
            "profile": facts.profile, "statement_schema": facts.statementSchema,
            "backend_archive_sha256": facts.backendArchiveSHA256, "ctl_abi_version": facts.ctlAbiVersion,
            "pins": facts.pins,
            "run": ["run_id": facts.runId, "nonce_hex": facts.nonceHex, "vmm_code": Int(facts.vmmCode),
                    "run_ms": facts.runMs],
            "channel": ["frames_in": facts.framesIn, "bytes_in": facts.bytesIn,
                        "guest_frames": facts.retainerFrames, "guest_bytes": facts.retainerBytes,
                        "post_terminal_bytes": facts.postTerminalBytes,
                        "frame_kinds": facts.frameKinds,
                        "terminal_sha256": facts.terminalPayloadSHA256],
            "terminal": ["authenticated": true, "status": facts.terminalRecord.status,
                         "exit_status": facts.terminalRecord.exitStatus,
                         "run_id": facts.runId, "nonce_hex": facts.nonceHex,
                         "output": terminalOutput,
                         "trace": terminalTrace,
                         "provider": facts.terminalRecord.provider,
                         "artifacts": facts.terminalRecord.artifacts],
            "lifecycle": ["head": rec.head, "events": rec.events],
            "trace": ["head": snap.head, "events": snap.events],
            "attest": ["status": "waiting",
                       "missing": facts.attestMissing,
                       "reason": facts.attestReason],
        ] as [String: Any])
    }
}
