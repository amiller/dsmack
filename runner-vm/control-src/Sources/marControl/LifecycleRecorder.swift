// Host-side checked-teardown lifecycle record (lifecycle.jsonl) for the
// control profile, aligned exactly with ../verifier-repair receipt_profile.py:
// stage names, per-stage field sets, the fixed endpoint/close_kind/exit_path
// strings, and the chain h_i = sha256(h_{i-1}hex || line_i), h_0 = 64 zeros.
//
// Two hard rules mirror the verifier's schema:
//  - NO timestamps and no extra fields: the verifier enforces exact field sets
//    per stage, so a recorder method can only emit its stage's fields.
//  - NO booleans: the verifier walks every parsed value and rejects any bool
//    (lifecycle_boolean_claim); every value here is Int, String or [name,
//    sha256, bytes] rows, so a self-claim like "teardown_ok": true cannot be
//    expressed through this API at all.
import Foundation

public struct LifecycleError: Error, CustomStringConvertible {
    public let description: String
    public init(_ reason: String) { description = "lifecycle: \(reason)" }
}

/// 64-char lowercase hex (a digest). Range checks, not Character.isLowercase:
/// digits are caseless under Unicode, so `isHexDigit && isLowercase` is false
/// for "0"..."9" and would reject every real digest.
func isLowercaseHex64(_ s: String) -> Bool {
    s.count == 64 && s.allSatisfy { ($0 >= "0" && $0 <= "9") || ($0 >= "a" && $0 <= "f") }
}

public final class LifecycleRecorder {
    public private(set) var lines = Data()
    public private(set) var head = String(repeating: "0", count: 64)
    public private(set) var events = 0

    public init() {}

    private func append(_ stage: String, _ fields: [String: Any]) throws {
        var object = fields
        object["seq"] = events
        object["stage"] = stage
        let line = try ControlJSON.canonical(object)
        head = SHA256.hex(Data(head.utf8) + line)
        lines += line + Data("\n".utf8)
        events += 1
    }

    /// Stage 1 — the session identity the verifier supplied for this run.
    public func sessionStarted(runId: String) throws {
        guard runId.range(of: "^[0-9a-f]{1,128}$", options: .regularExpression) != nil else {
            throw LifecycleError("run_id must be 1-128 lowercase hex")
        }
        try append("session_started", ["run_id": runId])
    }

    /// Stage 2 — the exact task bytes committed to the guest (stdin).
    public func taskInputCommitted(taskSHA256: String, taskBytes: Int) throws {
        guard isLowercaseHex64(taskSHA256) else {
            throw LifecycleError("task_sha256 must be 64 lowercase hex")
        }
        guard taskBytes >= 0 else { throw LifecycleError("task_bytes negative") }
        try append("task_input_committed", ["task_sha256": taskSHA256, "task_bytes": taskBytes])
    }

    /// Stage 3 — channel accounting. frames_out/bytes_out are the retained
    /// guest->host stream (control.rec); terminal once; nothing after it.
    public func channelClosed(framesIn: Int, bytesIn: Int, framesOut: Int, bytesOut: Int,
                              terminalFrames: Int, postTerminalBytes: Int) throws {
        for (name, v) in [("frames_in", framesIn), ("bytes_in", bytesIn), ("frames_out", framesOut),
                          ("bytes_out", bytesOut), ("terminal_frames", terminalFrames),
                          ("post_terminal_bytes", postTerminalBytes)] where v < 0 {
            throw LifecycleError("\(name) negative")
        }
        try append("channel_closed", [
            "frames_in": framesIn, "bytes_in": bytesIn, "frames_out": framesOut, "bytes_out": bytesOut,
            "terminal_frames": terminalFrames, "post_terminal_bytes": postTerminalBytes,
        ])
    }

    /// Stage 4 — the four authenticator-covered artifacts as sorted
    /// [name, sha256, bytes] rows over the bytes actually written to the run dir.
    public func artifactsCollected(files: [(name: String, sha256: String, bytes: Int)]) throws {
        let rows: [[Any]] = try files.map { row in
            guard isLowercaseHex64(row.sha256) else {
                throw LifecycleError("artifact digest malformed for \(row.name)")
            }
            guard row.bytes >= 0 else { throw LifecycleError("artifact bytes negative for \(row.name)") }
            return [row.name, row.sha256, row.bytes] as [Any]
        }
        try append("artifacts_collected", ["files": rows.sorted(by: { ($0[0] as! String) < ($1[0] as! String) })])
    }

    /// Stage 5 — the control device this run actually closed.
    public func deviceClosed(endpoint: String = ControlEmit.endpoint, closeKind: String = ControlEmit.closeKind) throws {
        try append("device_closed", ["endpoint": endpoint, "close_kind": closeKind])
    }

    /// Stage 6 — how the VM actually stopped. stop_reason records the observed
    /// fact; admission authority stays with the verifier (host-halt/watchdog
    /// are never success evidence there).
    public func vmStopped(stopReason: String, exitPath: String = ControlEmit.exitPath) throws {
        try append("vm_stopped", ["stop_reason": stopReason, "exit_path": exitPath])
    }
}
