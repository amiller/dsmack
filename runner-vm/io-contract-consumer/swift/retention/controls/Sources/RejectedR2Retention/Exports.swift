// Exports.swift — thin PUBLIC surface over the module-internal durable-retention entry
// points and test seams, so the controls executable can drive this EXACT implementation
// across the module boundary. No logic is added: ctrlPerformDurableRetention forwards
// verbatim to performDurableRetention, and the setters assign the module's existing
// test seams (retentionFsyncOverride / retentionReplaceHook).
#if canImport(Darwin)
import Foundation

public struct CtrlDoc {
    public let name: String
    public let bytes: [UInt8]
    public init(_ name: String, _ bytes: [UInt8]) { self.name = name; self.bytes = bytes }
}

public struct CtrlFile {
    public let path: String
    public let sha: String
    public let bytes: Int
    public let what: String
    public init(path: String, sha: String, bytes: Int, what: String) {
        self.path = path; self.sha = sha; self.bytes = bytes; self.what = what
    }
}

public func ctrlPerformDurableRetention(outDir: URL, docs: [CtrlDoc], files: [CtrlFile]) throws {
    try performDurableRetention(
        outDir: outDir,
        documents: docs.map { RetainedDocV3($0.name, Data($0.bytes)) },
        verifications: files.map { RetainedFileV3(path: $0.path, expectSha256: $0.sha, expectBytes: $0.bytes, what: $0.what) })
}

public func ctrlSetFsyncOverride(_ f: ((_ fd: Int32, _ stage: String) -> Int32)?) { retentionFsyncOverride = f }
public func ctrlSetReplaceHook(_ f: ((_ stage: String) -> Void)?) { retentionReplaceHook = f }
#endif
