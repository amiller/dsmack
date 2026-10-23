// ReproMain.swift — FIRST, standalone reproduction of the APP-SCOPE-02-R2-OUT-PATH-MAPPING
// counterexamples against the EXACT R2 immutable baseline RetentionV3.swift
// (sha256 7fe5ab0d3f456769d63a690add9ad36fd279e87be13a415e1fc8afe922fc92be), compiled in
// the SAME module so it calls the real performDurableRetention and sets the real
// retentionReplaceHook / retentionFsyncOverride seams. This is the failing-evidence
// artifact: the R2 baseline MUST incorrectly return SUCCESS for all four injections
// (parent rename / parent replacement, each pre-sync and post-sync). The repaired R3
// implementation is exercised through the SAME injections in the controls package, where
// it REFUSES (GREEN). repro.sh hash-verifies the baseline source before building this.
#if canImport(Darwin)
import CryptoKit
import Darwin
import Foundation

func rmkTmpDir() -> URL {
    let base = FileManager.default.temporaryDirectory
    let dir = base.appendingPathComponent("baseline-repro-\(UUID().uuidString)", isDirectory: true)
    try! FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    return dir
}
// <temp>/<grand>/parent/out so OUT's parent can be renamed/replaced without touching the
// process-wide temp root.
func rmkNestedOut() -> (grand: URL, parent: URL, out: URL) {
    let g = rmkTmpDir()
    let p = g.appendingPathComponent("parent", isDirectory: true)
    try! FileManager.default.createDirectory(at: p, withIntermediateDirectories: false)
    let o = p.appendingPathComponent("out", isDirectory: true)
    try! FileManager.default.createDirectory(at: o, withIntermediateDirectories: false)
    return (g, p, o)
}
func rsha(_ b: [UInt8]) -> String { SHA256.hash(data: Data(b)).map { String(format: "%02x", $0) }.joined() }
let rResult: [UInt8] = Array(repeating: 0x5a, count: 2048)
let rConsole: [UInt8] = Array("hello guest console\n".utf8)
func rproduce(_ out: URL) -> [RetainedFileV3] {
    let rp = out.appendingPathComponent("result.img").path
    let cp = out.appendingPathComponent("console-v3.log").path
    try! Data(rResult).write(to: URL(fileURLWithPath: rp))
    try! Data(rConsole).write(to: URL(fileURLWithPath: cp))
    return [RetainedFileV3(path: rp, expectSha256: rsha(rResult), expectBytes: rResult.count, what: "result.img (vdd)"),
            RetainedFileV3(path: cp, expectSha256: rsha(rConsole), expectBytes: rConsole.count, what: "console-v3.log")]
}
func rdocs() -> [RetainedDocV3] {
    [RetainedDocV3("envelope.json", Data(#"{"schema":"x","status":"halted"}"#.utf8)),
     RetainedDocV3("statement.json", Data(#"{"schema":"v3"}"#.utf8))]
}
func rRun(_ out: URL, replace: ((String) -> Void)? = nil, fsync: ((Int32, String) -> Int32)? = nil) -> Error? {
    retentionReplaceHook = replace
    retentionFsyncOverride = fsync
    defer { retentionReplaceHook = nil; retentionFsyncOverride = nil }
    let verifications = rproduce(out)   // write result.img + console-v3.log BEFORE retention opens them
    do { try performDurableRetention(outDir: out, documents: rdocs(), verifications: verifications); return nil }
    catch { return error }
}
func renameAway(_ g: URL, _ p: URL) {
    try? FileManager.default.moveItem(atPath: p.path, toPath: g.appendingPathComponent("parent-moved").path)
}
func replaceFresh(_ g: URL, _ p: URL, _ o: URL) {
    try? FileManager.default.moveItem(atPath: p.path, toPath: g.appendingPathComponent("parent-moved").path)
    try? FileManager.default.createDirectory(atPath: p.path, withIntermediateDirectories: false)
    try? FileManager.default.createDirectory(atPath: o.path, withIntermediateDirectories: false)  // DIFFERENT inode, same path
}

var vuln = 0, total = 0
func report(_ name: String, _ err: Error?) {
    total += 1
    if err == nil {
        vuln += 1
        print("  BASELINE-VULNERABLE [\(name)]: performDurableRetention returned SUCCESS though the caller's OUT pathname was missing/substituted")
    } else {
        print("  baseline-refused    [\(name)]: \(err!)")
    }
}

print("== APP-SCOPE-02-R2 BASELINE REPRODUCTION: RetentionV3.swift 7fe5ab0d (R2 immutable) ==")
do { let (g, p, o) = rmkNestedOut(); report("parent-rename  pre-sync",  rRun(o, replace: { if $0 == "out" { renameAway(g, p) } })) }
do { let (g, p, o) = rmkNestedOut(); report("parent-rename  post-sync", rRun(o, fsync: { fd, s in let rc = fsync(fd); if s == "parent" { renameAway(g, p) }; return rc })) }
do { let (g, p, o) = rmkNestedOut(); report("parent-replace pre-sync",  rRun(o, replace: { if $0 == "out" { replaceFresh(g, p, o) } })) }
do { let (g, p, o) = rmkNestedOut(); report("parent-replace post-sync", rRun(o, fsync: { fd, s in let rc = fsync(fd); if s == "parent" { replaceFresh(g, p, o) }; return rc })) }
print("== BASELINE-REPRO SUMMARY: \(vuln)/\(total) counterexamples incorrectly SUCCEEDED on the R2 baseline ==")
// Exit 0 ONLY when the baseline reproduced the vulnerability on ALL four injections
// (the expected pre-repair state). Any baseline refusal means the repro did not establish
// the defect and fails loudly.
exit(vuln == total ? 0 : 1)
#endif
