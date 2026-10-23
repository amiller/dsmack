// controls/main.swift — APP-RETENTION-CONTROLS driver.
//
// Drives the EXACT accepted (rejected-baseline) durable-retention implementation and the
// round-2 repaired implementation through the SAME injected faults, and the ACTUAL
// cleanup dispatch boundary, asserting for each control that:
//   * the repaired implementation is GREEN (detects + refuses, or binds owned bytes), and
//   * where the control distinguishes the round-2 defects, the accepted implementation is
//     RED (silently succeeds / never observes), reproducing the reviewer counterexample.
//
// Covers the complete specified boundary (APP-RETENTION-BOUNDARY-DECISION.json +
// generic-app-retention-repair-opus-review must_fix): retained-FD lifetime, same-inode
// post-sync mutation, post-dir-sync substitution, OUT no-follow, established/new parent
// mapping + sync failure, every file/dir/parent IO failure, missing/short/extra lengths,
// non-regular objects, unconfined names, full-set failure propagation, no-FD-leak on both
// success and failure, and the real APP-SCOPE-01 own()->dropScratch() dispatch.
//
// Each assertion is INDIVIDUAL and counted; the final summary prints the exact count and a
// machine-readable ASSERTION-COUNT so the saved log's PASS/FAIL line count can be checked
// to equal it (the rejected round-1 counted the ALL-PASS summary line as an assertion).
import CryptoKit
import Darwin
import Foundation
import AcceptedRetention
import RejectedR2Retention
import RepairedRetention
import AppCleanup

// ---------------- assertion bookkeeping (individual, counted) ----------------
var assertionsRun = 0
var failures = 0
func check(_ label: String, _ cond: Bool) {
    assertionsRun += 1
    print("  \(cond ? "PASS" : "FAIL") [#\(assertionsRun)] \(label)")
    if !cond { failures += 1 }
}

// ---------------- small filesystem helpers (test-only) ----------------
func mkTmpDir() -> URL {
    let base = FileManager.default.temporaryDirectory
    let dir = base.appendingPathComponent("retention-controls-\(UUID().uuidString)", isDirectory: true)
    try! FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    return dir
}
func writeFile(_ url: URL, _ bytes: [UInt8]) { try! Data(bytes).write(to: url, options: .atomic) }
func readBytes(_ path: String) -> [UInt8]? { FileManager.default.contents(atPath: path).map { [UInt8]($0) } }
func exists(_ path: String) -> Bool { FileManager.default.fileExists(atPath: path) }
func sha256hex(_ bytes: [UInt8]) -> String {
    SHA256.hash(data: Data(bytes)).map { String(format: "%02x", $0) }.joined()
}
func docBytes(_ out: URL, _ name: String) -> [UInt8]? { readBytes(out.appendingPathComponent(name).path) }

/// Count currently-open descriptors for THIS process (via /dev/fd) — the no-leak controls
/// assert this returns to baseline after batches of success AND failure retentions, i.e.
/// every owned descriptor is closed exactly once on both paths.
func openFdCount() -> Int { (try? FileManager.default.contentsOfDirectory(atPath: "/dev/fd").count) ?? -1 }

/// Overwrite an existing file IN PLACE (same inode; no unlink, no O_CREAT) with new bytes
/// of the same length — a same-inode modification the dev/inode mapping check cannot see.
func sameInodeOverwrite(_ path: String, _ bytes: [UInt8]) {
    let fd = open(path, O_WRONLY)
    guard fd >= 0 else { return }
    _ = ftruncate(fd, 0)
    _ = bytes.withUnsafeBytes { raw in write(fd, raw.baseAddress, raw.count) }
    close(fd)
}
/// Replace the inode answering a NAME (unlink old inode, create a fresh one) — a dev/inode
/// substitution the pre-sync mapping check detects.
func replaceInode(_ path: String, _ bytes: [UInt8]) {
    try? FileManager.default.removeItem(atPath: path)
    FileManager.default.createFile(atPath: path, contents: Data(bytes))
}

// ---------------- common specs (module-agnostic) ----------------
struct DocSpec { let name: String; let bytes: [UInt8] }
struct FileSpec { let path: String; let sha: String; let bytes: Int; let what: String }

func baseDocs() -> [DocSpec] {
    return [
        DocSpec(name: "envelope.json", bytes: [UInt8](#"{"schema":"x","status":"halted"}"#.utf8)),
        DocSpec(name: "statement.json", bytes: [UInt8](#"{"schema":"v3"}"#.utf8)),
        DocSpec(name: "launch-assertion.cbor", bytes: [0xa1, 0x01, 0x02]),
        DocSpec(name: "result-client-data.bin", bytes: [0x00, 0x01, 0x02, 0x03]),
        DocSpec(name: "trace.jsonl", bytes: [UInt8]("{}\n".utf8)),
    ]
}
let resultData: [UInt8] = Array(repeating: 0x5a, count: 2048)
let consoleData: [UInt8] = Array("hello guest console\n".utf8)

/// Produce the two backend files in OUT and return their TRUE verification specs (or a
/// deliberately wrong expectation to inject a verification fault).
func produce(_ out: URL, result: [UInt8] = resultData, console: [UInt8] = consoleData,
             resultSha: String? = nil, resultLen: Int? = nil, consoleSha: String? = nil) -> [FileSpec] {
    let rp = out.appendingPathComponent("result.img").path
    let cp = out.appendingPathComponent("console-v3.log").path
    writeFile(URL(fileURLWithPath: rp), result)
    writeFile(URL(fileURLWithPath: cp), console)
    return [
        FileSpec(path: rp, sha: resultSha ?? sha256hex(result), bytes: resultLen ?? result.count, what: "result.img (vdd)"),
        FileSpec(path: cp, sha: consoleSha ?? sha256hex(console), bytes: console.count, what: "console-v3.log"),
    ]
}

// ---------------- per-implementation runners (identical injections) ----------------
func runRepaired(_ out: URL, _ docs: [DocSpec], _ files: [FileSpec],
                 fsync: ((Int32, String) -> Int32)? = nil, replace: ((String) -> Void)? = nil) -> Error? {
    RepairedRetention.ctrlSetFsyncOverride(fsync)
    RepairedRetention.ctrlSetReplaceHook(replace)
    defer { RepairedRetention.ctrlSetFsyncOverride(nil); RepairedRetention.ctrlSetReplaceHook(nil) }
    do {
        try RepairedRetention.ctrlPerformDurableRetention(
            outDir: out,
            docs: docs.map { RepairedRetention.CtrlDoc($0.name, $0.bytes) },
            files: files.map { RepairedRetention.CtrlFile(path: $0.path, sha: $0.sha, bytes: $0.bytes, what: $0.what) })
        return nil
    } catch { return error }
}
func runAccepted(_ out: URL, _ docs: [DocSpec], _ files: [FileSpec],
                 fsync: ((Int32, String) -> Int32)? = nil, replace: ((String) -> Void)? = nil) -> Error? {
    AcceptedRetention.ctrlSetFsyncOverride(fsync)
    AcceptedRetention.ctrlSetReplaceHook(replace)
    defer { AcceptedRetention.ctrlSetFsyncOverride(nil); AcceptedRetention.ctrlSetReplaceHook(nil) }
    do {
        try AcceptedRetention.ctrlPerformDurableRetention(
            outDir: out,
            docs: docs.map { AcceptedRetention.CtrlDoc($0.name, $0.bytes) },
            files: files.map { AcceptedRetention.CtrlFile(path: $0.path, sha: $0.sha, bytes: $0.bytes, what: $0.what) })
        return nil
    } catch { return error }
}

/// Drive the EXACT R2 immutable baseline (RejectedR2Retention, sha256 7fe5ab0d...) through
/// the SAME injection as the repaired implementation. It is the same-baseline RED for the
/// new APP-SCOPE-02-R2-OUT-PATH-MAPPING counterexamples (it passes R2's descriptor-relative
/// mapping checks but never observes the caller's full OUT pathname).
func runRejectedR2(_ out: URL, _ docs: [DocSpec], _ files: [FileSpec],
                 fsync: ((Int32, String) -> Int32)? = nil, replace: ((String) -> Void)? = nil) -> Error? {
    RejectedR2Retention.ctrlSetFsyncOverride(fsync)
    RejectedR2Retention.ctrlSetReplaceHook(replace)
    defer { RejectedR2Retention.ctrlSetFsyncOverride(nil); RejectedR2Retention.ctrlSetReplaceHook(nil) }
    do {
        try RejectedR2Retention.ctrlPerformDurableRetention(
            outDir: out,
            docs: docs.map { RejectedR2Retention.CtrlDoc($0.name, $0.bytes) },
            files: files.map { RejectedR2Retention.CtrlFile(path: $0.path, sha: $0.sha, bytes: $0.bytes, what: $0.what) })
        return nil
    } catch { return error }
}

/// Record which fsync STAGES an implementation drives (and still perform the real fsync),
/// so a control can prove the repaired sequence synchronizes the parent and the accepted
/// one never does.
func stageRecorder() -> (hook: (Int32, String) -> Int32, stages: () -> [String]) {
    final class Box { var s: [String] = [] }
    let box = Box()
    let hook: (Int32, String) -> Int32 = { fd, stage in box.s.append(stage); return fsync(fd) }
    return (hook, { box.s })
}

func auditAllPreserved(_ out: URL, docs: [DocSpec], backend: [(name: String, bytes: [UInt8])]) -> Bool {
    for d in docs { if docBytes(out, d.name) != d.bytes { return false } }
    for b in backend { if docBytes(out, b.name) != b.bytes { return false } }
    return true
}
let backendRef: [(name: String, bytes: [UInt8])] = [("result.img", resultData), ("console-v3.log", consoleData)]

print("== APP-RETENTION-CONTROLS: accepted(b100ea54) vs repaired, identical injections ==")

// ===================================================================================
// S0. SUCCESS (repaired): completes, every doc + backend durable with exact bytes.
// ===================================================================================
do {
    let out = mkTmpDir()
    let files = produce(out)
    let err = runRepaired(out, baseDocs(), files)
    check("S0 repaired success completes (no throw)", err == nil)
    check("S0 repaired all docs + backend durable exact bytes", auditAllPreserved(out, docs: baseDocs(), backend: backendRef))
}

// ===================================================================================
// S1. FD-LIFETIME + POSTSYNC counterexample: a SAME-INODE content mutation of a retained
//     document AFTER its fsync (injected at the "out" window). dev/inode is unchanged, so
//     the mapping check cannot see it. The repaired sequence RETAINS the document fd and
//     RE-READS it after the directory/parent fsync, detecting the change and refusing. The
//     accepted sequence closed that fd in its helper and NEVER re-reads, so it returns
//     SUCCESS with corrupted-but-same-inode content on disk (silent, the exact defect).
// ===================================================================================
do {
    let foreign = [UInt8](#"{"schema":"FOREIGN-SAME-INODE"}"#.utf8)   // same length as {"schema":"v3"}? -> padded below
    // statement.json original is {"schema":"v3"} (15 bytes). Make foreign the SAME length
    // so only CONTENT differs (length check cannot catch it; only a content re-read can).
    let orig = [UInt8](#"{"schema":"v3"}"#.utf8)
    var same = [UInt8](repeating: 0x20, count: orig.count)
    for i in 0..<min(foreign.count, same.count) { same[i] = foreign[i] }

    // repaired
    let outR = mkTmpDir(); let filesR = produce(outR)
    let errR = runRepaired(outR, baseDocs(), filesR, replace: { stage in
        if stage == "out" { sameInodeOverwrite(outR.appendingPathComponent("statement.json").path, same) }
    })
    check("S1 repaired DETECTS same-inode post-sync mutation (throws)", errR != nil)
    check("S1 repaired error is a post-sync content change",
          (errR.map { "\($0)" } ?? "").contains("changed after synchronization"))

    // accepted (same injection) — reproduces the reviewer counterexample
    let outA = mkTmpDir(); let filesA = produce(outA)
    let errA = runAccepted(outA, baseDocs(), filesA, replace: { stage in
        if stage == "out" { sameInodeOverwrite(outA.appendingPathComponent("statement.json").path, same) }
    })
    check("S1 accepted RED: returns SUCCESS despite same-inode post-sync mutation", errA == nil)
    check("S1 accepted RED: corrupted same-inode content left on disk undetected",
          docBytes(outA, "statement.json") == same)
}

// ===================================================================================
// S2. POST-DIR-SYNC substitution: a dev/inode entry swap AFTER synchronization. The
//     repaired sequence re-confirms the no-follow mappings AFTER the fsyncs (post-sync
//     observation), detecting it. The accepted sequence has NO post-sync observation at
//     all (its finalizeDirectory returns immediately after fsync), so it cannot be driven
//     to this window — a structural gap recorded below.
// ===================================================================================
do {
    let outR = mkTmpDir(); let filesR = produce(outR)
    let errR = runRepaired(outR, baseDocs(), filesR, replace: { stage in
        if stage == "postdirsync" { replaceInode(outR.appendingPathComponent("statement.json").path, [UInt8]("different".utf8)) }
    })
    check("S2 repaired DETECTS post-dir-sync substitution (throws)", errR != nil)
    check("S2 repaired error is a [post-sync] substitution/change",
          { let m = errR.map { "\($0)" } ?? ""; return m.contains("post-sync") }())
    // Structural: the accepted implementation never calls the replace hook at a post-sync
    // stage (it has no post-sync observation), so this window is unobservable to it.
    var acceptedSawPostsync = false
    let outA = mkTmpDir(); let filesA = produce(outA)
    _ = runAccepted(outA, baseDocs(), filesA, replace: { stage in if stage == "postdirsync" || stage == "postsync" { acceptedSawPostsync = true } })
    check("S2 accepted RED: has NO post-sync observation window (never reaches postdirsync/postsync)", acceptedSawPostsync == false)
}

// ===================================================================================
// S3. ESTABLISHED-PARENT synchronization. The repaired sequence fsyncs the OUT directory
//     AND its established parent (so the newly created OUT entry is itself durable). The
//     accepted sequence never synchronizes the parent — proven by the stage recorder — and
//     a fsync FAULT injected at the parent stage is silently ignored by it while the
//     repaired sequence propagates it.
// ===================================================================================
do {
    // (a) stage coverage
    let outR = mkTmpDir(); let filesR = produce(outR)
    let recR = stageRecorder()
    let errR = runRepaired(outR, baseDocs(), filesR, fsync: recR.hook)
    check("S3 repaired success completes", errR == nil)
    check("S3 repaired fsyncs OUT dir stage 'dir'", recR.stages().contains("dir"))
    check("S3 repaired fsyncs established parent stage 'parent'", recR.stages().contains("parent"))

    let outA = mkTmpDir(); let filesA = produce(outA)
    let recA = stageRecorder()
    let errA = runAccepted(outA, baseDocs(), filesA, fsync: recA.hook)
    check("S3 accepted success completes", errA == nil)
    check("S3 accepted RED: NEVER synchronizes the parent (no 'parent' stage)", !recA.stages().contains("parent"))

    // (b) parent fsync fault
    func parentFault(_ fd: Int32, _ stage: String) -> Int32 { if stage == "parent" { errno = EIO; return -1 }; return fsync(fd) }
    let outR2 = mkTmpDir(); let filesR2 = produce(outR2)
    let errR2 = runRepaired(outR2, baseDocs(), filesR2, fsync: parentFault)
    check("S3 repaired PROPAGATES parent fsync fault (throws)", errR2 != nil)
    check("S3 repaired parent fsync fault preserves all evidence", auditAllPreserved(outR2, docs: baseDocs(), backend: backendRef))
    let outA2 = mkTmpDir(); let filesA2 = produce(outA2)
    let errA2 = runAccepted(outA2, baseDocs(), filesA2, fsync: parentFault)
    check("S3 accepted RED: parent fsync fault silently ignored (returns success)", errA2 == nil)
}

// ===================================================================================
// S4. OUT NO-FOLLOW. At the "out" window OUT is moved aside and replaced by a SYMLINK that
//     points back at the real (owned) directory. The repaired sequence checks the OUT
//     entry in its parent with fstatat(AT_SYMLINK_NOFOLLOW) — the symlink inode != the
//     owned OUT, so it refuses. The accepted sequence checks stat(OUT) which FOLLOWS the
//     symlink to the owned inode and PASSES, masking the substitution (returns success).
// ===================================================================================
do {
    func symlinkSwap(_ out: URL) {
        let parent = out.deletingLastPathComponent()
        let decoy = parent.appendingPathComponent("decoy-\(UUID().uuidString)")
        try? FileManager.default.moveItem(atPath: out.path, toPath: decoy.path)
        _ = decoy.path.withCString { d in out.path.withCString { o in symlink(d, o) } }
    }
    let outR = mkTmpDir(); let filesR = produce(outR)
    let errR = runRepaired(outR, baseDocs(), filesR, replace: { stage in if stage == "out" { symlinkSwap(outR) } })
    check("S4 repaired DETECTS OUT-pathname symlink substitution (no-follow, throws)", errR != nil)
    let outA = mkTmpDir(); let filesA = produce(outA)
    let errA = runAccepted(outA, baseDocs(), filesA, replace: { stage in if stage == "out" { symlinkSwap(outA) } })
    check("S4 accepted RED: following stat() masks the symlink substitution (success)", errA == nil)
}

// ===================================================================================
// S5. BOUNDARY COVERAGE (repaired GREEN; several are also detected by accepted round-1 and
//     are included for completeness of the specified boundary).
// ===================================================================================
do {
    // (a) document replacement AFTER creation (different inode) at its doc window.
    let out1 = mkTmpDir(); let f1 = produce(out1)
    let err1 = runRepaired(out1, baseDocs(), f1, replace: { stage in
        if stage == "doc:statement.json" { replaceInode(out1.appendingPathComponent("statement.json").path, [UInt8]("foreign".utf8)) }
    })
    check("S5a repaired refuses document inode replacement after creation", err1 != nil)

    // (b) backend-file replacement at the former stat/hash/open window.
    let out2 = mkTmpDir(); let f2 = produce(out2)
    let err2 = runRepaired(out2, baseDocs(), f2, replace: { stage in
        if stage == "file:result.img (vdd)" { replaceInode(out2.appendingPathComponent("result.img").path, Array(repeating: 0xEE, count: resultData.count)) }
    })
    check("S5b repaired refuses backend-file replacement at stat/hash/open window", err2 != nil)

    // (c) OUT pathname replaced by a DIFFERENT directory inode.
    let out3 = mkTmpDir(); let f3 = produce(out3)
    let err3 = runRepaired(out3, baseDocs(), f3, replace: { stage in
        if stage == "out" {
            let parent = out3.deletingLastPathComponent()
            let decoy = parent.appendingPathComponent("decoy-\(UUID().uuidString)")
            try? FileManager.default.moveItem(atPath: out3.path, toPath: decoy.path)
            try? FileManager.default.createDirectory(atPath: out3.path, withIntermediateDirectories: false, attributes: nil)
        }
    })
    check("S5c repaired refuses OUT replaced by a different directory inode", err3 != nil)

    // (d) SHORT bytes (on-disk < committed).
    let out4 = mkTmpDir()
    let f4 = produce(out4, result: Array(repeating: 0x5a, count: 1024), resultSha: sha256hex(resultData), resultLen: resultData.count)
    check("S5d repaired refuses short backend bytes", runRepaired(out4, baseDocs(), f4) != nil)
    // (e) EXTRA bytes (on-disk > committed).
    let out5 = mkTmpDir()
    let f5 = produce(out5, result: Array(repeating: 0x5a, count: 4096), resultSha: sha256hex(resultData), resultLen: resultData.count)
    check("S5e repaired refuses extra/trailing backend bytes", runRepaired(out5, baseDocs(), f5) != nil)
    // (f) MISSING backend file.
    let out6 = mkTmpDir(); let f6 = produce(out6)
    try? FileManager.default.removeItem(atPath: out6.appendingPathComponent("result.img").path)
    check("S5f repaired refuses missing backend file", runRepaired(out6, baseDocs(), f6) != nil)
    // (g) NON-REGULAR document name (a directory occupies the name -> O_EXCL collision).
    let out7 = mkTmpDir(); let f7 = produce(out7)
    try! FileManager.default.createDirectory(at: out7.appendingPathComponent("statement.json"), withIntermediateDirectories: false)
    check("S5g repaired refuses directory occupying a document name", runRepaired(out7, baseDocs(), f7) != nil)
    // (h) NON-REGULAR backend path (a directory at a backend file name -> fstat !regular).
    let out8 = mkTmpDir(); let f8 = produce(out8)
    try? FileManager.default.removeItem(atPath: out8.appendingPathComponent("result.img").path)
    try! FileManager.default.createDirectory(at: out8.appendingPathComponent("result.img"), withIntermediateDirectories: false)
    check("S5h repaired refuses non-regular backend object", runRepaired(out8, baseDocs(), f8) != nil)
    // (i) UNCONFINED name -> rejected up front, no partial set written.
    let out9 = mkTmpDir(); let f9 = produce(out9)
    var docs9 = baseDocs(); docs9.insert(DocSpec(name: "sub/evil.json", bytes: [0x78]), at: 2)
    let err9 = runRepaired(out9, docs9, f9)
    let noneWritten = !baseDocs().contains { exists(out9.appendingPathComponent($0.name).path) }
    check("S5i repaired refuses unconfined name", err9 != nil)
    check("S5i repaired writes NO partial set on unconfined name", noneWritten)
}

// ===================================================================================
// S6. fsync FAULTS at every sync stage of the repaired sequence (doc / file / dir), each
//     detected (throws) AND preserving all evidence (the destructive-cleanup gate holds).
// ===================================================================================
do {
    func faultAt(_ s: String) -> (Int32, String) -> Int32 {
        var fired = false
        return { fd, stage in if !fired && stage == s { fired = true; errno = EIO; return -1 }; return fsync(fd) }
    }
    let outD = mkTmpDir(); let fD = produce(outD)
    let eD = runRepaired(outD, baseDocs(), fD, fsync: faultAt("doc:result-client-data.bin"))
    check("S6 repaired detects document fsync fault", eD != nil)
    // Only docs written BEFORE the faulted fsync (result-client-data.bin is doc index 3,
    // written to disk before its fsync failed) must be preserved intact; the later
    // trace.jsonl was never written (no partial-set guarantee is being made about it).
    check("S6 repaired document fsync fault preserves already-written evidence",
          auditAllPreserved(outD, docs: Array(baseDocs()[0...3]), backend: backendRef))
    let outF = mkTmpDir(); let fF = produce(outF)
    let eF = runRepaired(outF, baseDocs(), fF, fsync: faultAt("file:result.img (vdd)"))
    check("S6 repaired detects backend fsync fault", eF != nil)
    check("S6 repaired backend fsync fault preserves evidence", auditAllPreserved(outF, docs: baseDocs(), backend: backendRef))
    let outDir = mkTmpDir(); let fDir = produce(outDir)
    let eDir = runRepaired(outDir, baseDocs(), fDir, fsync: faultAt("dir"))
    check("S6 repaired detects OUT-dir fsync fault", eDir != nil)
    check("S6 repaired OUT-dir fsync fault preserves evidence", auditAllPreserved(outDir, docs: baseDocs(), backend: backendRef))
}

// ===================================================================================
// S7. NO FD LEAK on BOTH success and failure (every owned descriptor closed exactly once).
//     Run many success and many faulted retentions; the process open-fd count must not grow.
// ===================================================================================
do {
    let before = openFdCount()
    for _ in 0..<120 {
        let out = mkTmpDir(); let f = produce(out)
        _ = runRepaired(out, baseDocs(), f)                                  // success: closes all
    }
    for _ in 0..<120 {
        let out = mkTmpDir(); let f = produce(out)
        _ = runRepaired(out, baseDocs(), f, fsync: { fd, stage in if stage == "dir" { errno = EIO; return -1 }; return fsync(fd) })  // failure: closes all
    }
    let after = openFdCount()
    check("S7 fd count stable across 120 success + 120 failure retentions (no leak)", before >= 0 && after >= 0 && after <= before + 2)
}

// ===================================================================================
// S8. ACTUAL APP-SCOPE-01 cleanup dispatch boundary: own()->dropScratch() (real code from
//     main.swift via AppCleanup) is NON-DESTRUCTIVE — a same-UID replacement at a residue
//     path survives, cleanup reports deferred-unconfirmed, and residue-free is refused.
// ===================================================================================
do {
    let out = mkTmpDir()
    let layout = out.appendingPathComponent("oci-layout").path
    let foreign = [UInt8]("foreign replacement at the oci-layout pathname must survive".utf8)
    writeFile(URL(fileURLWithPath: layout), foreign)
    _ = AppCleanup.own(URL(fileURLWithPath: layout))      // register via the REAL own()
    AppCleanup.dropScratch()                               // drive the REAL dispatch (no unlink)
    check("S8 actual dispatch preserves the replacement (no deletion)", readBytes(layout) == foreign)
    let r = AppCleanup.ctrlReportDeferredResidue(AppCleanup.scratchPaths.withLock { $0 })
    check("S8 actual dispatch reports deferred-unconfirmed for the registry", r.status == "deferred-unconfirmed" && r.paths == [layout])
    check("S8 actual dispatch refuses residue-free completion", r.refusesResidueFree)
}

// ===================================================================================
// S10/S11. APP-SCOPE-02-R2-OUT-PATH-MAPPING — the remaining reviewer counterexample.
//   R2's confirmMappings checks outName ONLY through the RETAINED parentFd and never
//   observes the caller's FULL OUT pathname. Renaming OUT's parent (original OUT path
//   DISAPPEARS, S10) or replacing it (full OUT path now resolves to a DIFFERENT inode,
//   S11) leaves parentFd / dirFd / every artifact FD valid, so R2's descriptor-relative
//   checks ALL pass and it returns SUCCESS (RED) while the caller's OUT pathname is missing
//   or points elsewhere. The R3 repair threads the absolute OUT path into pre/post
//   confirmMappings and adds a no-follow full-path lstat observation (dir + dev/inode vs
//   the owned OUT), so it REFUSES (GREEN) and preserves all residue. Each case is injected
//   BOTH pre-sync via the existing "out" replace seam AND post-sync via the existing
//   retentionFsync "parent" seam — both reached identically by the R2 baseline and the
//   repaired implementation (not a repaired-only hook).
// ===================================================================================

// Build <temp>/<grand>/parent/out so OUT's parent can be renamed/replaced WITHOUT touching
// the process-wide temp root. Returns grandparent, parent and out URLs.
func mkNestedOut() -> (grand: URL, parent: URL, out: URL) {
    let grand = mkTmpDir()
    let parent = grand.appendingPathComponent("parent", isDirectory: true)
    try! FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false)
    let out = parent.appendingPathComponent("out", isDirectory: true)
    try! FileManager.default.createDirectory(at: out, withIntermediateDirectories: false)
    return (grand, parent, out)
}
// The real (possibly moved) OUT location after a parent rename/replace: grand/parent-moved/out.
func movedOutOf(_ grand: URL) -> URL {
    grand.appendingPathComponent("parent-moved", isDirectory: true).appendingPathComponent("out", isDirectory: true)
}
// Every original retained artifact must survive, byte-identical, at its real location —
// the repair refuses WITHOUT unlinking or restoring any uncertain namespace.
func residuePreserved(_ realOut: URL) -> Bool { auditAllPreserved(realOut, docs: baseDocs(), backend: backendRef) }
func renameParentAway(_ grand: URL, _ parent: URL) {
    try? FileManager.default.moveItem(atPath: parent.path, toPath: grand.appendingPathComponent("parent-moved").path)
}
func replaceParentWithFreshInode(_ grand: URL, _ parent: URL, _ out: URL) {
    try? FileManager.default.moveItem(atPath: parent.path, toPath: grand.appendingPathComponent("parent-moved").path)
    try? FileManager.default.createDirectory(atPath: parent.path, withIntermediateDirectories: false)
    try? FileManager.default.createDirectory(atPath: out.path, withIntermediateDirectories: false)  // DIFFERENT inode at same path
}

// ---- S10. parent-path RENAME: the original OUT pathname disappears. ----
do {
    // (a) pre-sync injection via the "out" replace seam.
    let (g, p, out) = mkNestedOut(); let f = produce(out)
    let errRep = runRepaired(out, baseDocs(), f, replace: { if $0 == "out" { renameParentAway(g, p) } })
    check("S10a repaired REFUSES parent-rename before pre-sync (throws)", errRep != nil)
    check("S10a repaired error reports the OUT pathname no longer resolves",
          { let m = errRep.map { "\($0)" } ?? ""; return m.contains("OUT pathname") && m.contains("no longer resolves") }())
    check("S10a repaired preserved the original retained residue (no unlink/restore)", residuePreserved(movedOutOf(g)))
    // SAME injection on the R2 immutable baseline -> incorrectly SUCCEEDS (RED).
    let (g2, p2, out2) = mkNestedOut(); let f2 = produce(out2)
    let errR2 = runRejectedR2(out2, baseDocs(), f2, replace: { if $0 == "out" { renameParentAway(g2, p2) } })
    check("S10a RejectedR2 RED: returns SUCCESS though the original OUT pathname is gone", errR2 == nil)

    // (b) post-sync injection via the existing retentionFsync "parent" seam.
    let (g3, p3, out3) = mkNestedOut(); let f3 = produce(out3)
    let errRepB = runRepaired(out3, baseDocs(), f3, fsync: { fd, stage in
        let rc = fsync(fd); if stage == "parent" { renameParentAway(g3, p3) }; return rc })
    check("S10b repaired REFUSES parent-rename after dir/parent fsync (post-sync, throws)", errRepB != nil)
    check("S10b repaired error is a [post-sync] missing OUT pathname",
          { let m = errRepB.map { "\($0)" } ?? ""; return m.contains("post-sync") && m.contains("OUT pathname") }())
    let (g4, p4, out4) = mkNestedOut(); let f4 = produce(out4)
    let errR2B = runRejectedR2(out4, baseDocs(), f4, fsync: { fd, stage in
        let rc = fsync(fd); if stage == "parent" { renameParentAway(g4, p4) }; return rc })
    check("S10b RejectedR2 RED: returns SUCCESS despite the post-sync parent rename", errR2B == nil)

    // (c) held descriptors close on the new error path (no fd leak across many refusals).
    let before = openFdCount()
    for _ in 0..<60 {
        let (gi, pi, oi) = mkNestedOut(); let fi = produce(oi)
        _ = runRepaired(oi, baseDocs(), fi, replace: { if $0 == "out" { renameParentAway(gi, pi) } })
    }
    let after = openFdCount()
    check("S10c held descriptors close on the new error path (no fd leak across 60 refusals)",
          before >= 0 && after >= 0 && after <= before + 2)
}

// ---- S11. parent REPLACEMENT: the full OUT pathname resolves to a DIFFERENT inode. ----
do {
    // (a) pre-sync injection via the "out" replace seam.
    let (g, p, out) = mkNestedOut(); let f = produce(out)
    let errRep = runRepaired(out, baseDocs(), f, replace: { if $0 == "out" { replaceParentWithFreshInode(g, p, out) } })
    check("S11a repaired REFUSES parent-replace before pre-sync (full OUT path -> different inode, throws)", errRep != nil)
    check("S11a repaired error reports the full-path no-follow dev/inode substitution",
          { let m = errRep.map { "\($0)" } ?? ""; return m.contains("OUT pathname") && m.contains("full-path no-follow dev/inode changed") }())
    check("S11a repaired preserved the original retained residue at its real location", residuePreserved(movedOutOf(g)))
    check("S11a the substituted OUT path is a DIFFERENT, empty directory (counterexample realized)",
          exists(out.path) && docBytes(out, "statement.json") == nil)
    // SAME injection on the R2 immutable baseline -> incorrectly SUCCEEDS (RED).
    let (g2, p2, out2) = mkNestedOut(); let f2 = produce(out2)
    let errR2 = runRejectedR2(out2, baseDocs(), f2, replace: { if $0 == "out" { replaceParentWithFreshInode(g2, p2, out2) } })
    check("S11a RejectedR2 RED: returns SUCCESS though the full OUT path now resolves to a different inode", errR2 == nil)

    // (b) post-sync injection via the existing retentionFsync "parent" seam.
    let (g3, p3, out3) = mkNestedOut(); let f3 = produce(out3)
    let errRepB = runRepaired(out3, baseDocs(), f3, fsync: { fd, stage in
        let rc = fsync(fd); if stage == "parent" { replaceParentWithFreshInode(g3, p3, out3) }; return rc })
    check("S11b repaired REFUSES parent-replace after dir/parent fsync (post-sync, throws)", errRepB != nil)
    check("S11b repaired error is a [post-sync] full-path dev/inode substitution",
          { let m = errRepB.map { "\($0)" } ?? ""; return m.contains("post-sync") && m.contains("full-path no-follow dev/inode changed") }())
    let (g4, p4, out4) = mkNestedOut(); let f4 = produce(out4)
    let errR2B = runRejectedR2(out4, baseDocs(), f4, fsync: { fd, stage in
        let rc = fsync(fd); if stage == "parent" { replaceParentWithFreshInode(g4, p4, out4) }; return rc })
    check("S11b RejectedR2 RED: returns SUCCESS despite the post-sync full-OUT-path inode substitution", errR2B == nil)
}

// ===================================================================================
// S9. ASSERTION COUNT self-check: emit the exact count so the saved log can be checked to
//     contain exactly this many PASS/FAIL lines (NOT counting the summary line).
// ===================================================================================
print("== CONTROLS SUMMARY ==")
print("ASSERTION-COUNT=\(assertionsRun)")
print(failures == 0 ? "APP-RETENTION-CONTROLS: ALL \(assertionsRun) ASSERTIONS PASS"
                    : "APP-RETENTION-CONTROLS: \(failures) of \(assertionsRun) ASSERTIONS FAILED")
exit(failures == 0 ? 0 : 1)
