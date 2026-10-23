// main.swift — RETENTION FAULT-INJECTION harness (SWIFT04 repair3; preservation
// assertions STRENGTHENED in repair5).
//
// The review (SWIFT04) required: "Add retention fault-injection tests covering
// document writes, result/console verification, file/directory sync and
// preservation on failure." repair2 shipped NONE (it only asserted the control
// flow by inspection). This harness drives the EXACT production retention sequence
// (RetentionV3.performDurableRetention, the same call V3Launch makes) with injected
// faults and asserts, for each, that:
//   (1) the fault is detected (performDurableRetention THROWS), and
//   (2) the destructive-cleanup GATE holds: because the throw happens before the
//       caller's dropScratch(), a sentinel "scratch" file created up-front is
//       PRESERVED (not dropped) — i.e. a failed retention never destroys state, and
//   (3) PRESERVATION IS COMPLETE: EVERY evidence document the sequence had already
//       written before the fault is still on disk WITH ITS EXACT BYTES, and BOTH
//       pre-existing backend files (result.img vdd + console) are still on disk with
//       their exact produced bytes.
// SWIFT05: success and failure both preserve scratch and report deferred residue.
// Retention success proves evidence durability, never namespace exclusivity.
//
// SWIFT04 repair5: repair4's preservation assertion was `docs.contains { exists }`
// (anyDocDurable) — it passed if ONLY ONE document survived and NEVER re-read the
// result/console bytes. The review rejected that: "the four new fsync cases pass if
// only one document survives, without checking all already-written documents or the
// result/console bytes." Every failure case now audits ALL already-written
// documents and BOTH backend files by exact bytes (auditPreserved). The final block
// REPRODUCES the reviewer's counterexample: against a deliberately degraded OUT, the
// repair4 `anyDocDurable` assertion still PASSES while the repair5 strict audit
// FAILS (detects the lost/corrupted evidence).
//
// Pure Foundation/Darwin/CryptoKit — no HVF, App Attest, native archive or VM.
import CryptoKit
import Darwin
import Foundation

func mkTmpDir() -> URL {
    let base = FileManager.default.temporaryDirectory
    let dir = base.appendingPathComponent("retention-fault-\(UUID().uuidString)", isDirectory: true)
    try! FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    return dir
}

func write(_ url: URL, _ d: Data) { try! d.write(to: url, options: .atomic) }
func exists(_ p: String) -> Bool { FileManager.default.fileExists(atPath: p) }
func fileBytes(_ path: String) -> Data? { FileManager.default.contents(atPath: path) }
func docBytes(_ out: URL, _ name: String) -> Data? { fileBytes(out.appendingPathComponent(name).path) }

var failures = 0
func check(_ label: String, _ cond: Bool) {
    print("  \(cond ? "PASS" : "FAIL") \(label)")
    if !cond { failures += 1 }
}

// A representative retained document set (shape mirrors V3Launch: a mix of JSON,
// CBOR and raw bytes). Content is arbitrary — the retention mechanism is
// content-agnostic; only durability + the file verifications are under test.
func baseDocs() -> [RetainedDocV3] {
    return [
        RetainedDocV3("envelope.json", Data(#"{"schema":"x","status":"halted"}"#.utf8)),
        RetainedDocV3("statement.json", Data(#"{"schema":"v3"}"#.utf8)),
        RetainedDocV3("launch-assertion.cbor", Data([0xa1, 0x01, 0x02])),
        RetainedDocV3("result-client-data.bin", Data([0x00, 0x01, 0x02, 0x03])),
        RetainedDocV3("compose-manifest.bin", Data("manifest-bytes".utf8)),
        RetainedDocV3("admission.json", Data(#"{"decision":"admit"}"#.utf8)),
        RetainedDocV3("trace.jsonl", Data("{}\n".utf8)),
    ]
}

// Create the two backend-produced files (result.img vdd + console) in OUT with
// known content, and return the RetainedFileV3 verifications bound to the TRUE
// digest/length (so the success path verifies) — or a deliberately WRONG
// expectation (to inject a verification fault).
struct Produced { let resultPath: String; let consolePath: String; let verifs: [RetainedFileV3] }
func produceBackendFiles(_ out: URL, resultBytes: Data, consoleBytes: Data,
                         resultSha: String? = nil, resultLen: Int? = nil,
                         consoleSha: String? = nil) -> Produced {
    let rp = out.appendingPathComponent("result.img").path
    let cp = out.appendingPathComponent("console-v3.log").path
    write(URL(fileURLWithPath: rp), resultBytes)
    write(URL(fileURLWithPath: cp), consoleBytes)
    let rSha = resultSha ?? SHA256.hash(data: resultBytes).map { String(format: "%02x", $0) }.joined()
    let cSha = consoleSha ?? SHA256.hash(data: consoleBytes).map { String(format: "%02x", $0) }.joined()
    return Produced(resultPath: rp, consolePath: cp, verifs: [
        RetainedFileV3(path: rp, expectSha256: rSha, expectBytes: resultLen ?? resultBytes.count, what: "result.img (vdd)"),
        RetainedFileV3(path: cp, expectSha256: cSha, expectBytes: consoleBytes.count, what: "console-v3.log"),
    ])
}

/// Exactly the V3Launch gate: perform retention, and ONLY on success drop the
/// sentinel scratch. Returns whether performDurableRetention threw. `fsyncFault`,
/// when set, is installed as the production fsync seam so a DETERMINISTIC sync
/// failure can be injected at a chosen stage for the duration of this call only.
/// It mutates nothing in OUT on the failure path (cleanup is never reached), so the
/// caller can then `auditPreserved` the whole directory. `replaceHook`, when set, is
/// installed as the production replacement seam so a same-UID PATHNAME replacement
/// can be injected at a chosen window (APP-SCOPE-02 controls) for this call only.
func gatedRetain(_ out: URL, _ docs: [RetainedDocV3], _ verifs: [RetainedFileV3],
                 fsyncFault: ((_ fd: Int32, _ stage: String) -> Int32)? = nil,
                 replaceHook: ((_ stage: String) -> Void)? = nil,
                 beforeReport: (() -> Void)? = nil) -> Bool {
    let scratch = out.appendingPathComponent("scratch.img").path
    write(URL(fileURLWithPath: scratch), Data("throwaway".utf8))
    retentionFsyncOverride = fsyncFault
    retentionReplaceHook = replaceHook
    defer { retentionFsyncOverride = nil; retentionReplaceHook = nil }
    do {
        try performDurableRetention(outDir: out, documents: docs, verifications: verifs)
        // success path: cleanup is reached and drops ONLY the throwaway scratch.
        beforeReport?()
        let residue = reportDeferredResidue(paths: [scratch])
        check("success_reports_deferred_unconfirmed", residue.status == "deferred-unconfirmed")
        do { try residue.requireResidueFree(); check("residue_free_policy_refused", false) }
        catch { check("residue_free_policy_refused", true) }
        return false
    } catch {
        // failure path: dropScratch() is NOT reached — OUT (incl. scratch + every
        // already-written evidence document and both backend files) preserved.
        beforeReport?()
        let residue = reportDeferredResidue(paths: [scratch])
        check("failure_reports_deferred_unconfirmed", residue.status == "deferred-unconfirmed" && residue.paths == [scratch])
        print("      detected: \(error)")
        return true
    }
}

/// Build a fault closure that forces fsync to fail (errno=EIO, rc=-1) the FIRST
/// time the given stage predicate matches, and otherwise performs the REAL fsync.
/// This exercises a genuine fsync failure at one production stage while every other
/// stage syncs normally.
func fsyncFaultAt(_ matches: @escaping (String) -> Bool) -> (Int32, String) -> Int32 {
    var fired = false
    return { fd, stage in
        if !fired && matches(stage) { fired = true; errno = EIO; return -1 }
        return fsync(fd)
    }
}

/// Per-aspect verdict that a FAILED retention PRESERVED all already-written evidence
/// intact (SWIFT04 repair5). A failed retention must never destroy or corrupt state:
///   - the throwaway scratch must still exist (cleanup gate held),
///   - EVERY document in `writtenDocs` (the ones the sequence had written before the
///     fault) must be on disk with its EXACT expected bytes, and
///   - EACH pre-existing backend file must be on disk with its EXACT produced bytes.
/// Returns a bool per aspect so each assertion is explicit (repair4 asserted only
/// `docs.contains { exists }` — true if a single document survived, and never
/// re-read any backend bytes).
struct Preserved { let scratch: Bool; let allDocs: Bool; let backend: Bool; let detail: String }
func auditPreserved(out: URL, writtenDocs: [RetainedDocV3],
                    backend: [(path: String, bytes: Data, what: String)]) -> Preserved {
    let scratch = exists(out.appendingPathComponent("scratch.img").path)
    var allDocs = true
    var lost: [String] = []
    for d in writtenDocs {
        if let got = docBytes(out, d.name), got == d.bytes { continue }
        allDocs = false; lost.append("doc:\(d.name)")
    }
    var backendOk = true
    for f in backend {
        if let got = fileBytes(f.path), got == f.bytes { continue }
        backendOk = false; lost.append("backend:\(f.what)")
    }
    let detail = lost.isEmpty ? "all \(writtenDocs.count) docs + \(backend.count) backend files intact" : "LOST/CORRUPT: \(lost.joined(separator: ", "))"
    return Preserved(scratch: scratch, allDocs: allDocs, backend: backendOk, detail: detail)
}

let resultData = Data(repeating: 0x5a, count: 2048)   // 2 KiB "vdd" bytes
let consoleData = Data("hello guest console\n".utf8)
func backendRef(_ p: Produced) -> [(path: String, bytes: Data, what: String)] {
    return [(p.resultPath, resultData, "result.img (vdd)"), (p.consolePath, consoleData, "console-v3.log")]
}

print("== retention fault-injection (drives RetentionV3.performDurableRetention) ==")

// (0) SUCCESS: gate RELEASES — retention completes, scratch dropped, docs durable.
do {
    let out = mkTmpDir()
    let p = produceBackendFiles(out, resultBytes: resultData, consoleBytes: consoleData)
    let threw = gatedRetain(out, baseDocs(), p.verifs)
    let scratchPreserved = exists(out.appendingPathComponent("scratch.img").path)
    // every document durable with EXACT bytes, and both backend files intact.
    let a = auditPreserved(out: out, writtenDocs: baseDocs(), backend: backendRef(p))
    check("success_retention_completes", !threw)
    check("success_scratch_preserved_after_complete_retention", scratchPreserved)
    check("success_all_documents_durable_exact_bytes", a.allDocs)
    check("success_backend_files_intact_exact_bytes", a.backend)
}

// SWIFT05 actual retention success/fault + replacement before residue report.
for fail in [false, true] {
    let out = mkTmpDir()
    let p = produceBackendFiles(out, resultBytes: resultData, consoleBytes: consoleData)
    let scratch = out.appendingPathComponent("scratch.img")
    let foreign = Data("foreign replacement must survive".utf8)
    let fault: ((Int32, String) -> Int32)? = fail ? { _, _ in errno = EIO; return -1 } : nil
    let threw = gatedRetain(out, baseDocs(), p.verifs, fsyncFault: fault, beforeReport: {
        // Adversarial test action only; production cleanup performs no unlink.
        try! FileManager.default.removeItem(at: scratch)
        write(scratch, foreign)
    })
    check("replacement_\(fail ? "failure" : "success")_outcome", threw == fail)
    check("replacement_\(fail ? "failure" : "success")_survives", fileBytes(scratch.path) == foreign)
    // Missing names and an empty registry still cannot establish residue-free completion.
    do { try deferredResidue(paths: []).requireResidueFree(); check("empty_registry_refuses_residue_free", false) }
    catch { check("empty_registry_refuses_residue_free", true) }
}

// (1) UNCONFINED / NON-COMPLETE INVENTORY: a document name that is not a single
//     confined OUT component ("does-not-exist-subdir/evil.json") is rejected by the
//     finite contract's UP-FRONT complete-inventory validation (confined unique
//     names, APP-RETENTION-BOUNDARY-DECISION.json "no partial-set success") BEFORE
//     the owned OUT dirfd is opened or ANY document is written. Detected; scratch
//     preserved; NO document is written at all (no partial set); backend files
//     intact. (The accepted candidate instead let an atomic write escape into a
//     non-existent subdir and only failed mid-sequence after writing docs 0..1.)
do {
    let out = mkTmpDir()
    var docs = baseDocs()
    docs.insert(RetainedDocV3("does-not-exist-subdir/evil.json", Data("x".utf8)), at: 2)
    let p = produceBackendFiles(out, resultBytes: resultData, consoleBytes: consoleData)
    let threw = gatedRetain(out, docs, p.verifs)
    // No partial set: none of the valid documents were written either.
    let noneWritten = !baseDocs().contains { exists(out.appendingPathComponent($0.name).path) }
    let a = auditPreserved(out: out, writtenDocs: [], backend: backendRef(p))
    check("unconfined_name_refused_up_front", threw)
    check("unconfined_name_writes_no_partial_set", noneWritten)
    check("unconfined_name_preserves_scratch", a.scratch)
    check("unconfined_name_preserves_backend_files", a.backend)
}

// (2) RESULT verification fault — DIGEST mismatch. All documents are written in
//     stage 1 before verification, so ALL must be durable; both backend files are
//     unchanged on disk (the fault is a wrong COMMITTED digest, not altered bytes).
do {
    let out = mkTmpDir()
    let wrong = String(repeating: "00", count: 32)
    let p = produceBackendFiles(out, resultBytes: resultData, consoleBytes: consoleData, resultSha: wrong)
    let threw = gatedRetain(out, baseDocs(), p.verifs)
    let a = auditPreserved(out: out, writtenDocs: baseDocs(), backend: backendRef(p))
    check("result_digest_fault_detected", threw)
    check("result_digest_fault_preserves_scratch", a.scratch)
    check("result_digest_fault_preserves_all_documents", a.allDocs)
    check("result_digest_fault_preserves_backend_files", a.backend)
}

// (3) RESULT verification fault — LENGTH mismatch: committed length != on-disk size.
do {
    let out = mkTmpDir()
    let p = produceBackendFiles(out, resultBytes: resultData, consoleBytes: consoleData, resultLen: 4096)
    let threw = gatedRetain(out, baseDocs(), p.verifs)
    let a = auditPreserved(out: out, writtenDocs: baseDocs(), backend: backendRef(p))
    check("result_length_fault_detected", threw)
    check("result_length_fault_preserves_scratch", a.scratch)
    check("result_length_fault_preserves_all_documents", a.allDocs)
    check("result_length_fault_preserves_backend_files", a.backend)
}

// (4) CONSOLE verification fault — DIGEST mismatch (verified on EVERY path).
do {
    let out = mkTmpDir()
    let wrong = String(repeating: "ff", count: 32)
    let p = produceBackendFiles(out, resultBytes: resultData, consoleBytes: consoleData, consoleSha: wrong)
    let threw = gatedRetain(out, baseDocs(), p.verifs)
    let a = auditPreserved(out: out, writtenDocs: baseDocs(), backend: backendRef(p))
    check("console_digest_fault_detected", threw)
    check("console_digest_fault_preserves_scratch", a.scratch)
    check("console_digest_fault_preserves_all_documents", a.allDocs)
    check("console_digest_fault_preserves_backend_files", a.backend)
}

// (5) MISSING backend file: result.img absent entirely → verification refuses.
//     result.img is the injected-missing fault, so only the console backend file is
//     asserted present; all documents (written in stage 1) are still durable.
do {
    let out = mkTmpDir()
    let p = produceBackendFiles(out, resultBytes: resultData, consoleBytes: consoleData)
    try? FileManager.default.removeItem(atPath: p.resultPath)   // backend file vanished
    let threw = gatedRetain(out, baseDocs(), p.verifs)
    let a = auditPreserved(out: out, writtenDocs: baseDocs(),
                           backend: [(p.consolePath, consoleData, "console-v3.log")])
    check("missing_result_file_detected", threw)
    check("missing_result_file_preserves_scratch", a.scratch)
    check("missing_result_file_preserves_all_documents", a.allDocs)
    check("missing_result_file_preserves_console", a.backend)
}

// ---- fsync faults driven THROUGH performDurableRetention (SWIFT04 repair4;
// ---- preservation assertions STRENGTHENED repair5) ----
// These four inject a DETERMINISTIC fsync() failure (EIO) at each real sync stage of
// the EXACT production performDurableRetention, and assert that each (a) is detected
// (throws), (b) preserves the sentinel scratch (cleanup gate holds) and (c)
// preserves EVERY document already written before the fault AND BOTH backend files,
// each verified by EXACT bytes (repair5 — not merely "one document still exists").

// (6) DOCUMENT-FILE fsync fault: fail the fsync of the 4th document
//     (result-client-data.bin). Documents 0..2 fsync normally; doc 3's atomic write
//     lands then its fsync fails → throw. So docs 0..3 are all on disk and MUST be
//     intact with exact bytes ("every document written before that failure"); both
//     backend files intact; scratch preserved.
do {
    let out = mkTmpDir()
    let docs = baseDocs()
    let p = produceBackendFiles(out, resultBytes: resultData, consoleBytes: consoleData)
    let threw = gatedRetain(out, docs, p.verifs,
        fsyncFault: fsyncFaultAt { $0 == "doc:result-client-data.bin" })
    let a = auditPreserved(out: out, writtenDocs: Array(docs[0...3]), backend: backendRef(p))
    print("      preserved: \(a.detail)")
    check("doc_fsync_fault_detected", threw)
    check("doc_fsync_fault_preserves_scratch", a.scratch)
    check("doc_fsync_fault_preserves_all_written_docs", a.allDocs)
    check("doc_fsync_fault_preserves_backend_files", a.backend)
}

// (7) RESULT (vdd) fsync fault: by this stage ALL documents are written+fsynced and
//     result.img verified (sha/size) — its fsync then fails. ALL documents and BOTH
//     backend files must be intact.
do {
    let out = mkTmpDir()
    let docs = baseDocs()
    let p = produceBackendFiles(out, resultBytes: resultData, consoleBytes: consoleData)
    let threw = gatedRetain(out, docs, p.verifs,
        fsyncFault: fsyncFaultAt { $0 == "file:result.img (vdd)" })
    let a = auditPreserved(out: out, writtenDocs: docs, backend: backendRef(p))
    print("      preserved: \(a.detail)")
    check("result_fsync_fault_detected", threw)
    check("result_fsync_fault_preserves_scratch", a.scratch)
    check("result_fsync_fault_preserves_all_documents", a.allDocs)
    check("result_fsync_fault_preserves_backend_files", a.backend)
}

// (8) CONSOLE fsync fault: all documents written, result.img verified+fsynced,
//     console verified — its fsync then fails. ALL documents + BOTH backend files
//     intact.
do {
    let out = mkTmpDir()
    let docs = baseDocs()
    let p = produceBackendFiles(out, resultBytes: resultData, consoleBytes: consoleData)
    let threw = gatedRetain(out, docs, p.verifs,
        fsyncFault: fsyncFaultAt { $0 == "file:console-v3.log" })
    let a = auditPreserved(out: out, writtenDocs: docs, backend: backendRef(p))
    print("      preserved: \(a.detail)")
    check("console_fsync_fault_detected", threw)
    check("console_fsync_fault_preserves_scratch", a.scratch)
    check("console_fsync_fault_preserves_all_documents", a.allDocs)
    check("console_fsync_fault_preserves_backend_files", a.backend)
}

// (9) DIRECTORY fsync fault: the OUT-directory fsync (last stage) fails. Documents
//     written and both backend files verified, then the directory sync fails, so
//     cleanup is still gated and OUT preserved intact — ALL documents + BOTH backend
//     files.
do {
    let out = mkTmpDir()
    let docs = baseDocs()
    let p = produceBackendFiles(out, resultBytes: resultData, consoleBytes: consoleData)
    let threw = gatedRetain(out, docs, p.verifs,
        fsyncFault: fsyncFaultAt { $0 == "dir" })
    let a = auditPreserved(out: out, writtenDocs: docs, backend: backendRef(p))
    print("      preserved: \(a.detail)")
    check("dir_fsync_fault_detected", threw)
    check("dir_fsync_fault_preserves_scratch", a.scratch)
    check("dir_fsync_fault_preserves_all_documents", a.allDocs)
    check("dir_fsync_fault_preserves_backend_files", a.backend)
}

// ---- SWIFT04 repair5: reviewer counterexample for the weak preservation check ----
// The review rejected repair4's assertion: "the four new fsync cases pass if only
// one document survives, without checking all already-written documents or the
// result/console bytes." This block builds an OUT exactly as a fault would leave it
// (scratch + all docs + both backend files preserved) and then applies a DESTRUCTIVE
// mutation that a too-weak retention would allow: it deletes all but the FIRST
// document and corrupts the result.img bytes. It then evaluates BOTH assertions:
//   - repair4's `anyDocDurable` == `docs.contains { exists }`  → still TRUE (the
//     first document survives) → the repair4 case would have WRONGLY PASSED, and
//   - repair5's strict `auditPreserved` (all docs exact bytes + backend exact bytes)
//     → FALSE → the lost documents and corrupted result bytes are DETECTED.
print("== SWIFT04 repair5: weak-vs-strict preservation (reviewer counterexample) ==")
func repair4AnyDocDurable(_ out: URL, _ docs: [RetainedDocV3]) -> Bool {
    return docs.contains { exists(out.appendingPathComponent($0.name).path) }   // repair4 logic, verbatim
}
do {
    let out = mkTmpDir()
    let docs = baseDocs()
    let p = produceBackendFiles(out, resultBytes: resultData, consoleBytes: consoleData)
    // Simulate "after a fault" state, then DEGRADE it (what a weak retention permits):
    for d in docs { write(out.appendingPathComponent(d.name), d.bytes) }
    write(URL(fileURLWithPath: out.appendingPathComponent("scratch.img").path), Data("throwaway".utf8))
    // destructive mutation: drop every doc except the first, corrupt result.img.
    for d in docs.dropFirst() { try? FileManager.default.removeItem(atPath: out.appendingPathComponent(d.name).path) }
    write(URL(fileURLWithPath: p.resultPath), Data(repeating: 0x00, count: resultData.count))   // corrupted bytes (same length)

    let weak = repair4AnyDocDurable(out, docs)
    let strict = auditPreserved(out: out, writtenDocs: docs, backend: backendRef(p))
    print("      repair4 anyDocDurable=\(weak)  repair5 allDocs=\(strict.allDocs) backend=\(strict.backend)")
    print("      repair5 detail: \(strict.detail)")
    // The counterexample: the weak check is satisfied though evidence was lost/corrupt.
    check("repair4_weak_check_wrongly_passes_on_degraded_out", weak == true)
    // The fix detects the lost documents...
    check("repair5_strict_detects_lost_documents", strict.allDocs == false)
    // ...and the corrupted result bytes (which the weak check never re-read).
    check("repair5_strict_detects_corrupted_result_bytes", strict.backend == false)
}

// ======================================================================================
// APP-SCOPE-02 same-UID REPLACEMENT controls (APP-RETENTION-BOUNDARY-DECISION.json).
// These drive the EXACT production performDurableRetention with a same-UID PATHNAME
// replacement injected at the precise windows the ACCEPTED candidate was vulnerable at
// (document after creation; the former stat/hash/open window; the OUT pathname), plus
// missing/short/extra byte bounds. Each control is shown GREEN against the repaired
// owned-descriptor sequence (detected + refused, or owned bytes bound) and RED against
// the accepted logic reproduced verbatim below (silent desync: wrong bytes synchronized
// while returning success). "baseline detects the defect, repaired SAME control passes."
// ======================================================================================
print("== APP-SCOPE-02: same-UID replacement controls (through performDurableRetention) ==")

func shaHex(_ d: Data) -> String { SHA256.hash(data: d).map { String(format: "%02x", $0) }.joined() }

/// Replace the inode answering a NAME with a DIFFERENT inode (same path, new bytes) —
/// a harmless local model of a same-UID replacement; it performs no privileged action.
func replaceFile(_ path: String, with bytes: Data) {
    try? FileManager.default.removeItem(atPath: path)
    write(URL(fileURLWithPath: path), bytes)
}

// Accepted-candidate (pre-APP-SCOPE-02) logic reproduced VERBATIM so the SAME controls
// are RED against it. `hook(stage)` fires at the exact window the accepted code exposed:
// between the atomic write and the reopen (saveDurable), and between sha256File and the
// SEPARATE reopen-for-fsync (verifyRetainedFile) — the stat/hash/open gap the gate named.
func baselineSaveDurable(_ name: String, _ d: Data, in dir: URL, hook: ((String) -> Void)? = nil) throws {
    let url = dir.appendingPathComponent(name)
    try d.write(to: url, options: .atomic)                 // atomic write
    hook?("doc:\(name)")                                   // same-UID replacement window
    let fd = open(url.path, O_RDONLY)                      // reopen-by-path, no content/inode re-check
    guard fd >= 0 else { throw Fail("cannot reopen \(name) to fsync") }
    defer { close(fd) }
    guard fsync(fd) == 0 else { throw Fail("fsync \(name) failed") }
}
func baselineVerifyRetainedFile(_ path: String, expectSha256: String, expectBytes: Int, what: String,
                                hook: ((String) -> Void)? = nil) throws {
    var st = stat()
    guard stat(path, &st) == 0 else { throw Fail("retained \(what) missing") }      // resolution #1
    guard Int(st.st_size) == expectBytes else { throw Fail("retained \(what) wrong length") }
    let got = try sha256File(path)                                                  // resolution #2 (hash)
    guard got == expectSha256 else { throw Fail("retained \(what) digest mismatch") }
    hook?("file:\(what)")                                                           // replacement window
    let fd = open(path, O_RDONLY)                                                   // resolution #3 (fsync)
    guard fd >= 0 else { throw Fail("cannot reopen retained \(what) to fsync") }
    defer { close(fd) }
    guard fsync(fd) == 0 else { throw Fail("fsync retained \(what) failed") }
}

// (R1) DOCUMENT replacement AFTER CREATION. Repaired: the bytes were validated through
//      the OWNED descriptor and the directory stage re-confirms the entry dev/inode, so
//      the substitution is DETECTED and retention REFUSES; residue is preserved.
do {
    let out = mkTmpDir()
    let p = produceBackendFiles(out, resultBytes: resultData, consoleBytes: consoleData)
    let target = out.appendingPathComponent("statement.json").path
    let foreign = Data(#"{"schema":"FOREIGN-REPLACEMENT"}"#.utf8)
    let threw = gatedRetain(out, baseDocs(), p.verifs, replaceHook: { stage in
        if stage == "doc:statement.json" { replaceFile(target, with: foreign) }
    })
    check("app02_doc_replacement_detected_and_refused", threw)
    // Baseline contrast (RED): reopen-by-path fsyncs WITHOUT re-check, so the foreign
    // bytes are left on disk and the call returns success — silent desync.
    let bout = mkTmpDir()
    var baselineAccepted = true
    do {
        for d in baseDocs() {
            try baselineSaveDurable(d.name, d.bytes, in: bout, hook: { stage in
                if stage == "doc:statement.json" { replaceFile(bout.appendingPathComponent("statement.json").path, with: foreign) }
            })
        }
    } catch { baselineAccepted = false }
    check("app02_doc_baseline_desyncs_silently", baselineAccepted && docBytes(bout, "statement.json") == foreign)
}

// (R2) BACKEND FILE replacement at the FORMER STAT/HASH/OPEN WINDOW. Repaired: result.img
//      is opened ONCE and fstat/read/digest/fsync bind to that owned descriptor; the
//      directory stage re-confirms the entry dev/inode — so the swap is DETECTED/REFUSED.
do {
    let out = mkTmpDir()
    let p = produceBackendFiles(out, resultBytes: resultData, consoleBytes: consoleData)
    let evil = Data(repeating: 0xEE, count: resultData.count)   // same length, different inode/content
    let threw = gatedRetain(out, baseDocs(), p.verifs, replaceHook: { stage in
        if stage == "file:result.img (vdd)" { replaceFile(p.resultPath, with: evil) }
    })
    check("app02_backend_window_replacement_detected_and_refused", threw)
    // Baseline contrast (RED): stat/hash pass on the ORIGINAL inode, the pathname is
    // swapped, then a SEPARATE open(path) fsyncs the EVIL inode and returns success —
    // the inode synchronized is NOT the inode validated.
    let bout = mkTmpDir()
    let bp = produceBackendFiles(bout, resultBytes: resultData, consoleBytes: consoleData)
    var baselineAccepted = true
    do {
        try baselineVerifyRetainedFile(bp.resultPath, expectSha256: shaHex(resultData), expectBytes: resultData.count,
                                       what: "result.img (vdd)", hook: { stage in
            if stage == "file:result.img (vdd)" { replaceFile(bp.resultPath, with: evil) }
        })
    } catch { baselineAccepted = false }
    check("app02_backend_baseline_syncs_unvalidated_bytes", baselineAccepted && fileBytes(bp.resultPath) == evil)
}

// (R3) OUT PATHNAME replacement. Repaired: the owned no-follow dirfd is held throughout
//      and the directory stage re-confirms stat(OUT) maps the owned dirfd, so the remap
//      is DETECTED/REFUSED. (The accepted fsyncDir reopened OUT by path with no mapping
//      check, so it would have fsynced whatever answered the name.)
do {
    let out = mkTmpDir()
    let p = produceBackendFiles(out, resultBytes: resultData, consoleBytes: consoleData)
    let threw = gatedRetain(out, baseDocs(), p.verifs, replaceHook: { stage in
        if stage == "out" {
            let decoy = out.deletingLastPathComponent().appendingPathComponent("decoy-\(UUID().uuidString)")
            try? FileManager.default.moveItem(at: out, to: decoy)
            try? FileManager.default.createDirectory(at: out, withIntermediateDirectories: false)
        }
    })
    check("app02_out_pathname_replacement_detected_and_refused", threw)
}

// (R4) MISSING / SHORT / EXTRA bytes bound by fstat exact length on the owned descriptor.
do {
    let out1 = mkTmpDir()   // SHORT: on-disk 1024, backend committed 2048
    let p1 = produceBackendFiles(out1, resultBytes: Data(repeating: 0x5a, count: 1024), consoleBytes: consoleData,
                                 resultSha: shaHex(resultData), resultLen: resultData.count)
    check("app02_short_bytes_refused", gatedRetain(out1, baseDocs(), p1.verifs))
    let out2 = mkTmpDir()   // EXTRA: on-disk 4096, backend committed 2048
    let p2 = produceBackendFiles(out2, resultBytes: Data(repeating: 0x5a, count: 4096), consoleBytes: consoleData,
                                 resultSha: shaHex(resultData), resultLen: resultData.count)
    check("app02_extra_bytes_refused", gatedRetain(out2, baseDocs(), p2.verifs))
    let out3 = mkTmpDir()   // MISSING: result.img absent entirely
    let p3 = produceBackendFiles(out3, resultBytes: resultData, consoleBytes: consoleData)
    try? FileManager.default.removeItem(atPath: p3.resultPath)
    check("app02_missing_file_refused", gatedRetain(out3, baseDocs(), p3.verifs))
}

// (R5) NON-REGULAR retained object: a directory answering a document name is refused
//      (exclusive create collision) and a non-regular backend path is refused (fstat
//      S_ISREG). Both are owned-descriptor validations the accepted stat()-only path
//      did not perform.
do {
    let out = mkTmpDir()
    // A directory already occupying a document name → O_EXCL create collision refusal.
    try! FileManager.default.createDirectory(at: out.appendingPathComponent("statement.json"), withIntermediateDirectories: false)
    let p = produceBackendFiles(out, resultBytes: resultData, consoleBytes: consoleData)
    check("app02_doc_name_collision_refused", gatedRetain(out, baseDocs(), p.verifs))
    // A directory occupying a backend file name → fstat regular-file refusal.
    let out2 = mkTmpDir()
    let p2 = produceBackendFiles(out2, resultBytes: resultData, consoleBytes: consoleData)
    try? FileManager.default.removeItem(atPath: p2.resultPath)
    try! FileManager.default.createDirectory(at: URL(fileURLWithPath: p2.resultPath), withIntermediateDirectories: false)
    check("app02_backend_nonregular_refused", gatedRetain(out2, baseDocs(), p2.verifs))
}

// ======================================================================================
// APP-SCOPE-01 legacy cleanup boundary: the removed automatic layout deletion vs the
// repaired non-destructive own()->dropScratch()->reportDeferredResidue path. Exercises
// the ACTUAL DeferredCleanup boundary. The full hvf-v3 run path needs HVF (out of unit
// scope — no VM), but the destructive-vs-nondestructive decision IS exactly this.
// ======================================================================================
print("== APP-SCOPE-01: legacy cleanup boundary is non-destructive (DeferredCleanup) ==")
do {
    let foreign = Data("foreign replacement at the oci-layout pathname must survive".utf8)
    // Baseline legacy behavior (main.swift:610 verbatim): automatic pathname deletion.
    let bout = mkTmpDir()
    let blayout = bout.appendingPathComponent("oci-layout").path
    write(URL(fileURLWithPath: blayout), foreign)
    try? FileManager.default.removeItem(atPath: blayout)          // destroys a same-UID replacement
    check("app01_baseline_destroys_replacement", !exists(blayout))
    // Repaired behavior: no deletion; path flows through the non-destructive boundary,
    // the replacement survives, and cleanup is reported deferred-unconfirmed (never
    // residue-free).
    let out = mkTmpDir()
    let layout = out.appendingPathComponent("oci-layout").path
    write(URL(fileURLWithPath: layout), foreign)
    let residue = reportDeferredResidue(paths: [layout])
    check("app01_repaired_preserves_replacement", fileBytes(layout) == foreign)
    check("app01_repaired_reports_deferred_unconfirmed", residue.status == "deferred-unconfirmed" && residue.paths == [layout])
    do { try residue.requireResidueFree(); check("app01_repaired_refuses_residue_free", false) }
    catch { check("app01_repaired_refuses_residue_free", true) }
}

print(failures == 0 ? "RETENTION FAULT-INJECTION: ALL PASS" : "RETENTION FAULT-INJECTION: \(failures) FAILURE(S)")
exit(failures == 0 ? 0 : 1)
