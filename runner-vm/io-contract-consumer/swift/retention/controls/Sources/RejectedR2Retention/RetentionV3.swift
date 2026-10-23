// RetentionV3.swift — the DURABLE-COMPLETE-RETENTION mechanism for the v3 launch
// path, factored out of V3Launch.swift (SWIFT04 repair3) so it is exercisable by
// an independent fault-injection harness WITHOUT the HVF backend, App Attest, the
// native archive or a VM.
//
// APP-SCOPE-02 repair, round 2 (APP-RETENTION-BOUNDARY-DECISION.json,
// schema dsmack-finite-app-retention-contract/1). The accepted candidate bound its
// "durable complete retention" claim to bytes it never held a descriptor to:
// saveDurable atomically wrote a document then REOPENED its pathname to fsync
// WITHOUT re-checking content/inode, and verifyRetainedFile performed independent
// stat(path) -> sha256File(path) -> open(path) resolutions. A same-UID replacement
// between any two of those path resolutions let a DIFFERENT object be hashed, or
// synchronized, while the operation returned success. The round-1 rewrite bound each
// validated byte to an owned descriptor BUT closed each artifact descriptor when its
// helper returned (before the directory stage), re-checked entries only by HISTORICAL
// inode numbers (not a still-owned reference), never re-read content AFTER fsync,
// checked the OUT pathname with a FOLLOWING stat(), and did not synchronize the
// parent that received a newly created OUT. Root rejected that as incomplete against
// the finite-descriptor contract (APP-SCOPE-02-R1-FD-LIFETIME / -POSTSYNC /
// -DIRECTORY).
//
// This round-2 rewrite enforces the full contract:
//  * performDurableRetention owns a no-follow OUT directory descriptor throughout AND
//    a no-follow descriptor to OUT's ESTABLISHED parent; it validates the complete
//    inventory of confined, unique names up front (no partial-set success).
//  * Each document is written by EXCLUSIVE CREATE relative to the owned OUT dirfd, its
//    exact generated length + content verified and fsynced through the SAME descriptor,
//    which is then RETAINED OPEN (not closed in the helper).
//  * Each backend-produced file is opened ONCE relative to the owned OUT dirfd,
//    no-follow; fstat (regular + exact committed length), a bounded read + digest +
//    trailing-byte check and fsync bind to that SAME descriptor, which is RETAINED OPEN.
//    The pathname is never independently stat/hash/reopened.
//  * finalizeDirectory re-confirms, no-follow, BEFORE AND AFTER the directory/parent
//    fsync, that (a) the OUT entry in its parent still maps (dev/inode) the owned OUT
//    and (b) every retained OUT entry still maps the exact object this sequence owns
//    (compared against the STILL-OPEN owned fd's captured dev/inode — inode reuse is
//    excluded by the retained reference, APP-SCOPE-02-R1-FD-LIFETIME). It fsyncs the
//    OUT directory AND then the established parent so the (possibly newly created) OUT
//    directory entry is itself durable (APP-SCOPE-02-R1-DIRECTORY).
//  * After synchronization it CONSERVATIVELY RE-READS each retained artifact's exact
//    committed length + content/digest THROUGH its retained descriptor
//    (APP-SCOPE-02-R1-POSTSYNC), so a same-inode modification that the dev/inode
//    mapping cannot see is still caught.
//  * Every owned descriptor (OUT dir, parent dir, and every artifact) is closed exactly
//    once, on BOTH success and failure. Any observed substitution, disappearance,
//    mapping mismatch, post-sync content change or required I/O error throws (retention
//    unconfirmed/refuse); nothing is unlinked and all possible residue is preserved.
//
// EXACT GUARANTEE on success: every required artifact was verified against its expected
// bytes THROUGH its own owned, retained descriptor both before and after the fsyncs;
// the required OUT-directory and parent-directory fsyncs succeeded; and the sequential
// no-follow name->object mapping observations passed before and after synchronization.
// WHAT IS NOT GUARANTEED (stated, not silently strengthened): owned descriptors prevent
// a pathname replacement from redirecting THAT descriptor, not same-inode writes — the
// post-sync re-read is a FINITE OBSERVATION of the committed bytes at that instant, NOT
// a claim of immutability or an atomic simultaneous snapshot under hostile mutation; and
// nothing here guarantees against a subsequent unlink/replacement/corruption or an
// indefinitely-available pathname after the sequence's last defined observation
// (0700/random names are NOT a same-UID writer exclusion). Downstream transfer/checkers
// must independently verify the actually delivered bytes. Success proves evidence
// retention only. SWIFT05: the caller preserves all possible host residue and reports
// deferred/unconfirmed cleanup on both paths; NO retention operation authorizes pathname
// deletion.
//
// Helpers bind to the OUT the caller passes (not the main.swift `out` global) so the
// harness can point them at a scratch temp dir whose parent is established. `Fail` is
// provided by the app (main.swift) for the mar build and by the test shim for the
// standalone harness; this file defines neither. Digests are computed over
// owned-descriptor bytes with CryptoKit (no pathname reopen).

#if canImport(Darwin)
import CryptoKit
import Darwin
import Foundation

/// Test-only fsync seam (SWIFT04 repair4). Production leaves this nil and every
/// sync below calls the real `Darwin.fsync` directly, so the shipped retention
/// sequence is byte-for-byte unchanged. The independent fault-injection harness
/// sets this to force a DETERMINISTIC sync failure at a chosen stage ("doc:<name>",
/// "file:<what>", "dir" or "parent") so the EXACT production `performDurableRetention`
/// can be driven to a real fsync fault and the destructive-cleanup gate asserted. The
/// closure returns the value the real fsync would (0 ok, -1 + errno on failure);
/// V3Launch never sets it.
var retentionFsyncOverride: ((_ fd: Int32, _ stage: String) -> Int32)? = nil

@inline(__always)
private func retentionFsync(_ fd: Int32, _ stage: String) -> Int32 {
    if let o = retentionFsyncOverride { return o(fd, stage) }
    return fsync(fd)
}

/// Test-only replacement seam (APP-SCOPE-02 controls). Production leaves this nil, so
/// the shipped sequence makes no extra call and is byte-for-byte unchanged. The
/// fault-injection harness sets it to simulate a same-UID replacement/modification of a
/// retained object at the EXACT window a path-reopen would have observed it — a document
/// pathname just after its exclusive create ("doc:<name>"), a backend file's former
/// stat/hash/open window ("file:<what>"), the OUT pathname itself ("out"), or a
/// dev/inode substitution injected AFTER the fsyncs and before the post-sync mapping
/// re-confirmation ("postdirsync"), or a same-inode/entry content modification injected
/// after that and before the post-sync content re-read ("postsync"). Because every
/// validated byte is bound to a retained owned
/// descriptor, the repaired sequence does NOT read a substituted object; it detects a
/// dev/inode remap around the directory fsync, an OUT-pathname remap, or a same-inode
/// content change via the post-sync re-read, and refuses. The closure runs for its side
/// effect only and returns nothing.
var retentionReplaceHook: ((_ stage: String) -> Void)? = nil

@inline(__always)
private func retentionReplace(_ stage: String) {
    retentionReplaceHook?(stage)
}

/// One evidence document to retain durably: a file name (written under OUT) and
/// its exact bytes.
struct RetainedDocV3 {
    let name: String
    let bytes: Data
    init(_ name: String, _ bytes: Data) { self.name = name; self.bytes = bytes }
}

/// One backend-produced retained file to re-verify from disk against the exact
/// digest/length the backend committed through its retained descriptor.
struct RetainedFileV3 {
    let path: String
    let expectSha256: String
    let expectBytes: Int
    let what: String
}

/// The retained state for one durable artifact. Holds the OWNED, STILL-OPEN descriptor
/// the sequence wrote/verified/fsynced through (APP-SCOPE-02-R1-FD-LIFETIME), the
/// (name, dev, inode) captured from the fstat of that exact fd — BEFORE any replacement
/// window — and the expected committed length + content digest. The directory-fsync
/// stage re-confirms, no-follow, that the retained directory entry still maps to this
/// object (so a post-creation swap is detectable, not self-cancelling, because the fd is
/// still held); the post-sync stage re-reads the exact length + digest THROUGH this same
/// descriptor. A class so the retained fd has a single, explicit close site in the
/// caller's defer (success and failure).
private final class OwnedArtifact {
    let name: String
    let fd: Int32
    let dev: dev_t
    let ino: ino_t
    let expectBytes: Int
    let expectDigest: String
    let what: String
    init(name: String, fd: Int32, dev: dev_t, ino: ino_t, expectBytes: Int, expectDigest: String, what: String) {
        self.name = name; self.fd = fd; self.dev = dev; self.ino = ino
        self.expectBytes = expectBytes; self.expectDigest = expectDigest; self.what = what
    }
}

// ---- small checked POSIX helpers (all operate on an already-owned descriptor) ----

@inline(__always) private func isReg(_ st: stat) -> Bool { (st.st_mode & S_IFMT) == S_IFREG }
@inline(__always) private func isDir(_ st: stat) -> Bool { (st.st_mode & S_IFMT) == S_IFDIR }

/// A single path COMPONENT confined to OUT: non-empty, not "." / "..", no "/" and no
/// embedded NUL. Rejects any name that could escape or alias the owned directory.
private func requireConfinedName(_ name: String, _ what: String) throws {
    guard !name.isEmpty, name != ".", name != "..",
          !name.contains("/"), !name.contains("\0") else {
        throw Fail("retention \(what) name is not a confined OUT component: \(name)")
    }
}

/// Write EVERY byte of `data` to an owned fd (EINTR-safe, short-write-safe).
private func writeAllOwned(_ fd: Int32, _ data: Data, _ what: String) throws {
    guard !data.isEmpty else { return }
    try data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
        guard let base = raw.baseAddress else { throw Fail("retention \(what): nil buffer") }
        var off = 0
        while off < raw.count {
            let n = write(fd, base.advanced(by: off), raw.count - off)
            if n < 0 { if errno == EINTR { continue }; throw Fail("retention \(what) write failed: \(String(cString: strerror(errno)))") }
            if n == 0 { throw Fail("retention \(what) write returned 0") }
            off += n
        }
    }
}

/// Read EXACTLY `n` bytes from the current offset of an owned fd, then confirm the
/// descriptor is at EOF (no trailing bytes beyond the committed length). Returns the
/// exact bytes read. EINTR-safe; a short read or any trailing byte throws.
private func readExactOwned(_ fd: Int32, _ n: Int, _ what: String) throws -> Data {
    var buf = Data(count: n)
    if n > 0 {
        try buf.withUnsafeMutableBytes { (raw: UnsafeMutableRawBufferPointer) in
            guard let base = raw.baseAddress else { throw Fail("retention \(what): nil read buffer") }
            var off = 0
            while off < n {
                let r = read(fd, base.advanced(by: off), n - off)
                if r < 0 { if errno == EINTR { continue }; throw Fail("retention \(what) read failed: \(String(cString: strerror(errno)))") }
                if r == 0 { throw Fail("retention \(what) short read: got \(off) of \(n) bytes") }
                off += r
            }
        }
    }
    var tail = [UInt8](repeating: 0, count: 1)
    let more = read(fd, &tail, 1)
    guard more == 0 else {
        throw Fail(more < 0
            ? "retention \(what) trailing read failed: \(String(cString: strerror(errno)))"
            : "retention \(what) has trailing bytes beyond committed length \(n)")
    }
    return buf
}

private func sha256hexData(_ d: Data) -> String {
    SHA256.hash(data: d).map { String(format: "%02x", $0) }.joined()
}

/// Re-read an owned artifact's exact committed length + content digest THROUGH its
/// retained descriptor (APP-SCOPE-02-R1-POSTSYNC). A FINITE OBSERVATION of the bytes
/// synchronized moments earlier — it does NOT claim the object is immutable; it catches
/// a same-inode modification that the dev/inode mapping check cannot see.
private func rereadOwned(_ a: OwnedArtifact, _ phase: String) throws {
    guard lseek(a.fd, 0, SEEK_SET) == 0 else {
        throw Fail("cannot rewind retained \(a.what) for \(phase) re-read: \(String(cString: strerror(errno)))")
    }
    let got = try readExactOwned(a.fd, a.expectBytes, "retained \(a.what) \(phase)")
    let dg = sha256hexData(got)
    guard dg == a.expectDigest else {
        throw Fail("retained \(a.what) changed after synchronization (\(phase) digest \(dg) != committed \(a.expectDigest))")
    }
}

/// Write one evidence document by EXCLUSIVE CREATE relative to the owned OUT dirfd,
/// then verify its exact generated length + content and fsync it — all through the
/// SAME owned descriptor (no pathname reopen, no overwrite of an existing entry). The
/// descriptor is RETAINED OPEN inside the returned OwnedArtifact (the caller closes it);
/// it is closed here only if this helper throws. Returns the captured (name, dev, inode)
/// plus the expected length/digest so the directory stage can re-confirm the entry and
/// the post-sync stage can re-read it. Fails closed on any I/O error, a non-regular
/// object, a length/content mismatch, or a collision.
private func saveDurable(_ name: String, _ d: Data, dirFd: Int32) throws -> OwnedArtifact {
    try requireConfinedName(name, "document")
    // O_EXCL: we create a fresh inode at this name or refuse; O_NOFOLLOW: never a
    // symlink; O_RDWR: the SAME fd writes, reads back for verification, and (retained)
    // re-reads after the directory/parent fsync.
    let fd = name.withCString { openat(dirFd, $0, O_CREAT | O_EXCL | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0o600) }
    guard fd >= 0 else { throw Fail("cannot exclusively create retained document \(name): \(String(cString: strerror(errno)))") }
    var keep = false
    defer { if !keep { close(fd) } }   // closed on throw; retained to the caller on success
    try writeAllOwned(fd, d, "document \(name)")
    var st = stat()
    guard fstat(fd, &st) == 0 else { throw Fail("cannot fstat retained document \(name): \(String(cString: strerror(errno)))") }
    guard isReg(st) else { throw Fail("retained document \(name) is not a regular file") }
    guard Int(st.st_size) == d.count else { throw Fail("retained document \(name) is \(st.st_size) bytes, generated \(d.count)") }
    guard lseek(fd, 0, SEEK_SET) == 0 else { throw Fail("cannot rewind retained document \(name): \(String(cString: strerror(errno)))") }
    let got = try readExactOwned(fd, d.count, "document \(name)")
    guard got == d else { throw Fail("retained document \(name) read-back differs from generated bytes") }
    guard retentionFsync(fd, "doc:\(name)") == 0 else { throw Fail("fsync \(name) failed: \(String(cString: strerror(errno)))") }
    // Window a reopen-by-path would be vulnerable at (production: no-op). The owned
    // inode is already recorded and the fd stays open, so a post-creation swap is
    // caught by the dir stage and a same-inode change by the post-sync re-read.
    retentionReplace("doc:\(name)")
    keep = true
    return OwnedArtifact(name: name, fd: fd, dev: st.st_dev, ino: st.st_ino,
                         expectBytes: d.count, expectDigest: sha256hexData(d), what: "document \(name)")
}

/// Open a backend-produced retained file ONCE relative to the owned OUT dirfd,
/// no-follow, and bind fstat (regular file + exact committed length), a full bounded
/// read + digest + trailing-byte check, and fsync to that SAME descriptor, which is
/// RETAINED OPEN inside the returned OwnedArtifact (the caller closes it; closed here
/// only on throw). Never performs an independent stat/hash/reopen of the pathname — the
/// openat is relative to the owned OUT dirfd, so the object is definitionally confined to
/// the owned OUT. Returns the captured (name, dev, inode) + expected length/digest for
/// the directory-stage mapping re-confirmation and the post-sync re-read.
private func verifyRetainedFile(_ rf: RetainedFileV3, dirFd: Int32) throws -> OwnedArtifact {
    let name = URL(fileURLWithPath: rf.path).lastPathComponent
    try requireConfinedName(name, "retained \(rf.what)")
    let fd = name.withCString { openat(dirFd, $0, O_RDONLY | O_NOFOLLOW | O_CLOEXEC) }
    guard fd >= 0 else { throw Fail("retained \(rf.what) missing or unopenable relative to owned OUT: \(String(cString: strerror(errno)))") }
    var keep = false
    defer { if !keep { close(fd) } }   // closed on throw; retained to the caller on success
    var st = stat()
    guard fstat(fd, &st) == 0 else { throw Fail("cannot fstat retained \(rf.what): \(String(cString: strerror(errno)))") }
    guard isReg(st) else { throw Fail("retained \(rf.what) is not a regular file") }
    guard Int(st.st_size) == rf.expectBytes else {
        throw Fail("retained \(rf.what) is \(st.st_size) bytes, backend committed \(rf.expectBytes)")
    }
    // Simulated same-UID replacement at the former stat/hash/open window (production
    // no-op). The owned fd below is unaffected; the directory stage detects a swap and
    // the post-sync re-read a same-inode change.
    retentionReplace("file:\(rf.what)")
    let bytes = try readExactOwned(fd, rf.expectBytes, "retained \(rf.what)")
    let got = sha256hexData(bytes)
    guard got == rf.expectSha256 else { throw Fail("retained \(rf.what) sha256 \(got) != backend-committed \(rf.expectSha256)") }
    guard retentionFsync(fd, "file:\(rf.what)") == 0 else { throw Fail("fsync retained \(rf.what) failed: \(String(cString: strerror(errno)))") }
    keep = true
    return OwnedArtifact(name: name, fd: fd, dev: st.st_dev, ino: st.st_ino,
                         expectBytes: rf.expectBytes, expectDigest: rf.expectSha256, what: rf.what)
}

/// No-follow re-confirmation of the directory mappings, used BEFORE and AFTER the
/// directory/parent fsyncs (APP-SCOPE-02-R1-DIRECTORY). Confirms (a) the OUT entry in
/// its parent still maps (dev/inode) the owned OUT directory and (b) every retained OUT
/// entry still maps the exact object this sequence owns (compared against the STILL-OPEN
/// owned fd's captured dev/inode). All checks use AT_SYMLINK_NOFOLLOW — never a following
/// stat() of the OUT pathname. Any remap/substitution/disappearance or required I/O error
/// throws; nothing is unlinked.
private func confirmMappings(outName: String, dirFd: Int32, parentFd: Int32,
                             outDev: dev_t, outIno: ino_t, entries: [OwnedArtifact],
                             phase: String) throws {
    // (a) OUT entry in its established parent still maps the owned OUT (no-follow).
    var ost = stat()
    let orc = outName.withCString { fstatat(parentFd, $0, &ost, AT_SYMLINK_NOFOLLOW) }
    guard orc == 0 else { throw Fail("[\(phase)] OUT entry \(outName) missing from its parent: \(String(cString: strerror(errno)))") }
    guard ost.st_dev == outDev, ost.st_ino == outIno else {
        throw Fail("[\(phase)] OUT entry \(outName) no longer maps the owned OUT directory (dev/inode changed)")
    }
    // (b) every retained OUT entry still maps the exact owned object (no-follow).
    for e in entries {
        var est = stat()
        let rc = e.name.withCString { fstatat(dirFd, $0, &est, AT_SYMLINK_NOFOLLOW) }
        guard rc == 0 else { throw Fail("[\(phase)] retained entry \(e.name) disappeared from the owned OUT: \(String(cString: strerror(errno)))") }
        guard est.st_dev == e.dev, est.st_ino == e.ino else {
            throw Fail("[\(phase)] retained entry \(e.name) was substituted in the owned OUT (dev/inode changed)")
        }
    }
}

/// Around the OUT-directory fsync, re-confirm the no-follow mappings (OUT-in-parent and
/// every retained entry) BEFORE syncing, fsync the OUT directory AND then its established
/// parent (so the possibly newly created OUT entry is itself durable), re-confirm the
/// SAME mappings AFTER syncing (post-sync substitution detection), and finally
/// conservatively RE-READ each retained artifact's exact committed length + digest
/// through its retained descriptor (post-sync same-inode modification detection). Any
/// remap/substitution/disappearance, a sync failure, a post-sync content change or a
/// required I/O error throws (retention unconfirmed) — nothing is unlinked.
private func finalizeDirectory(outName: String, dirFd: Int32, parentFd: Int32,
                               outDev: dev_t, outIno: ino_t, entries: [OwnedArtifact]) throws {
    // Simulated OUT-pathname replacement window (production no-op); detected by the
    // pre-sync OUT-in-parent no-follow mapping check just below.
    retentionReplace("out")
    try confirmMappings(outName: outName, dirFd: dirFd, parentFd: parentFd,
                        outDev: outDev, outIno: outIno, entries: entries, phase: "pre-sync")
    guard retentionFsync(dirFd, "dir") == 0 else { throw Fail("fsync OUT dir failed: \(String(cString: strerror(errno)))") }
    // The (possibly newly created) OUT directory ENTRY is only durable once its parent
    // is synchronized too (APP-SCOPE-02-R1-DIRECTORY).
    guard retentionFsync(parentFd, "parent") == 0 else { throw Fail("fsync OUT parent dir failed: \(String(cString: strerror(errno)))") }
    // Post-dir-sync substitution window (production no-op); detected by the post-sync
    // no-follow mapping re-confirmation just below — the observation the round-1 rewrite
    // lacked (it checked mappings only before the fsync).
    retentionReplace("postdirsync")
    try confirmMappings(outName: outName, dirFd: dirFd, parentFd: parentFd,
                        outDev: outDev, outIno: outIno, entries: entries, phase: "post-sync")
    // Same-inode modification window (production no-op); caught by the post-sync re-read.
    retentionReplace("postsync")
    for e in entries { try rereadOwned(e, "post-sync") }
}

/// Execute the complete durable-retention sequence (documents, backend-file
/// verifications, directory + parent fsync, post-sync re-read) as ONE fail-closed unit
/// bound to owned, no-follow OUT and parent directory descriptors held throughout, plus
/// one retained descriptor per artifact. Returns normally ONLY when the whole retained
/// set is durably written and verified against its expected bytes through owned,
/// retained descriptors BOTH before and after the fsyncs AND the sequential no-follow
/// name->object mappings pass before and after synchronization; the caller gates
/// destructive scratch cleanup on this returning. Any fault throws here and the caller
/// never reaches cleanup, so OUT is preserved. There is no partial-set success: the
/// complete inventory of confined, unique names is validated up front. Every owned
/// descriptor is closed exactly once on both paths.
func performDurableRetention(outDir: URL, documents: [RetainedDocV3],
                             verifications: [RetainedFileV3]) throws {
    // ---- complete-inventory validation BEFORE any processing (no partial set) ----
    guard !documents.isEmpty else { throw Fail("retention requires at least one document") }
    var names = Set<String>()
    for doc in documents {
        try requireConfinedName(doc.name, "document")
        guard names.insert(doc.name).inserted else { throw Fail("duplicate retained name: \(doc.name)") }
    }
    for v in verifications {
        let n = URL(fileURLWithPath: v.path).lastPathComponent
        try requireConfinedName(n, "retained \(v.what)")
        guard names.insert(n).inserted else { throw Fail("duplicate retained name: \(n)") }
        guard v.expectBytes >= 0 else { throw Fail("retained \(v.what) committed length is negative") }
        guard v.expectSha256.count == 64 else { throw Fail("retained \(v.what) committed digest is not a sha256 hex string") }
    }

    // ---- own the OUT directory for the whole sequence: no-follow, confirmed dir ----
    let dirFd = outDir.path.withCString { open($0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) }
    guard dirFd >= 0 else { throw Fail("cannot open OUT dir to retain into: \(String(cString: strerror(errno)))") }
    defer { close(dirFd) }
    var dst = stat()
    guard fstat(dirFd, &dst) == 0 else { throw Fail("cannot fstat owned OUT dir: \(String(cString: strerror(errno)))") }
    guard isDir(dst) else { throw Fail("owned OUT is not a directory") }
    let outDev = dst.st_dev, outIno = dst.st_ino

    // ---- own OUT's ESTABLISHED parent: no-follow, confirmed dir; confirm the OUT entry
    // ---- maps the owned OUT up front (newly created OUT needs a retained-parent sync) --
    let outName = outDir.lastPathComponent
    try requireConfinedName(outName, "OUT directory")
    let parentPath = outDir.deletingLastPathComponent().path
    let parentFd = parentPath.withCString { open($0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) }
    guard parentFd >= 0 else { throw Fail("cannot open established OUT parent dir \(parentPath): \(String(cString: strerror(errno)))") }
    defer { close(parentFd) }
    var pst = stat()
    guard fstat(parentFd, &pst) == 0 else { throw Fail("cannot fstat owned OUT parent dir: \(String(cString: strerror(errno)))") }
    guard isDir(pst) else { throw Fail("owned OUT parent is not a directory") }
    var ost0 = stat()
    guard (outName.withCString { fstatat(parentFd, $0, &ost0, AT_SYMLINK_NOFOLLOW) }) == 0 else {
        throw Fail("OUT entry \(outName) not found in its established parent: \(String(cString: strerror(errno)))")
    }
    guard ost0.st_dev == outDev, ost0.st_ino == outIno else {
        throw Fail("OUT entry \(outName) in its parent does not map the owned OUT directory (no-follow)")
    }

    // ---- process artifacts, RETAINING each owned fd; close all exactly once here ----
    var artifacts: [OwnedArtifact] = []
    defer { for a in artifacts { close(a.fd) } }   // success AND failure
    for doc in documents {
        artifacts.append(try saveDurable(doc.name, doc.bytes, dirFd: dirFd))
    }
    for v in verifications {
        artifacts.append(try verifyRetainedFile(v, dirFd: dirFd))
    }
    try finalizeDirectory(outName: outName, dirFd: dirFd, parentFd: parentFd,
                          outDev: outDev, outIno: outIno, entries: artifacts)
}

#endif
