// RetentionV3.swift — the DURABLE-COMPLETE-RETENTION mechanism for the v3 launch
// path, factored out of V3Launch.swift (SWIFT04 repair3) so it is exercisable by
// an independent fault-injection harness WITHOUT the HVF backend, App Attest, the
// native archive or a VM.
//
// APP-SCOPE-02 repair (APP-RETENTION-BOUNDARY-DECISION.json,
// schema dsmack-finite-app-retention-contract/1). The accepted candidate bound its
// "durable complete retention" claim to bytes it never held a descriptor to:
// saveDurable atomically wrote a document then REOPENED its pathname to fsync
// WITHOUT re-checking content/inode, and verifyRetainedFile performed independent
// stat(path) -> sha256File(path) -> open(path) resolutions. A same-UID replacement
// between any two of those path resolutions let a DIFFERENT object be hashed, or
// synchronized, while the operation returned success — the retention guarantee was
// not tied to the validated bytes. This rewrite enforces the Root finite-descriptor
// contract: performDurableRetention owns a no-follow OUT directory descriptor
// throughout; validates the complete inventory of confined, unique names up front
// (no partial-set success); writes each document by EXCLUSIVE CREATE relative to the
// owned OUT and verifies its exact generated length + content and fsyncs through the
// SAME descriptor; opens each backend-produced file ONCE relative to the owned OUT,
// no-follow, and binds fstat (regular file + exact committed length), a full bounded
// read + digest + trailing-byte check, and fsync to that SAME descriptor — never
// re-resolving the pathname; and around the directory fsync re-confirms, no-follow,
// that every retained directory entry still maps (dev/inode) to the object this
// sequence owned and that the OUT pathname still maps the owned OUT. Any observed
// substitution, disappearance, mapping mismatch or required I/O error throws
// (retention unconfirmed/refuse); nothing is unlinked and all possible residue is
// preserved.
//
// EXACT GUARANTEE on success: every required artifact was verified against its
// expected bytes THROUGH its own owned descriptor, the required file and directory
// fsyncs succeeded, and the sequential name->object mapping observations passed.
// WHAT IS NOT GUARANTEED (stated, not silently strengthened): owned descriptors
// prevent a pathname replacement from redirecting THAT descriptor, not same-inode
// writes; the sequential mapping/content checks are not an atomic simultaneous
// snapshot under hostile mutation; and nothing here guarantees against a subsequent
// unlink/replacement/corruption or an indefinitely-available pathname after the
// sequence's last defined observation (0700/random names are NOT a same-UID writer
// exclusion). Downstream transfer/checkers must independently verify the actually
// delivered bytes. Success proves evidence retention only. SWIFT05: the caller
// preserves all possible host residue and reports deferred/unconfirmed cleanup on
// both paths; NO retention operation authorizes pathname deletion.
//
// Helpers bind to the OUT the caller passes (not the main.swift `out` global) so the
// harness can point them at a scratch temp dir. `Fail` is provided by the app
// (main.swift) for the mar build and by the test shim for the standalone harness;
// this file defines neither. Digests are computed over owned-descriptor bytes with
// CryptoKit (no pathname reopen), so the prior `sha256File(path)` reopen is gone.

#if canImport(Darwin)
import CryptoKit
import Darwin
import Foundation

/// Test-only fsync seam (SWIFT04 repair4). Production leaves this nil and every
/// sync below calls the real `Darwin.fsync` directly, so the shipped retention
/// sequence is byte-for-byte unchanged. The independent fault-injection harness
/// sets this to force a DETERMINISTIC sync failure at a chosen stage ("doc:<name>",
/// "file:<what>" or "dir") so the EXACT production `performDurableRetention` can be
/// driven to a real fsync fault and the destructive-cleanup gate asserted. The
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
/// fault-injection harness sets it to simulate a same-UID replacement of a retained
/// PATHNAME at the EXACT window a reopen-by-path would have observed it — a document
/// pathname just after its exclusive create ("doc:<name>"), a backend file's former
/// stat/hash/open window ("file:<what>"), or the OUT pathname itself ("out"). Because
/// every validated byte is bound to an owned descriptor, the repaired sequence does
/// NOT read the substituted object; it detects the dev/inode mapping change around
/// the directory fsync (or the OUT-pathname remap) and refuses. The closure runs for
/// its side effect only and returns nothing.
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

/// The (name, dev, inode) a retention step bound to its OWNED descriptor, captured
/// from the fstat of the exact fd that was written/verified/fsynced — BEFORE any
/// replacement window. The directory-fsync stage re-confirms, no-follow, that the
/// retained directory entry still maps to this object (substitution/disappearance
/// detection); recording from the owned fd (not a later path re-stat) is what makes
/// a post-creation swap detectable rather than self-cancelling.
private struct OwnedEntry { let name: String; let dev: dev_t; let ino: ino_t }

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

/// Write one evidence document by EXCLUSIVE CREATE relative to the owned OUT dirfd,
/// then verify its exact generated length + content and fsync it — all through the
/// SAME owned descriptor (no pathname reopen, no overwrite of an existing entry).
/// Returns the (name, dev, inode) captured from the owned fd so the directory stage
/// can re-confirm the entry. Fails closed on any I/O error, a non-regular object, a
/// length/content mismatch, or a collision.
private func saveDurable(_ name: String, _ d: Data, dirFd: Int32) throws -> OwnedEntry {
    try requireConfinedName(name, "document")
    // O_EXCL: we create a fresh inode at this name or refuse; O_NOFOLLOW: never a
    // symlink; O_RDWR: the SAME fd both wrote and reads back for verification.
    let fd = name.withCString { openat(dirFd, $0, O_CREAT | O_EXCL | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0o600) }
    guard fd >= 0 else { throw Fail("cannot exclusively create retained document \(name): \(String(cString: strerror(errno)))") }
    defer { close(fd) }
    try writeAllOwned(fd, d, "document \(name)")
    var st = stat()
    guard fstat(fd, &st) == 0 else { throw Fail("cannot fstat retained document \(name): \(String(cString: strerror(errno)))") }
    guard isReg(st) else { throw Fail("retained document \(name) is not a regular file") }
    guard Int(st.st_size) == d.count else { throw Fail("retained document \(name) is \(st.st_size) bytes, generated \(d.count)") }
    guard lseek(fd, 0, SEEK_SET) == 0 else { throw Fail("cannot rewind retained document \(name): \(String(cString: strerror(errno)))") }
    let got = try readExactOwned(fd, d.count, "document \(name)")
    guard got == d else { throw Fail("retained document \(name) read-back differs from generated bytes") }
    guard retentionFsync(fd, "doc:\(name)") == 0 else { throw Fail("fsync \(name) failed: \(String(cString: strerror(errno)))") }
    let owned = OwnedEntry(name: name, dev: st.st_dev, ino: st.st_ino)
    // Window a reopen-by-path would be vulnerable at (production: no-op). The owned
    // inode is already recorded, so a post-creation swap is caught by the dir stage.
    retentionReplace("doc:\(name)")
    return owned
}

/// Open a backend-produced retained file ONCE relative to the owned OUT dirfd,
/// no-follow, and bind fstat (regular file + exact committed length), a full bounded
/// read + digest + trailing-byte check, and fsync to that SAME descriptor. Never
/// performs an independent stat/hash/reopen of the pathname. Returns the (name, dev,
/// inode) captured from the owned fd for the directory-stage mapping re-confirmation.
private func verifyRetainedFile(_ rf: RetainedFileV3, dirFd: Int32, outDev: dev_t, outIno: ino_t) throws -> OwnedEntry {
    let url = URL(fileURLWithPath: rf.path)
    let name = url.lastPathComponent
    try requireConfinedName(name, "retained \(rf.what)")
    // The pathname's parent must map to the owned OUT (not merely share a name).
    var pst = stat()
    guard stat(url.deletingLastPathComponent().path, &pst) == 0 else {
        throw Fail("retained \(rf.what) parent missing: \(url.deletingLastPathComponent().path)")
    }
    guard pst.st_dev == outDev, pst.st_ino == outIno else {
        throw Fail("retained \(rf.what) is not under the owned OUT directory")
    }
    let fd = name.withCString { openat(dirFd, $0, O_RDONLY | O_NOFOLLOW | O_CLOEXEC) }
    guard fd >= 0 else { throw Fail("retained \(rf.what) missing or unopenable: \(String(cString: strerror(errno)))") }
    defer { close(fd) }
    var st = stat()
    guard fstat(fd, &st) == 0 else { throw Fail("cannot fstat retained \(rf.what): \(String(cString: strerror(errno)))") }
    guard isReg(st) else { throw Fail("retained \(rf.what) is not a regular file") }
    guard Int(st.st_size) == rf.expectBytes else {
        throw Fail("retained \(rf.what) is \(st.st_size) bytes, backend committed \(rf.expectBytes)")
    }
    let owned = OwnedEntry(name: name, dev: st.st_dev, ino: st.st_ino)
    // Simulated same-UID replacement at the former stat/hash/open window (production
    // no-op). The owned fd below is unaffected; the directory stage detects the swap.
    retentionReplace("file:\(rf.what)")
    let bytes = try readExactOwned(fd, rf.expectBytes, "retained \(rf.what)")
    let got = sha256hexData(bytes)
    guard got == rf.expectSha256 else { throw Fail("retained \(rf.what) sha256 \(got) != backend-committed \(rf.expectSha256)") }
    guard retentionFsync(fd, "file:\(rf.what)") == 0 else { throw Fail("fsync retained \(rf.what) failed: \(String(cString: strerror(errno)))") }
    return owned
}

/// Around the OUT-directory fsync, re-confirm no-follow that (a) the OUT pathname
/// still maps the owned OUT descriptor and (b) every retained directory entry still
/// maps (dev/inode) to the exact object this sequence owned, then fsync the directory
/// so its entries are durable. Any remap/substitution/disappearance or the sync
/// failing throws (retention unconfirmed) — nothing is unlinked.
private func finalizeDirectory(_ outDir: URL, dirFd: Int32, outDev: dev_t, outIno: ino_t, entries: [OwnedEntry]) throws {
    // Simulated OUT-pathname replacement (production no-op); detected just below.
    retentionReplace("out")
    var ost = stat()
    guard stat(outDir.path, &ost) == 0 else { throw Fail("OUT pathname missing: \(outDir.path)") }
    guard ost.st_dev == outDev, ost.st_ino == outIno else { throw Fail("OUT pathname no longer maps the owned OUT directory") }
    for e in entries {
        var est = stat()
        let rc = e.name.withCString { fstatat(dirFd, $0, &est, AT_SYMLINK_NOFOLLOW) }
        guard rc == 0 else { throw Fail("retained entry \(e.name) disappeared from the owned OUT: \(String(cString: strerror(errno)))") }
        guard est.st_dev == e.dev, est.st_ino == e.ino else {
            throw Fail("retained entry \(e.name) was substituted in the owned OUT (dev/inode changed)")
        }
    }
    guard retentionFsync(dirFd, "dir") == 0 else { throw Fail("fsync OUT dir failed: \(String(cString: strerror(errno)))") }
}

/// Execute the complete durable-retention sequence (documents, backend-file
/// verifications, directory fsync) as ONE fail-closed unit bound to an owned,
/// no-follow OUT directory descriptor held throughout. Returns normally ONLY when the
/// whole retained set is durably written and verified against its expected bytes
/// through owned descriptors AND the sequential name->object mappings pass; the caller
/// gates destructive scratch cleanup on this returning. Any fault throws here and the
/// caller never reaches cleanup, so OUT is preserved intact. There is no partial-set
/// success: the complete inventory of confined, unique names is validated up front.
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

    var entries: [OwnedEntry] = []
    for doc in documents {
        entries.append(try saveDurable(doc.name, doc.bytes, dirFd: dirFd))
    }
    for v in verifications {
        entries.append(try verifyRetainedFile(v, dirFd: dirFd, outDev: outDev, outIno: outIno))
    }
    try finalizeDirectory(outDir, dirFd: dirFd, outDev: outDev, outIno: outIno, entries: entries)
}

#endif
