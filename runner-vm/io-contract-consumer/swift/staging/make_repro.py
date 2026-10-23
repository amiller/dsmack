from pathlib import Path
import sys
root=Path(sys.argv[1]); dest=Path(sys.argv[2])
s=(root/'app-src/Sources/mar/V2Launch.swift').read_text()
a=s.index('func stageVerifiedCopy('); b=s.index('\n/// Chunked sha256',a)
helper=s[a:b]
# Instrument actual helper boundaries, without changing its cleanup decisions.
helper=helper.replace('open(', 'trackedOpen(').replace('close(', 'trackedClose(').replace('fsync(', 'trackedSync(')
helper=helper.replace('if let want = wantBytes, total != want {','if caseName == "length" { try replaceWithForeign() }\n    if let want = wantBytes, total != want {')
helper=helper.replace('guard digest == wantSha256 else {','if caseName == "digest" { try replaceWithForeign() }\n    guard digest == wantSha256 else {')
pre='''import Foundation
import CryptoKit
import Darwin
struct Fail: Error, CustomStringConvertible { let description: String; init(_ s: String) { description=s } }
var registered: [String] = []
func own(_ u: URL) -> URL { registered.append(u.path); return u }
var opened: [Int32] = []
func trackedOpen(_ p: String, _ flags: Int32, _ mode: mode_t = 0) -> Int32 {
    let fd = Darwin.open(p, flags, mode); if fd >= 0 { opened.append(fd) }; return fd
}
func trackedClose(_ fd: Int32) { Darwin.close(fd) }
func trackedSync(_ fd: Int32) -> Int32 {
    if caseName == "sync" { try! replaceWithForeign(); errno = EIO; return -1 }
    return Darwin.fsync(fd)
}
let caseName = CommandLine.arguments[1]
let dir = URL(fileURLWithPath: CommandLine.arguments[2])
try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
let target = dir.appendingPathComponent("staged")
let source = dir.appendingPathComponent("source")
let foreign = Data("foreign replacement must survive".utf8)
func replaceWithForeign() throws {
    if FileManager.default.fileExists(atPath: target.path) { try FileManager.default.removeItem(at: target) }
    try foreign.write(to: target)
}
var checks = 0
func checkCancellation() throws {
    checks += 1
    if caseName == "partial" && checks == 2 { try replaceWithForeign(); throw Fail("injected partial-copy failure") }
}
func sha256File(_ p: String) throws -> String {
    if caseName == "readback" || caseName == "readthrow" {
        try replaceWithForeign()
        if caseName == "readthrow" { throw Fail("injected read-back failure") }
        return String(repeating: "0", count: 64)
    }
    return SHA256.hash(data: try Data(contentsOf: URL(fileURLWithPath: p))).map { String(format:"%02x", $0) }.joined()
}
'''
pre+=(root/'app-src/Sources/mar/DeferredCleanup.swift').read_text()+'\n'
post='''
let input = Data(repeating: 65, count: (1 << 20) + 7)
try input.write(to: source)
let digest = SHA256.hash(data: input).map { String(format:"%02x", $0) }.joined()
var failure = ""
do {
    _ = try stageVerifiedCopy(dir, "staged", src: source.path, maxBytes: input.count + 1,
        wantSha256: caseName == "digest" ? String(repeating:"0",count:64) : digest,
        wantBytes: caseName == "length" ? input.count + 1 : input.count)
} catch { failure = String(describing:error) }
let survives = (try? Data(contentsOf: target)) == foreign
let allClosed = opened.allSatisfy { fcntl($0, F_GETFD) == -1 }
let expectedFailure: Bool
switch caseName {
case "partial": expectedFailure = failure.contains("injected partial-copy failure")
case "length": expectedFailure = failure.contains("manifest says")
case "digest": expectedFailure = failure.contains("!= expected")
case "readback": expectedFailure = failure.contains("changed after write")
case "sync": expectedFailure = failure.contains("cannot sync staged copy")
default: expectedFailure = failure.contains("injected read-back failure")
}
// An eventual cleanup/report attempt must also preserve a second replacement.
try replaceWithForeign()
let registryBefore = registered
dropScratch()
let survivesLater = (try? Data(contentsOf: target)) == foreign && registered == registryBefore
var residueFreeRefused = false
do { try deferredResidue(paths: registered).requireResidueFree() } catch { residueFreeRefused = true }
print("later_replacement_survives=\(survivesLater) residue_free_refused=\(residueFreeRefused)")
print("case=\\(caseName) foreign_survives=\\(survives) registered=\\(registered.contains(target.path)) fds_closed=\\(allClosed) original_failure=\\(expectedFailure) error=\\(failure)")
exit(survives && registered.contains(target.path) && allClosed && expectedFailure && survivesLater && residueFreeRefused ? 0 : 1)
'''
main=(root/'app-src/Sources/mar/main.swift').read_text()
a=main.index('func dropScratch() {'); b=main.index('\n}\n',a)+3
drop=main[a:b].replace('scratchPaths.withLock { $0 }', 'registered')
dest.write_text(pre+helper+drop+post)
