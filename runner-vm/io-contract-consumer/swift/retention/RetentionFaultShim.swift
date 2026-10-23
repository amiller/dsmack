// RetentionFaultShim.swift — the two symbols RetentionV3.swift references but which
// are provided by the mar app (main.swift `Fail`, V2Launch.swift `sha256File`) in
// the real build. Defined here so the standalone retention fault-injection harness
// links WITHOUT the HVF backend / App Attest / the native archive / a VM.
import CryptoKit
import Foundation

struct Fail: Error, CustomStringConvertible { let description: String; init(_ s: String) { description = s } }

/// Whole-file sha256 (lowercase hex). The app's V2Launch.sha256File streams; for
/// the small test fixtures a single read is equivalent and sufficient.
func sha256File(_ path: String) throws -> String {
    guard let d = FileManager.default.contents(atPath: path) else { throw Fail("cannot read \(path)") }
    return SHA256.hash(data: d).map { String(format: "%02x", $0) }.joined()
}
