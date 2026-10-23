// GoldenShim.swift — the two helpers the pure contract sources (CanonicalJSON.swift,
// AssertionEvidence.swift, RunResultEnvelopeV3.swift) reference but which live in
// main.swift (Darwin CLI). Defined here so the golden harness links WITHOUT pulling
// Darwin/DeviceCheck/Hypervisor/CJoin. These are byte-identical to main.swift:42-44.
import CryptoKit
import Foundation

struct Fail: Error, CustomStringConvertible { let description: String; init(_ s: String) { description = s } }

func hex(_ digest: SHA256.Digest) -> String { digest.map { String(format: "%02x", $0) }.joined() }
func sha256hex(_ d: Data) -> String { hex(SHA256.hash(data: d)) }
