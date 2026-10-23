// ReproShim.swift — the one symbol the R2 RetentionV3.swift references but which is
// provided by the mar app (main.swift `Fail`) in the real build. Lets the pristine R2
// baseline compile as a standalone swiftc module WITHOUT the HVF backend / App Attest /
// the native archive / a VM, so the APP-SCOPE-02-R2 counterexamples can be reproduced
// against the EXACT immutable baseline (sha256 7fe5ab0d..., hash-verified by repro.sh).
import Foundation

struct Fail: Error, CustomStringConvertible { let description: String; init(_ s: String) { description = s } }
