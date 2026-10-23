// Shim.swift — the one symbol the accepted RetentionV3.swift references but which is
// provided by the mar app (main.swift `Fail`) in the real build. Defined here so the
// module links WITHOUT the HVF backend / App Attest / the native archive / a VM. The
// accepted RetentionV3.swift in this target is byte-identical to the reviewed baseline
// (sha256 b100ea54...); only this shim and Exports.swift are added, so the control
// drives the EXACT accepted implementation, not a hand-copied approximation.
import Foundation

struct Fail: Error, CustomStringConvertible { let description: String; init(_ s: String) { description = s } }
