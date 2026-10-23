// Shim.swift — the one symbol the R2 RetentionV3.swift references but which is provided by
// the mar app (main.swift `Fail`) in the real build. Defined here so the module links
// WITHOUT the HVF backend / App Attest / the native archive / a VM. The RetentionV3.swift
// in this target is byte-identical to the R2 immutable baseline being repaired (sha256
// 7fe5ab0d3f456769d63a690add9ad36fd279e87be13a415e1fc8afe922fc92be); run_controls.sh
// hash-verifies it before building, so the control drives the EXACT rejected-R2
// implementation, not a hand-copied approximation. Only this shim and Exports.swift are
// added (both logic-free).
import Foundation

struct Fail: Error, CustomStringConvertible { let description: String; init(_ s: String) { description = s } }
