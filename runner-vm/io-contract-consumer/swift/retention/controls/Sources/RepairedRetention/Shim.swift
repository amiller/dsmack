// Shim.swift — the one symbol the repaired RetentionV3.swift references but which is
// provided by the mar app (main.swift `Fail`) in the real build. Defined here so the
// module links WITHOUT the HVF backend / App Attest / the native archive / a VM. The
// repaired RetentionV3.swift in this target is byte-identical to the app-src source of
// truth (run_controls.sh hash-verifies before building); only this shim and Exports.swift
// are added.
import Foundation

struct Fail: Error, CustomStringConvertible { let description: String; init(_ s: String) { description = s } }
