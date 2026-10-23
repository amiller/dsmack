import Foundation

/// No namespace exclusion is enforced against same-UID replacements. Never inspect,
/// rename or unlink these names. Paths describe possible residue, not inode ownership.
struct DeferredResidue {
    let paths: [String]
    let status = "deferred-unconfirmed"
    func requireResidueFree() throws {
        // Even an empty registry cannot prove the host namespace residue-free.
        throw NSError(domain: "DsmackDeferredResidue", code: 1,
                      userInfo: [NSLocalizedDescriptionKey: "residue-free completion is unconfirmed and refused"])
    }
}

func deferredResidue(paths: [String]) -> DeferredResidue {
    DeferredResidue(paths: paths)
}

/// Unconditional report: does not claim that a name still refers to our inode.
@discardableResult
func reportDeferredResidue(paths: [String]) -> DeferredResidue {
    let residue = deferredResidue(paths: paths)
    let report: [String: Any] = ["schema": "dsmack-host-residue/1",
        "status": residue.status, "possible_paths": residue.paths,
        "residue_free_confirmed": false]
    // This fixed shape contains only JSON-supported types.
    let bytes = try! JSONSerialization.data(withJSONObject: report, options: [.sortedKeys])
    FileHandle.standardError.write(bytes + Data("\n".utf8))
    return residue
}
