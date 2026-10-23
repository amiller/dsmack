// ScratchDispatch.swift — the ACTUAL cleanup-dispatch boundary, extracted VERBATIM from
// app-src/Sources/mar/main.swift (the `scratchPaths` declaration + `own` + `dropScratch`;
// slice sha256 1d92450449485f69e7831a355dd0028b4c6943c1def59e6d3f03d94709cf13a1). The three
// statements are byte-identical to main.swift; only `public` visibility is added so the
// controls executable can drive the REAL dispatch across the module boundary. This is the
// production own()->dropScratch()->reportDeferredResidue path (APP-SCOPE-01) — NOT a
// re-modeled deletion. reportDeferredResidue is provided verbatim by DeferredCleanup.swift
// in this same module.
import Foundation
import Synchronization

public let scratchPaths = Mutex<[String]>([])
public func own(_ u: URL) -> URL { scratchPaths.withLock { $0.append(u.path) }; return u }
public func dropScratch() {
    reportDeferredResidue(paths: scratchPaths.withLock { $0 })
}

// PUBLIC observation surface (no logic added): forwards to the verbatim DeferredCleanup
// semantics so the control can assert status / residue-free refusal.
public func ctrlReportDeferredResidue(_ paths: [String]) -> (status: String, paths: [String], refusesResidueFree: Bool) {
    let r = reportDeferredResidue(paths: paths)
    var refused = false
    do { try r.requireResidueFree() } catch { refused = true }
    return (r.status, r.paths, refused)
}
