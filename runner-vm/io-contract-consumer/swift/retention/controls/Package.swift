// swift-tools-version:6.0
// RetentionControls — APP-RETENTION-CONTROLS package.
//
// Three library targets compile the durable-retention mechanism in THREE forms so the
// SAME controls run against each:
//   * AcceptedRetention   — the EXACT original rejected baseline RetentionV3.swift
//     (sha256 b100ea540804490e64984bdc5f16b2392cd182c1a30415a7d361f58cdd1fe248,
//     byte-identical). Drives the prior 39 RED/GREEN assertions unchanged.
//   * RejectedR2Retention — the EXACT R2 immutable baseline being repaired in R3
//     (sha256 7fe5ab0d3f456769d63a690add9ad36fd279e87be13a415e1fc8afe922fc92be,
//     byte-identical). It passes R2's descriptor-relative mapping checks but has NO full
//     OUT-pathname observation, so it is the same-baseline RED for the new
//     APP-SCOPE-02-R2-OUT-PATH-MAPPING counterexamples.
//   * RepairedRetention   — the round-3 repaired app-src RetentionV3.swift (single source
//     of truth; run_controls.sh re-copies + hash-verifies all three before build).
// AppCleanup links the verbatim DeferredCleanup.swift and the exact scratch/own/dropScratch
// dispatch slice extracted from main.swift, so the controls drive the ACTUAL cleanup
// dispatch boundary (not a re-modeled deletion). The executable drives all four.
//
// Swift LANGUAGE MODE v5 matches the app manifest (app-src/Package.swift uses
// swiftSettings [.swiftLanguageMode(.v5)]), so the retention files compile here EXACTLY
// as they do in the shipped build (the module-global test seams are Swift-5-legal).
import PackageDescription

let v5: [SwiftSetting] = [.swiftLanguageMode(.v5)]

let package = Package(
    name: "RetentionControls",
    platforms: [.macOS(.v15)],
    targets: [
        .target(name: "AcceptedRetention", swiftSettings: v5),
        .target(name: "RejectedR2Retention", swiftSettings: v5),
        .target(name: "RepairedRetention", swiftSettings: v5),
        .target(name: "AppCleanup", swiftSettings: v5),
        .executableTarget(
            name: "controls",
            dependencies: ["AcceptedRetention", "RejectedR2Retention", "RepairedRetention", "AppCleanup"],
            swiftSettings: v5
        ),
    ]
)
