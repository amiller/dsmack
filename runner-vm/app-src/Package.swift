// swift-tools-version: 6.2
import PackageDescription
import Foundation

// SWIFT03 repair2 — CONCRETE native linkage (no placeholder sed).
//
// The rejected repair1 manifest carried the literal token
// `LINK_ARCHIVE_DIR_PLACEHOLDER` and relied on packaging/build.sh sed-rewriting
// it, so the manifest as reviewed linked against a non-existent path. This
// manifest instead resolves the reviewed v3 apple-static archive DIRECTORY from
// the environment variable DSMACK_V3_ARCHIVE_DIR at manifest-evaluation time:
//
//   * DSMACK_V3_ARCHIVE_DIR = directory containing libdsmack_hvf_returning.a
//     (the native-nat `dsmack-hvf-returning` staticlib crate output —
//     crate-type ["staticlib"] ⇒ lib<name>.a, so -ldsmack_hvf_returning is the
//     correct link name; confirmed against native-nat
//     apple-static/Cargo.toml `name = "dsmack-hvf-returning"`).
//
// If the variable is unset the manifest still evaluates (so `swift package
// dump-package`, resolution and tooling work), but it points -L at a sentinel
// path that cannot exist — the LINK then fails LOUDLY with the required archive
// dir, never silently links a stale/placeholder library. packaging/build.sh
// exports DSMACK_V3_ARCHIVE_DIR from the reviewed ARCHIVE_DIR and verifies the
// archive exports the complete v3 symbol set BEFORE invoking `swift build`.
//
// The Swift executable TARGET name stays "mar" (compile command unchanged:
// `swift build -c release --product mar`); only the COPIED product binary is
// renamed to dsmack-runner by the packager.
let v3ArchiveDir = Context.environment["DSMACK_V3_ARCHIVE_DIR"]
    ?? "/nonexistent/DSMACK_V3_ARCHIVE_DIR-unset-set-it-to-the-reviewed-v3-archive-dir"

let package = Package(
    name: "mar",
    platforms: [.macOS("27.0")],
    dependencies: [.package(url: "https://github.com/apple/containerization.git", exact: "0.33.4"),
                    .package(url: "https://github.com/apple/swift-system.git", exact: "1.8.1"),
                    // local: the control-profile emit path (pure Foundation; unit-tested
                    // standalone in control-src). Bound into the hvf-control mode by
                    // assembly step AS-3 once the backend control ABI is published.
                    .package(path: "../control-src")],
    targets: [
        // CJoin: the v3 C ABI header (dsmack_ctl_join_v3.h, byte-identical to the
        // native-nat implementer's include/dsmack_ctl_join_v3.h) plus the frozen
        // v1/v2 headers. The archive libdsmack_hvf_returning.a is linked below via
        // -L$DSMACK_V3_ARCHIVE_DIR -ldsmack_hvf_returning; cSettings headerSearchPath
        // finds Sources/CJoin for the modulemap+headers.
        .systemLibrary(name: "CJoin", path: "Sources/CJoin"),
        .executableTarget(name: "mar", dependencies: [
            .product(name: "Containerization", package: "containerization"),
            .product(name: "SystemPackage", package: "swift-system"),
            .product(name: "marControl", package: "control-src"),
            .product(name: "marAttest", package: "control-src"),
            "CJoin",
        ], swiftSettings: [.swiftLanguageMode(.v5)], linkerSettings: [
            .linkedFramework("DeviceCheck"),
            .linkedFramework("Hypervisor"),
            // Concrete: the reviewed v3 archive directory (env-resolved), then the
            // correct library name for the dsmack-hvf-returning staticlib crate.
            .unsafeFlags(["-L", v3ArchiveDir]),
            .unsafeFlags(["-ldsmack_hvf_returning"]),
        ]),
    ]
)
