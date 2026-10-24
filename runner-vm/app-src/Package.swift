// swift-tools-version: 6.2
import PackageDescription

// DSMACK_V3_ARCHIVE_DIR is the directory holding libdsmack_hvf_returning.a (native/build.sh output).
guard let archiveDir = Context.environment["DSMACK_V3_ARCHIVE_DIR"] else {
    fatalError("set DSMACK_V3_ARCHIVE_DIR to the directory holding libdsmack_hvf_returning.a")
}

let package = Package(
    name: "mar",
    platforms: [.macOS("27.0")],
    dependencies: [.package(path: "../control-src")],
    targets: [
        .systemLibrary(name: "CJoin", path: "Sources/CJoin"),
        .executableTarget(name: "mar", dependencies: [
            .product(name: "marAttest", package: "control-src"),
            "CJoin",
        ], swiftSettings: [.swiftLanguageMode(.v5)], linkerSettings: [
            .linkedFramework("DeviceCheck"),
            .linkedFramework("Hypervisor"),
            .unsafeFlags(["-L", archiveDir, "-ldsmack_hvf_returning"]),
        ]),
    ]
)
