// swift-tools-version: 6.2
// marControl: the app-side control-profile emit path (candidate
// dsmack-owned-boot-verity-control/1). Pure Foundation + a local SHA-256: no
// DeviceCheck, no Hypervisor, no Containerization, so the exact bytes the joined
// app will emit are compilable and unit-testable independently of the backend,
// and the mar executable binds them when the backend control ABI lands.
import PackageDescription
let package = Package(
    name: "control-src",
    platforms: [.macOS("13.0")],
    products: [
        .library(name: "marControl", targets: ["marControl"]),
        .library(name: "marAttest", targets: ["marAttest"]),
    ],
    targets: [
        .target(name: "marControl", swiftSettings: [.swiftLanguageMode(.v5)]),
        .target(name: "marAttest", dependencies: ["marControl"], swiftSettings: [.swiftLanguageMode(.v5)]),
        .testTarget(name: "marControlTests", dependencies: ["marControl"], swiftSettings: [.swiftLanguageMode(.v5)]),
        .testTarget(name: "marAttestTests", dependencies: ["marAttest", "marControl"], swiftSettings: [.swiftLanguageMode(.v5)]),
    ]
)
