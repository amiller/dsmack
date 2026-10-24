// swift-tools-version: 6.2
// marAttest: CBOR decoding of App Attest output and offline App Attest verification.
import PackageDescription
let package = Package(
    name: "control-src",
    platforms: [.macOS("13.0")],
    products: [.library(name: "marAttest", targets: ["marAttest"])],
    targets: [
        .target(name: "marAttest", swiftSettings: [.swiftLanguageMode(.v5)]),
        .testTarget(name: "marAttestTests", dependencies: ["marAttest"], swiftSettings: [.swiftLanguageMode(.v5)]),
    ]
)
