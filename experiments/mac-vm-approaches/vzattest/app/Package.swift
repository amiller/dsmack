// swift-tools-version: 6.2
import PackageDescription
let package = Package(
    name: "vzattest",
    platforms: [.macOS("27.0")],
    dependencies: [.package(url: "https://github.com/apple/containerization.git", exact: "0.33.4")],
    targets: [.executableTarget(name: "vzattest", dependencies: [
        .product(name: "Containerization", package: "containerization"),
    ], linkerSettings: [.linkedFramework("DeviceCheck")])]
)
