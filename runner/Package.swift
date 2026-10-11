// swift-tools-version: 6.2
import PackageDescription
let package = Package(
    name: "runner",
    platforms: [.macOS("27.0")],
    dependencies: [
        .package(url: "https://github.com/apple/containerization.git", exact: "0.33.4"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.104.0"),
        .package(url: "https://github.com/apple/swift-nio-extras.git", from: "1.35.1"),
        .package(url: "https://github.com/apple/swift-system.git", from: "1.8.1"),
    ],
    targets: [.executableTarget(name: "runner", dependencies: [
        .product(name: "Containerization", package: "containerization"),
        .product(name: "ContainerizationEXT4", package: "containerization"),
        .product(name: "NIOCore", package: "swift-nio"),
        .product(name: "NIOPosix", package: "swift-nio"),
        .product(name: "NIOHTTP1", package: "swift-nio"),
        .product(name: "NIOExtras", package: "swift-nio-extras"),
        .product(name: "SystemPackage", package: "swift-system"),
    ], swiftSettings: [.swiftLanguageMode(.v5)], linkerSettings: [.linkedFramework("DeviceCheck")])]
)
