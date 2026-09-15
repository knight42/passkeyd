// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "passkeyd",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(name: "passkeyd", path: "Sources/passkeyd"),
        .testTarget(name: "passkeydTests", dependencies: ["passkeyd"], path: "Tests/passkeydTests"),
    ]
)
