// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "ESLogger",
    products: [
        .library(
            name: "ESLogger",
            targets: ["ESLogger"]),
    ],
    dependencies: [
        .package(url: "https://github.com/jamf/Subprocess.git", from: "2.1.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.4.4"),
    ],
    targets: [
        .target(
            name: "ESLogger",
            dependencies: ["Subprocess",
                           .product(name: "Logging", package: "swift-log"),
            ]),
        .testTarget(
            name: "ESLoggerTests",
            dependencies: ["ESLogger"]),
    ]
)
