// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "WalletKitTestPackage",
    platforms: [
        .iOS(.v13)
    ],
    products: [
        .library(
            name: "WalletKit",
            targets: ["WalletKit"])
    ],
    targets: [
        .target(
            name: "WalletKit",
            dependencies: ["WalletKitFFI"],
            path: "Sources/WalletKit"
        ),
        .binaryTarget(
            name: "WalletKitFFI",
            path: "../WalletKit.xcframework"
        ),
        .testTarget(
            name: "WalletKitTests",
            dependencies: ["WalletKit"],
            path: "WalletKitTests"
        )
    ]
)
