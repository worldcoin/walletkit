// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

// Release version: refs/heads/main

import PackageDescription

let package = Package(
    name: "WalletKit",
    platforms: [
        .iOS(.v13),
    ],
    products: [
        .library(
            name: "WalletKitCore",
            targets: ["WalletKitCore", "walletkit_coreFFI"]),
    ],
    dependencies: [],
    targets: [
        .target(
            name: "WalletKitCore",
            dependencies: ["walletkit_coreFFI"]
        ),
        .binaryTarget(name: "walletkit_coreFFI", path: "WalletKitCore.xcframework")
    ]
)