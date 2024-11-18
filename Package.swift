// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

// The package must be installed from github.com/worldcoin/walletkit-swift

import PackageDescription

// Current version is: 0.0.4

let package = Package(
    name: "WalletKit",
    platforms: [
        .iOS(.v13),
    ],
    products: [
        .library(
            name: "WalletKitCore",
            targets: ["WalletKitCore"]),
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
