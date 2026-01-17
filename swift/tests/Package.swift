// swift-tools-version: 5.7

import PackageDescription

let package = Package(
    name: "WalletKitForeignTestPackage",
    platforms: [
        .iOS(.v13),
        .macOS(.v12),
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
            path: "../../WalletKit.xcframework"
        ),
        .testTarget(
            name: "WalletKitTests",
            dependencies: ["WalletKit"],
            path: "WalletKitTests"
        ),
    ]
)
