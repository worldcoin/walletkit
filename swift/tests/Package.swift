// swift-tools-version: 5.7

import PackageDescription

let package = Package(
    name: "WalletKitForeignTestPackage",
    platforms: [
        .iOS(.v13),
        .macOS(.v12)
    ],
    products: [
        .library(
            name: "WalletKit",
            targets: ["WalletKit"])
    ],
    dependencies: [
        .package(url: "https://github.com/attaswift/BigInt.git", from: "5.4.0"),
    ],
    targets: [
        .target(
            name: "WalletKit",
            dependencies: [
                "WalletKitFFI",
                .product(name: "BigInt", package: "BigInt"),
            ],
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
