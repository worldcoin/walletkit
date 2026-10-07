// swift-tools-version: 6.0
import PackageDescription

// Host integration tests use the shared library built by Cargo. Distribution uses swift/Package.swift.template.
let package = Package(
    name: "WalletKitNativeTests",
    platforms: [.macOS(.v13)],
    products: [.library(name: "WalletKit", targets: ["WalletKit"])],
    targets: [
        .systemLibrary(name: "walletkit_coreFFI", path: "native/include"),
        .target(name: "WalletKit", dependencies: ["walletkit_coreFFI"], path: "swift/native", linkerSettings: [.linkedLibrary("walletkit")]),
        .testTarget(name: "WalletKitTests", dependencies: ["WalletKit"], path: "swift/tests/WalletKitTests"),
    ]
)
