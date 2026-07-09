# Swift for WalletKit

This folder contains Swift support files for WalletKit:

1. Script to cross-compile and build Swift bindings.
2. Script to build a Swift package for local development.
3. Foreign tests (XCTest suite) for Swift under `tests/`.

## Building the Swift bindings

Building always uses the **host Xcode** (Apple's iOS SDKs can't be provided
through Nix), so either way you need macOS with full Xcode installed.

The recommended path is the Nix devshell, which provides everything else —
the pinned Rust toolchain and iOS targets, `cmake`, `swiftlint` — and takes
care of selecting a usable Xcode (it also validates the `WALLETKIT_DEVELOPER_DIR`
pin, which is how CI ensures a specific Xcode version):

```bash
    # run from the walletkit directory
    nix develop .#swift
    ./swift/build_swift.sh
```

Without Nix, install the dependencies yourself — `rustup` (picks up
`rust-toolchain.toml` automatically) and `cmake` — and make sure
`xcode-select -p` points at full Xcode, not CommandLineTools
(see [`nix/README.md`](../nix/README.md) for details):

```bash
    # run from the walletkit directory
    ./swift/build_swift.sh
```

## Testing WalletKit locally

To build a Swift package that can be imported locally via Swift Package Manager:

```bash
    # run from the walletkit directory
    ./swift/local_swift.sh
```

This creates a complete Swift package in `swift/local_build/` that you can import in your iOS project.

## Integration via Package.swift

Add the local package to your Package.swift dependencies:

```swift
dependencies: [
    .package(name: "WalletKit", path: "../../../walletkit/swift/local_build"),
    // ... other dependencies
],
```

Then add it to specific targets that need WalletKit functionality:

```swift
.target(
    name: "YourTarget",
    dependencies: [
        .product(name: "WalletKit", package: "WalletKit"),
        // ... other dependencies
    ]
),
```

## Running foreign tests for Swift

```bash
    # run from the walletkit directory
    ./swift/test_swift.sh
```
