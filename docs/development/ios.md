# iOS and Swift

WalletKit's Swift bindings are generated with UniFFI and built by the workspace
`xtask`. This page describes how to build and test them locally.

## Before you begin

Building for iOS requires macOS with the following:

- Xcode
- The iOS Rust targets. `rustup` installs them from `rust-toolchain.toml`.
- `nargo` v1.0.0-beta.11, installed with
  [`noirup`](https://noir-lang.org/docs/getting_started/noir_installation)

The Swift build doesn't use a Nix shell; it runs with the host's Xcode setup.

## Build a local package

To build a Swift package that an app can import locally, run the following
command:

```sh
cargo xtask swift local
```

The package is written to `swift/local_build/walletkit-swift`. To build only the
bindings and `swift/WalletKit.xcframework`, run `cargo xtask swift build`.

To use the local package in an app, add it to the app's `Package.swift`
dependencies, adjusting the path to your checkout:

```swift
dependencies: [
    .package(name: "WalletKit", path: "../walletkit/swift/local_build/walletkit-swift"),
],
```

Then add the `WalletKit` product to each target that needs it:

```swift
.target(
    name: "YourTarget",
    dependencies: [
        .product(name: "WalletKit", package: "WalletKit"),
    ]
),
```

## Run the Swift tests

To build the bindings and run the XCTest suite on an available iPhone simulator,
run:

```sh
cargo xtask swift test
```

To test bindings that you built separately, as CI does, add `--skip-build`.
