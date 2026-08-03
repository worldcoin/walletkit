# Swift for WalletKit

This folder contains Swift support files for WalletKit:

1. Swift Package Manager configuration.
2. Foreign tests (XCTest suite) under `tests/`.

Swift automation is implemented by the workspace xtask and requires macOS with
Xcode, the iOS Rust targets, and `nargo` v1.0.0-beta.11 installed.

## Building the Swift bindings

Run from anywhere in the workspace:

```bash
cargo xtask swift build
```

This cross-compiles WalletKit, generates the UniFFI Swift bindings, and creates
`swift/WalletKit.xcframework`.

## Testing WalletKit locally

Build a package that can be imported locally through Swift Package Manager:

```bash
cargo xtask swift local
```

The complete package is created at `swift/local_build/walletkit-swift`.

## Integration via Package.swift

Add the local package to your `Package.swift` dependencies:

```swift
dependencies: [
    .package(name: "WalletKit", path: "../../../walletkit/swift/local_build/walletkit-swift"),
    // ... other dependencies
],
```

Then add it to the targets that need WalletKit:

```swift
.target(
    name: "YourTarget",
    dependencies: [
        .product(name: "WalletKit", package: "WalletKit"),
        // ... other dependencies
    ],
),
```

## Running foreign tests for Swift

```bash
cargo xtask swift test
```

The command builds the bindings and runs the test suite on an available iPhone
simulator. To test artifacts built separately, as CI does, run:

```bash
cargo xtask swift test --skip-build
```
