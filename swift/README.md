# Swift for WalletKit

This folder contains Swift support files for WalletKit:

1. Script to cross-compile and build Swift bindings.
2. Script to build a Swift package for local development.
3. Foreign tests (XCTest suite) for Swift under `tests/`.

## Building the Swift bindings

To build the Swift project for release/distribution:

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
