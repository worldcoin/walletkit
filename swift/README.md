# WalletKit Swift Bindings

This directory contains the Swift bindings and test infrastructure for WalletKit.

## Building

To build the Swift XCFramework:

```bash
./build_swift.sh
```

This will:
1. Build the Rust library for all iOS targets (arm64 device, arm64 simulator, x86_64 simulator)
2. Generate Swift bindings using UniFFI
3. Create `WalletKit.xcframework`

## Testing

To run the Swift tests:

```bash
./test_swift.sh
```

This will:
1. Build the Swift bindings
2. Copy generated files to the test package
3. Run tests on an iOS simulator

## Directory Structure

```
swift/
├── build_swift.sh           # Build script for XCFramework
├── test_swift.sh            # Test runner script
├── README.md                # This file
├── WalletKit.xcframework/   # Generated framework (not in git)
├── Sources/
│   └── WalletKit/
│       └── walletkit_core.swift  # Generated Swift bindings
└── tests/
    ├── Package.swift        # Swift Package manifest
    ├── Sources/
    │   └── WalletKit/       # Copy of generated bindings for tests
    └── WalletKitTests/
        └── *.swift          # Swift test files
```

## Integration

To use WalletKit in your iOS app:

1. Build the framework using `./build_swift.sh`
2. Add `WalletKit.xcframework` to your Xcode project
3. Import the module in your Swift code:

```swift
import WalletKit

// Example usage
let store = try WorldIdStore(rootPath: documentsPath)
let account = try store.createAccount()
print("Created account: \(account.accountId().hex)")

// Store a credential
let credId = generateCredentialId()
try account.storeCredential(
    credentialId: credId,
    credentialBlob: Data("credential data".utf8).map { $0 },
    associatedData: nil
)

// List credentials
let filter = CredentialFilter(issuerSchemaId: nil, status: nil, includeExpired: false)
let credentials = try account.listCredentials(filter: filter)
```
