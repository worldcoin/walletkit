# WalletKit Swift Foreign Binding Tests

Foreign binding tests that verify the FFI (Foreign Function Interface) between Rust and Swift works correctly.

## Running Tests

From the repository root:

```bash
./swift/test_swift.sh
```

This script will automatically:

1. Build the Rust library for iOS targets
2. Generate Swift bindings via UniFFI
3. Copy bindings to the test package
4. Run the tests on iOS Simulator

**Note:** You don't need to run `build_swift.sh` separately - the test script does it for you.

## What These Tests Verify

### 1. U256Wrapper (Comprehensive)

- All constructors: `fromU64`, `fromU32`, `fromLimbs`, `tryFromHexString`
- Output conversions: `toHexString`, `toDecimalString`, `intoLimbs`
- Edge cases: max values, zero, empty strings
- Deterministic outputs matching Rust test values
- Round-trip conversions
- Error handling for invalid inputs

### 2. Authenticator (Error Cases)

- Invalid seed validation (empty, too short, too long)
- Invalid RPC URL validation
- Non-existent account errors
- Multiple environments (staging, production)

### 3. FFI Boundary

- Type marshalling between Rust and Swift
- Error propagation across FFI
- Async function calls from Swift to Rust
- Enum variants (Environment, WalletKitError, etc.)
