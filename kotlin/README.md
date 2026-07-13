# Kotlin for WalletKit

This folder contains support files for WalletKit to work in Kotlin:

1. Android library and Kotlin binding configuration.
2. Foreign tests (JUnit) for Kotlin in the `walletkit-tests` module.

## Building the Kotlin project

Run the Kotlin build xtask from anywhere in the workspace:

```bash
cargo xtask kotlin build
```

The Android cross-compilation environment must be configured. See
[`nix/README.md`](../nix/README.md) for the supported Nix and Docker workflows.

## Running foreign tests for Kotlin

```bash
cargo xtask kotlin test
```

The test task builds a host library for macOS or Linux, generates bindings, and
runs the Kotlin/JVM test suite.

## Publishing to Maven Local

```bash
nix develop .#android --command cargo xtask kotlin local 0.3.1
```

## Kotlin project structure

The Kotlin project has two members:

- `walletkit`: The main WalletKit library with UniFFI bindings for Kotlin.
- `walletkit-tests`: Unit tests to assert the Kotlin bindings behave as intended (foreign tests).
