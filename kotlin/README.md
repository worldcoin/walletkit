# Kotlin for WalletKit

This folder contains support files for WalletKit to work in Kotlin:

1. Script to build Kotlin/JNA bindings.
2. Foreign tests (JUnit) for Kotlin in the `walletkit-tests` module.

## Building the Kotlin project

```bash
    # run from the walletkit directory
    ./kotlin/build_kotlin.sh
```

## Running foreign tests for Kotlin

```bash
    # run from the walletkit directory
    ./kotlin/test_kotlin.sh
```

## Kotlin project structure

The Kotlin project has two members:
- `walletkit`: The main WalletKit library with UniFFI bindings for Kotlin.
- `walletkit-tests`: Unit tests to assert the Kotlin bindings behave as intended (foreign tests).
