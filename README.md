WalletKit enables mobile applications to use [World ID](https://world.org/world-id).

Part of the [World ID SDK](https://docs.world.org/world-id).

WalletKit can be used as a Rust crate, or directly as a Swift or Android package. WalletKit includes foreign bindings for direct usage in Swift/Kotlin through [UniFFI](https://github.com/mozilla/uniffi-rs).

## Installation

**To use WalletKit in another Rust project:**

```bash
cargo install walletkit
```

**To use WalletKit in an iOS app:**

WalletKit is distributed through a separate repo specifically for Swift bindings. This repo contains all the binaries required and is a mirror of `@worldcoin/walletkit`.

1. Navigate to File > Swift Packages > Add Package Dependency in Xcode.
2. Enter the WalletKit repo URL (note this is **not** the same repo): `https://github.com/worldcoin/walletkit-swift`

**To use WalletKit in an Android app:**

WalletKit's bindings for Kotlin are distributed through GitHub packages.

1. Update `build.gradle` (App Level)

```kotlin
dependencies {
    /// ...
    implementation "org.world:walletkit:VERSION"
}
```

Replace `VERSION` with the desired WalletKit version.

2. Sync Gradle.

## Local development (Android/Kotlin)

### Prerequisites

1. **Docker Desktop**: Required for cross-compilation
   - The build uses [`cross`](https://github.com/cross-rs/cross) which runs builds in Docker containers with all necessary toolchains
   - Install via Homebrew:
     ```bash
     brew install --cask docker
     ```
   - Launch Docker Desktop and ensure it's running before building

2. **Android SDK + NDK**: Required for Gradle Android tasks
   - Install via Android Studio > Settings > Android SDK (ensure the NDK is installed)
   - Set `sdk.dir` (and `ndk.dir` if needed) in `kotlin/local.properties`

3. **Protocol Buffers compiler**:
   ```bash
   brew install protobuf
   ```

### Building and publishing

To test local changes before publishing a release, use the build script to compile the Rust library, generate UniFFI bindings, and publish a SNAPSHOT to Maven Local:

```bash
./kotlin/build_android_local.sh 0.3.1-SNAPSHOT
```

> **Note**: The script sets `RUSTUP_HOME` and `CARGO_HOME` to `/tmp` by default to avoid Docker permission issues when using `cross`. You can override them by exporting your own values.

This will:
1. Build the Rust library for all Android architectures (arm64-v8a, armeabi-v7a, x86_64, x86)
2. Generate Kotlin UniFFI bindings
3. Publish to `~/.m2/repository/org/world/walletkit/`

In your consuming project, ensure `mavenLocal()` is included in your repositories and update your dependency version to the SNAPSHOT version (e.g., `0.3.1-SNAPSHOT`).

## Overview

WalletKit is broken down into separate crates, offering the following functionality.

- `walletkit-core` - Enables basic usage of a World ID to generate ZKPs using different credentials.

### World ID Secret

- Each World ID requires a secret. The secret is used in ZKPs to prove ownership over a World ID.
- Each host app is responsible for generating, storing and backing up a World ID secret.
- A World ID secret is a 32-byte secret generated with a cryptographically secure random function.
- The World ID secret **must** never be exposed to third-parties and **must not** leave the holder's device.
  //TODO: Additional guidelines for secret generation and storage.

## Getting Started

WalletKit is generally centered around a World ID. The most basic usage requires initializing a `WorldId`.

A World ID can then be used to generate [Zero-Knowledge Proofs](https://docs.world.org/world-id/further-reading/zero-knowledge-proofs).

A ZKP is analogous to _presenting_ a credential.

```rust
use walletkit::{proof::ProofContext, CredentialType, Environment, world_id::WorldId};

async fn example() {
    let world_id = WorldId::new(b"not_a_real_secret", &Environment::Staging);
    let context = ProofContext::new("app_ce4cb73cb75fc3b73b71ffb4de178410", Some("my_action".to_string()), None, CredentialType::Orb);
    let proof = world_id.generate_proof(&context).await.unwrap();

    println!(proof.to_json()); // the JSON output can be passed to the Developer Portal, World ID contracts, etc. for verification
}
```

## 🛠️ Logging

WalletKit includes logging functionality that can be integrated with foreign language bindings. The logging system allows you to capture debug information and operational logs from the library.

### Basic Usage

Implement the `Logger` trait and set it as the global logger:

```rust
use walletkit_core::logger::{Logger, LogLevel, set_logger};
use std::sync::Arc;

struct MyLogger;

impl Logger for MyLogger {
    fn log(&self, level: LogLevel, message: String) {
        println!("[{:?}] {}", level, message);
    }
}

// Set the logger once at application startup
set_logger(Arc::new(MyLogger));
```

### Swift Integration

```swift
class WalletKitLoggerBridge: WalletKit.Logger {
    static let shared = WalletKitLoggerBridge()

    func log(level: WalletKit.LogLevel, message: String) {
        // Forward to your app's logging system
        Log.log(level.toCoreLevel(), message)
    }
}

// Set up the logger in your app delegate
public func setupWalletKitLogger() {
    WalletKit.setLogger(logger: WalletKitLoggerBridge.shared)
}
```

### Kotlin Integration

```kotlin
class WalletKitLoggerBridge : WalletKit.Logger {
    companion object {
        val shared = WalletKitLoggerBridge()
    }

    override fun log(level: WalletKit.LogLevel, message: String) {
        // Forward to your app's logging system
        Log.log(level.toCoreLevel(), message)
    }
}

// Set up the logger in your application
fun setupWalletKitLogger() {
    WalletKit.setLogger(WalletKitLoggerBridge.shared)
}
```
