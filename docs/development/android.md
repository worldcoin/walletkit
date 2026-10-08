# Android and Kotlin

WalletKit's Kotlin bindings are generated with UniFFI and built by the workspace
`xtask`. This page describes how to build, test, and publish them locally.

## Before you begin

- Use the `android` Nix shell, which provides the Rust toolchain, the Android NDK,
  and the linkers. The `xtask` doesn't enter the shell for you, so run it through
  `nix develop .#android`, or provide the same dependencies yourself.
- For Gradle's Android tasks, install the Android SDK and NDK from Android Studio,
  in **Settings > Android SDK**. Then set `sdk.dir`, and `ndk.dir` if needed, in
  `kotlin/local.properties`.

The Kotlin project in `kotlin/` has two modules:

- `walletkit`: the Android library with the generated bindings
- `walletkit-tests`: JUnit tests of the bindings

## Build the bindings

To cross-compile WalletKit and generate the Kotlin bindings, run the following
command:

```sh
nix develop .#android --command cargo xtask kotlin build
```

## Run the Kotlin tests

To build a host library for macOS or Linux, generate bindings, and run the JUnit
suite on the JVM, run the following command. The `android` shell provides the
JDK 17 and `nargo` that the tests need:

```sh
nix develop .#android --command cargo xtask kotlin test
```

## Test with an app before release

To try local changes in an Android app, publish them to Maven Local:

1. Build and publish a version, for example `0.3.1`:

   ```sh
   nix develop .#android --command cargo xtask kotlin local 0.3.1
   ```

   The command builds the Rust library for `arm64-v8a`, `armeabi-v7a`, `x86_64`,
   and `x86`, generates the Kotlin bindings, and publishes them to
   `~/.m2/repository/org/world/walletkit/`.

1. In the app, add `mavenLocal()` to the Gradle repositories and set the WalletKit
   dependency to the version that you published.

To use Rust from a non-default location, set `RUSTUP_HOME` and `CARGO_HOME` when
you run the command.
