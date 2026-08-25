# BoltFFI-only binding experiment

This branch removes WalletKit's UniFFI dependency, generator crate, and
annotations. `walletkit-core` is annotated directly with BoltFFI 0.30.1; there
is no annotation facade or proc-macro wrapper.

## What works

BoltFFI can scan the migrated API and generate Swift, Kotlin/JNI, and
TypeScript bindings. It can also build and package a loadable
`wasm32-unknown-unknown` npm package. The generated Node loader has been smoke
tested by constructing a `UserAgent` and calling `headerValue()`. A second
smoke test constructs `CredentialStore` with JavaScript keystore/blob-store
callbacks and calls `destroyStorage()`, proving callbacks cross both sides of
the WASM boundary.

The WASM package currently exposes the synchronous part of the API: records,
enums, errors, callback interfaces, storage classes, `FieldElement`,
`Credential`, `Authenticator`'s synchronous methods, proof request/response
types, and user-agent helpers.

## Build the WASM package

Install BoltFFI 0.30.1 and TypeScript, then run:

```sh
CC_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/clang \
  boltffi pack wasm --release \
  --cargo-arg=--locked \
  --cargo-arg=--no-default-features \
  --cargo-arg=--features=boltffi-wasm
```

Output is written to `target/boltffi/pkg`.

The compiler override avoids a Darwin Nix `cc-wrapper` hardening flag that is
invalid for the WASM target. It is an environment workaround, not a BoltFFI
requirement. Cargo arguments intentionally live on the command because
BoltFFI 0.30.1 duplicates configured cargo arguments between its pack and
generate phases.

## API adaptations

- Exported functions use direct `#[boltffi::export]`, `#[boltffi::data]`, and
  `#[boltffi::error]` annotations.
- Exported `Result` aliases were expanded because BoltFFI does not resolve
  those aliases while scanning source.
- `CredentialStore` owns shared state internally and is passed as a Bolt class,
  rather than exporting `Arc<CredentialStore>` handles.
- Callback traits cannot inherit supertraits in BoltFFI metadata. ZK artifact
  providers therefore use the opaque `WalletKitZkArtifacts` class.
- A callback provider returning other callback objects could not be encoded,
  so `StorageProvider` remains a Rust-only convenience. The binding-facing
  storage constructor accepts `DeviceKeystore` and `AtomicBlobStore` directly.
- Binding-facing 256-bit integers are padded hexadecimal strings. The local
  `Uint256` wrapper keeps the existing Rust and V3 API source-compatible, but
  BoltFFI 0.30.1 could not match it as a custom binding type.
- Async binding parameters are owned values because BoltFFI futures must be
  `'static`.

## Blocking issues

This is not yet a usable replacement for the complete WalletKit WASM API.
BoltFFI 0.30.1 requires every exported Rust future to implement `Send` in its
WASM runtime bridge. WalletKit's browser `reqwest` and Alloy futures are
correctly `!Send`, because they run on the browser's single-threaded event
loop. Consequently the `boltffi-wasm` feature excludes async exports so that
the package can be built and inspected. In particular, the generated
`Authenticator` has no async constructor or proof/network operations.

The experiment therefore establishes that the data model, synchronous calls,
callbacks, code generation, packaging, and runtime loading work. Completing
the replacement requires one of:

1. BoltFFI support for local (`!Send`) futures on WASM; this is the preferred
   fix because it preserves WalletKit's async API.
2. A WASM-specific start/callback or polling adapter around every async method;
   this is substantially more WalletKit-owned surface and should only be used
   if the upstream runtime cannot be changed.

There is a second runtime integration gap: initializing credential storage
reaches `getrandom`'s `wasm_js` backend, whose generated
`__wbg_getRandomValues_*` import is not implemented by BoltFFI's npm runtime.
The callback bridge itself works, but `CredentialStore::init` fails when it
needs secure randomness. A complete package therefore also needs BoltFFI to
forward the standard `wasm-bindgen` Web Crypto import, or WalletKit needs a
secure random-source import supported by BoltFFI. Falling back to insecure
randomness is not acceptable.

Native Swift and Kotlin source generation succeeds with the same direct
annotations, but this branch does not yet replace the repository's existing
XCFramework, JNI, Gradle, or release packaging pipelines with BoltFFI's native
packagers.
