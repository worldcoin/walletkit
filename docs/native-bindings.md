# Native SDKs

WalletKit owns its Swift and Kotlin public APIs and ships their implementations
with Rust. Apps import `WalletKit` in Swift or `org.world.walletkit` in Kotlin;
they do not generate sources or call the native layer directly.

## Layout and artifacts

- `crates/walletkit-core`: domain logic, storage, recovery, proving, and matching;
  plain Rust without a binding framework.
- `crates/walletkit`: re-exports the core and, behind features, the bindings in
  `src/native`:
  - `ops/`: one plain Rust function per SDK method, shared by both bindings;
  - `jni/` (feature `jni`): JNI runtime; `#[jni_export]` turns each operation into a
    `Java_org_world_walletkit_NativeBridge_*` symbol;
  - `c/` (feature `c`): C wrappers declared in the generated
    `native/include/walletkit_coreFFI.h`;
  - `codec.rs`, `values.rs`, `error.rs`: the binary encoding of records, lists, maps,
    enumerations, and errors;
  - `registry.rs`, `operation.rs`, `integrity.rs`: handles, async execution, and
    asynchronous host callbacks.
- `crates/walletkit-jni-macros`: the `#[jni_export]` attribute.
- `kotlin/walletkit`: the Kotlin API and JNI libraries in the `org.world:walletkit`
  Android AAR. Minimum Android API remains 23.
- `swift/native`: the Swift 6 API. Releases contain these sources plus an iOS
  device/simulator XCFramework with the C header. The product remains `WalletKit` in
  `worldcoin/walletkit-swift`.
- `crates/walletkit-web`: the browser facade over `walletkit-core` with
  `wasm-bindgen`; it does not use this layer.

Android builds enable `jni` and iOS builds enable `c` (the xtasks add them). Releases
retain `compress-zkeys,embed-zkeys,v3` and default features. Operations of features
missing from a build are absent from the library, so ship the full release feature
set to mobile apps.

## How a call crosses

Each SDK method maps to one Rust function:

```rust
/// `FieldElement.toHexString`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn field_element_to_hex_string(element: Arc<FieldElement>) -> String {
    element.to_hex_string()
}
```

Kotlin calls the generated JNI symbol directly:

```kotlin
@JvmStatic external fun fieldElementToHexString(element: NativeHandle): String // NativeBridge
fun toHexString(): String = NativeBridge.fieldElementToHexString(handle)
```

Swift calls the C wrapper, `walletkit_field_element_to_hex_string`, which converts the
arguments, calls the same function, and writes the result or an error:

```swift
public func toHexString() throws -> String {
  try handle.withID { id in
    try callString { walletkit_field_element_to_hex_string(WalletKitFieldElementHandle(id: id), $0, $1) }
  }
}
```

The parameter and result types select the representation; the JNI conversions live in
`FromJni`/`IntoJni` impls, so the macro stays small:

| Rust | Kotlin / JNI | C |
|---|---|---|
| `u64`, `u32`, `bool` | `Long`, `Int`, `Boolean` | same-width integer, `bool` |
| `Option<u64>` | `Long?` | nullable `const uint64_t *` |
| `String`, `Vec<u8>` | `String`, `ByteArray` | `WalletKitByteSlice` in, `WalletKitBuffer` out |
| `Option<String>`, `Option<Vec<u8>>` | nullable | nullable slice pointer in, null buffer out |
| fieldless enum | `Int` ordinal | `uint8_t` ordinal; optional input `int32_t`, -1 if absent |
| `Uint256` | 32-byte `ByteArray` | `WalletKitUint256` |
| `Arc<T>` resource | `NativeHandle` in, `Long` out | `WalletKit<T>Handle` |
| `Binary<T>`: record, list, map | `ByteArray` | slice in, buffer out |
| `Arc<dyn Callback>` | Kotlin interface | callback table |
| `Operation` | `Long` from `operationNew` | `WalletKitOperationHandle` |

Scalars, strings, bytes, handles, and enumerations cross as primitives. Records,
lists, maps, and nested inputs use the binary encoding.

## Binary encoding and errors

`native/codec.rs` defines the layout: little-endian integers, `u32`-length-prefixed
UTF-8 strings and bytes, a tag byte for optionals, a count for lists and maps, an
ordinal byte for fieldless enumerations, and a variant index followed by the fields
for enumerations with fields. `native/values.rs` holds one encoder or decoder per
type and the frozen ordinals and variant indices. Kotlin (`Codec.kt`) and Swift
(`Codec.swift`) implement the matching decoders for results and encoders for inputs.

The three implementations must agree byte for byte. Frozen fixtures in
`values.rs`, `CodecTest.kt`, and `CodecTests.swift` pin the same bytes; changing one is
a wire-format change. Never renumber an ordinal or variant: append new ones and update
all three codecs and fixtures together.

Errors use the same encoding with a leading domain byte: `0` bridge failure with a
fixed code, `1` `WalletKitError`, `2` `StorageError`, `3` `FlamingoError`, `4`
`CredentialConstraintsCheckError`. JNI throws the SDK exception that
`NativeBridge.nativeError` decodes; C functions return `false` and write the encoded
error to `out_error`. The bridge code `Cancelled` becomes `CancellationException` or
`CancellationError`.

A host callback can fail with a storage error: Kotlin throws `StorageException`,
Swift throws `StorageError`, and Rust receives the encoded variant. Any other host
failure becomes `StorageError.Callback("HostFailure")`, so host messages, which may
contain secrets, do not cross. Errors and default descriptions identify the variant
without printing payloads. Never log seeds, keys, credentials, raw requests, or
arbitrary error details.

`ABI_VERSION` (2) changes whenever an existing symbol, ordinal, or encoding changes.
The SDKs check it when they load the library and refuse to run against another
version. Ship SDK sources and native binaries from the same release. Native symbols
are not a supported app API.

## Ownership

Handles are monotonically allocated, process-local registry IDs, never pointers, so a
stale or mistyped handle fails with `InvalidHandle` instead of touching freed memory.
A call resolves its handles to `Arc`s first, so closing a resource during a call cannot
free an object that the call uses.

Kotlin resources are `AutoCloseable`; use `use { ... }` or close long-lived resources.
A phantom-reference queue is a fallback. Kotlin passes the `NativeHandle` object to
JNI; its local reference keeps the owner reachable during the call (API 23 has no
`reachabilityFence`). Swift resources release through ARC and support `close()`;
calls keep the handle alive with `withExtendedLifetime`. Close is idempotent and
closed resources reject new calls.

Returned handles belong to the caller. Handles inside an encoded result are released
if the result never reaches the host (for example when the JNI array cannot be
allocated), and the SDK decoders release the handles they read if decoding fails.

## Threads, async calls, and cancellation

Synchronous methods run on the caller's thread; keep blocking operations off the UI
thread. Swift `async throws` and Kotlin `suspend` methods call blocking native
functions on four native workers. Kotlin queues up to 128 calls behind the running ones;
Swift admits up to 128 calls in total, running or queued. Further calls fail with
`Busy`.

An async call first creates an operation token (`operationNew` /
`walletkit_operation_new`). The worker passes it to the native function, which drives
the domain future on the shared Tokio runtime until it completes or the token is
cancelled. Cancelling the coroutine or task cancels the token. Cancellation drops the
future at its next yield point; it cannot interrupt synchronous proving or undo
committed storage or remote effects. Swift reports cancellation after the native call
returns. Kotlin stops waiting at once; the worker finishes the call and releases a
late result. Native functions called from a runtime thread, such as a callback that
re-enters WalletKit, fail with `ReentrantCall`.

Callbacks run on background threads and must be thread-safe:

- Keystore and blob store callbacks are synchronous. Do not synchronously re-enter
  WalletKit or wait for work that needs the same store lock.
- Logs and change notifications keep the core's delivery threads. On Android, a failing
  listener is reported through the WalletKit log, and a failing logger through stderr,
  without payloads.
- On Android, Rust threads attach to the JVM once, as daemons, and stay attached, so a
  callback costs one JNI call. `JNI_OnLoad` resolves the classes, method IDs, and field
  IDs that Rust uses, so `System.loadLibrary` fails at once if R8 renamed one;
  `consumer-rules.pro` keeps them.
- In C, a callback table is `{ context, functions…, release }`. Rust owns one retain of
  `context` and calls `release` exactly once, including when the call that received
  the table fails. Callback outputs are allocated with `walletkit_buffer_copy`.
- `RequestIntegrityProvider.prepare` is asynchronous. Rust passes a completion ID to
  the host, which completes it once from any thread
  (`walletkit_request_integrity_prepared`/`_failed`, or the Kotlin coroutine through
  `NativeBridge`). A late completion after the matcher's deadline is ignored.

C response buffers are zeroed when freed, and byte results are zeroed in Rust after
they are copied to Java. Seeds are zeroed on every path, including invalid arguments
and cancellation before a call starts; the Java copies of keystore plaintext are zeroed
after each callback. Managed strings, callback arguments, and caller buffers can
retain other copies, so this is not a guarantee of complete secret erasure. Rust
invariant panics keep the existing release abort policy.

## Adding an operation

1. Add the function to the matching `native/ops` module with
   `#[cfg_attr(feature = "jni", jni_export)]`. Wrap results in `Arc` for resources and
   `Binary` for records; async operations take an `Operation` first and call
   `operation.run(async move { ... })`.
2. For a new record or enumeration, add its encoder or decoder and ordinals to
   `values.rs`, plus a frozen fixture. Add `FromJni`/`IntoJni` impls only for a new kind
   of type.
3. Add the C wrapper to the matching `native/c` module and regenerate the header:
   `nix develop --command cbindgen --config crates/walletkit/cbindgen.toml --output native/include/walletkit_coreFFI.h crates/walletkit`.
   CI fails if the committed header is stale.
4. Add the Kotlin `external fun` to `NativeBridge` and the public method; add the
   Swift method. Update `Codec.kt`/`Codec.swift` and their fixtures for new values, and
   `JNI_OnLoad` plus `consumer-rules.pro` for new callback interfaces.
5. Add Rust, Kotlin, and Swift tests for new ownership, enumeration, error, or callback
   behavior. Compilation alone does not prove that the codecs agree.

## Migration from UniFFI

Package identities remain, but this is a source-breaking SDK release:

- Kotlin imports move from generated `uniffi.*` to `org.world.walletkit.*`. Resources
  use `AutoCloseable`; domain errors use `*Exception` names and enum constants use
  upper snake case. Async APIs remain coroutines. The AAR no longer depends on JNA or
  kotlinx-serialization.
- Swift requires Swift 6. Native-state methods, including getters, now throw to report
  closed handles and bridge failures. Rust `new` factories use `create`; `init` methods
  use `initialize`. Descriptive factories such as `newWithComponents` remain.
- `Uint256` replaces the UniFFI adapter/Swift BigInt dependency. Construct from hex or
  exactly 32 big-endian bytes. It is a value type, not an arithmetic API.
- Activity filters are immutable Swift/Kotlin values, with `withIssuerSchemaId`
  builders. They do not need native resource handles.
- Supply keystore/blob-store components to `CredentialStore.newWithComponents`. The
  Rust-only `StorageProvider` convenience trait is not in the native API.
- Attested Flamingo matching uses `FlamingoMatcher.newAttested` with a
  `RequestIntegrityProvider` (a Kotlin `suspend` function or a Swift `async` method)
  that returns a `RequestIntegritySession` and its `RequestDigestSigner`.

Pin matching SDK/app changes together. Roll back to the previous SDK/app build; this
change requires no database migration. Existing SQLite schemas, CBOR layouts, and
content ID derivations are unchanged.

## Development

Use the repository Nix shells. `cargo xtask swift local --debug` builds a local Swift
package on macOS; `nix develop .#android --command cargo xtask kotlin local <version> --debug`
builds a local Android package.

```sh
cargo test -p walletkit --all-features   # codecs, C ABI, callbacks, cancellation
cargo xtask kotlin test                  # Kotlin/JVM tests against the host library
cargo xtask swift test                   # Swift tests against the XCFramework (macOS)
```

The root `Package.swift` is a macOS harness for the Swift tests against a host library
built with all features:

```sh
cargo build -p walletkit --all-features
swift test -Xlinker -L -Xlinker "$PWD/target/debug" \
  -Xlinker -rpath -Xlinker "$PWD/target/debug"
```

Run the README's three Clippy feature configurations for binding changes.
