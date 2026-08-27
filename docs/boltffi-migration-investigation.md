# Replacing UniFFI with BoltFFI

Date: 2026-08-27

## Conclusion

Replacing UniFFI with BoltFFI is feasible for WalletKit's native Swift and
Kotlin bindings, but it is an API-breaking migration and this draft is not yet
sufficient for a production release. BoltFFI 0.30.1 now scans the adapted
surface with the exact release features and generates Swift and Kotlin/JNI
sources without skipped items. The native configuration, `xtask`, Nix, CI,
Gradle, and release paths have been migrated in this branch. The remaining
release gates are:

1. restore the complete binding surface without silently dropping or reshaping
   consumers' APIs;
2. provide and test a Tokio runtime for native async operations;
3. work around or fix BoltFFI 0.30.1's invalid Swift rendering of async
   `Self`-returning factories;
4. freeze the intended source-level API in compile tests and exercise the
   generated JNI/Swift binaries;
5. decide whether preserving `BigInteger`/`BigUInt` for `Uint256` is required;
6. treat browser/WASM support as a separate blocked workstream.

The migration should therefore be released as a breaking version, even if the
new package/module names are configured to minimize import churn.

## Sources and version boundary

This report uses the published BoltFFI 0.30.1 sources for behavioral constraints
and the official BoltFFI documentation for generated API and packaging format.
The official documentation can move ahead of a release, so constraints that
affect feasibility are also linked to versioned 0.30.1 source.

Repo-local evidence comes from the UniFFI baseline at `origin/main`, the
current migration branch, and [the earlier runnable experiment](boltffi-only-experiment.md).

## Annotation and scanner migration

| UniFFI surface | BoltFFI surface | Migration effect |
| --- | --- | --- |
| `#[derive(uniffi::Record)]` | `#[boltffi::data]` | Value type copied across the boundary. |
| `#[derive(uniffi::Enum)]` | `#[boltffi::data]` | Plain and payload enums are generated as native enum/sealed forms. |
| `#[derive(uniffi::Error)]` | `#[boltffi::error]` | `Result<T, E>` becomes Swift `throws` and Kotlin exceptions. |
| `#[derive(uniffi::Object)]` plus `#[uniffi::export] impl` | plain Rust struct plus `#[boltffi::export] impl` | The exported impl defines the class surface; the struct itself need not be annotated. |
| `#[uniffi::constructor]` | no method annotation | A public associated function returning `Self` or `Result<Self, E>` is inferred as a constructor/factory. |
| `#[uniffi::export(with_foreign)] trait` | `#[boltffi::export] trait` | Generates a Swift protocol/Kotlin interface callback. |
| `#[uniffi::export(async_runtime = "tokio")]` | `#[boltffi::export]` on an async function/impl | Target API stays async, but BoltFFI does not supply the Tokio runtime. |

BoltFFI documents `#[data]` and `#[export]` as the basic markers and requires
`staticlib`/`cdylib` crate output for packaged targets
([Getting Started](https://github.com/boltffi/boltffi/blob/8f862c8dd35ec9d8437ac0212c001baf0d700dd2/docs/src/content/docs/getting-started.mdx#L33-L79)).
Classes are inferred from exported impl blocks, and `Self`-returning methods are
inferred as constructors or factories
([Classes](https://github.com/boltffi/boltffi/blob/8f862c8dd35ec9d8437ac0212c001baf0d700dd2/docs/src/content/docs/classes.mdx#L19-L167)).

The scanner recognizes BoltFFI's marker vocabulary directly. A future macro
facade must expand into scanner-visible BoltFFI markers; an arbitrary attribute
name will not be discovered by the source scanner. The direct annotations used
by the current experiment are the lower-risk first migration.

## Generated API differences

The configured generated surface has these concrete source changes:

| Surface | UniFFI | BoltFFI in this branch |
| --- | --- | --- |
| Kotlin package | `uniffi.walletkit_core` | `org.world.walletkit` |
| Kotlin native bridge | JNA runtime | generated JNI `Native` bridge and `libwalletkit_jni`/Android `libwalletkit.so` |
| Kotlin errors | UniFFI-generated exception hierarchy | sealed exception classes such as `WalletKitError.InvalidInput` |
| Kotlin async | `suspend` | `suspend` (preserved) |
| Swift module | `WalletKit` | `WalletKit` (preserved by configuration) |
| Swift errors | UniFFI-generated errors | BoltFFI enums conforming to `Error`; fallible calls still use `throws` |
| Swift async | `async`/`async throws` | preserved for ordinary methods, currently broken for async factories returning `Self` |
| `Uint256` | Kotlin `BigInteger`, Swift `BigUInt` | padded `0x`-prefixed 64-digit hex `String` in both languages |
| Factories | UniFFI constructor annotations | inferred from Rust functions returning `Self`; Kotlin uses named companion methods, Swift renders labeled initializers |
| Callbacks | UniFFI foreign traits | Swift protocols/Kotlin interfaces backed by BoltFFI callback handles |

For example, Kotlin imports change from
`uniffi.walletkit_core.LogLevel` to `org.world.walletkit.LogLevel` (or need no
import from code already in that package). `LogLevel.INFO` remains unchanged.
Swift continues to use `import WalletKit` and `.info`, but generated ownership,
callback, and exception helper types are BoltFFI-specific.

### Values, names, and top-level functions

BoltFFI maps primitive-only Rust records to Swift structs with public mutable
properties and Kotlin `data class` values with `val` properties. It converts
Rust snake case to target-language lower camel case
([Records](https://github.com/boltffi/boltffi/blob/8f862c8dd35ec9d8437ac0212c001baf0d700dd2/docs/src/content/docs/records.mdx#L21-L104)).

Kotlin functions are top-level by default, but configuration can instead place
them on a module object. Kotlin factories can likewise be rendered as
constructors or companion methods
([Android configuration](https://github.com/boltffi/boltffi/blob/8f862c8dd35ec9d8437ac0212c001baf0d700dd2/docs/src/content/docs/configuration.mdx#L336-L397)).
These settings must be pinned in `boltffi.toml`; relying on defaults makes the
public API vulnerable to accidental changes.

WalletKit-specific expected changes:

- Kotlin currently imports `uniffi.walletkit_core.*`. BoltFFI defaults to
  `com.example.{name}`, so the package must be explicitly configured. Keeping
  `uniffi.walletkit_core` minimizes import churn but preserves a misleading
  name; choosing a new package is cleaner and explicitly breaking.
- Swift's module name must be explicitly configured as `WalletKit` to preserve
  `import WalletKit`; BoltFFI otherwise derives it from the package name
  ([Swift module configuration](https://github.com/boltffi/boltffi/blob/8f862c8dd35ec9d8437ac0212c001baf0d700dd2/docs/src/content/docs/configuration.mdx#L106-L119)).
- Kotlin field and function names remain lower camel case and enum constants
  remain uppercase (`LogLevel.INFO`) in the generated WalletKit 0.30.1 output.
  Swift enum cases remain lower camel case (`.info`).
- Byte vectors remain idiomatic (`Data` in Swift and `ByteArray` in Kotlin),
  but generated ownership wrappers and helper/runtime types are different.

### Objects and constructors

BoltFFI target objects are native class wrappers around Rust handles. A Rust
`new()` becomes a primary initializer. Named `Self` factories can become Swift
initializers/static factories and Kotlin constructors/companion factories,
depending on their signature and configuration. Fallible factories become
throwing APIs
([constructors](https://github.com/boltffi/boltffi/blob/8f862c8dd35ec9d8437ac0212c001baf0d700dd2/docs/src/content/docs/classes.mdx#L114-L415)).

This is material for WalletKit because `Authenticator`,
`InitializingAuthenticator`, `FieldElement`, `Credential`, and storage types
have multiple named constructors. With `factory_style = "companion_methods"`,
Kotlin factories are named companion functions and asynchronous factories are
`suspend`. This avoids a real JVM signature collision between BoltFFI's private
`FieldElement(Long)` handle constructor and the public `FieldElement(ULong)`
value constructor. Swift renders named factories as labeled initializers.

BoltFFI 0.30.1 currently renders WalletKit's async `Self`-returning factories
incorrectly in Swift: the generated initializer calls the C function that
creates a future handle as if it synchronously returned the class handle and
an error buffer. Kotlin correctly emits a companion `suspend` factory and the
C header contains the expected poll/complete/cancel functions. This is a
generated-code compile blocker. The migration must either move those entry
points to exported free async functions, or take an upstream BoltFFI fix before
the Swift package can ship.

BoltFFI requires exported classes to be `Send + Sync` and disallows `&mut self`
unless the entire impl uses `#[export(single_threaded)]`; the latter transfers
thread-safety responsibility to the host
([class thread safety](https://github.com/boltffi/boltffi/blob/8f862c8dd35ec9d8437ac0212c001baf0d700dd2/docs/src/content/docs/classes.mdx#L946-L1089)).
WalletKit should retain thread-safe classes rather than use
`single_threaded` as an annotation escape hatch.

### Errors

BoltFFI maps `Result` to Swift throwing functions and Kotlin functions that
throw exceptions. `String` errors become generic `FfiError`/`FfiException`;
`#[error]` structs and enums retain structured data in native error forms
([Errors](https://github.com/boltffi/boltffi/blob/8f862c8dd35ec9d8437ac0212c001baf0d700dd2/docs/src/content/docs/errors.mdx#L9-L41)).

This preserves the broad error-handling model but not the generated type
identity or case spelling. Swift `catch` switches and Kotlin exception catches
must be compiled against the generated BoltFFI surface. `WalletKitError`,
`StorageError`, and proof-constraint errors need cross-language tests covering
at least one unit case and one payload case each.

### Async functions

BoltFFI generates Swift `async`/`async throws` and Kotlin `suspend` APIs and
propagates cancellation through its future polling bridge
([Async](https://github.com/boltffi/boltffi/blob/8f862c8dd35ec9d8437ac0212c001baf0d700dd2/docs/src/content/docs/async.mdx#L9-L36)).
However, BoltFFI explicitly does not provide a Rust executor; code using
Reqwest or other Tokio I/O must arrange for an active Tokio runtime
([runtime requirement](https://github.com/boltffi/boltffi/blob/8f862c8dd35ec9d8437ac0212c001baf0d700dd2/docs/src/content/docs/async.mdx#L357-L363)).

This is a native release blocker. The UniFFI baseline marks six exported impl
blocks with `async_runtime = "tokio"` and enables UniFFI's `tokio` feature.
After removing UniFFI, `walletkit-core` only enables Tokio `sync` in normal
dependencies; runtime/macros are currently dev-only. Generated source can
succeed while the first network operation still fails at runtime. The
migration needs one explicit design:

- a WalletKit-owned process runtime used by all exported async entrypoints; or
- exported wrappers that spawn onto an owned runtime and await the result.

Validate from both XCTest and Kotlin/JUnit with a real async constructor and a
real HTTP-backed operation, not only a pure computation future.

BoltFFI 0.30.1 also requires every exported future and its output to be
`Send + 'static` in the runtime itself
([versioned source](https://docs.rs/crate/boltffi_core/0.30.1/source/src/runtime/future.rs#429-435)).
This is compatible with the intended native API after changing borrowed async
parameters to owned values, but blocks WalletKit's browser Reqwest/Alloy
futures, which are `!Send`.

### Callbacks and traits

An exported BoltFFI trait becomes a Swift protocol and Kotlin interface;
foreign implementations can be passed into and retained by Rust. Both sync
and async callback methods are supported
([Callbacks](https://github.com/boltffi/boltffi/blob/8f862c8dd35ec9d8437ac0212c001baf0d700dd2/docs/src/content/docs/callbacks.mdx#L153-L205)).

Restrictions relevant to WalletKit:

- generic traits, associated types, and default method implementations are not
  supported
  ([documented limitations](https://github.com/boltffi/boltffi/blob/8f862c8dd35ec9d8437ac0212c001baf0d700dd2/docs/src/content/docs/callbacks.mdx#L562-L570));
- the 0.30.1 scanner accepts only `Send`, `Sync`, and `Debug` as callback
  supertraits
  ([versioned scanner source](https://docs.rs/crate/boltffi_scan/0.30.1/source/src/items/callback.rs#62-87));
- `WalletKitZkArtifactSource: ZkArtifactSource + Send` therefore cannot be
  exported unchanged because `ZkArtifactSource` is an unsupported inherited
  trait. The current experiment replaces it with an opaque
  `WalletKitZkArtifacts` class;
- `DeviceKeystore`, `AtomicBlobStore`, `VaultChangedListener`, and `Logger`
  have only supported `Send + Sync` bounds and are natural callback migrations;
- the published 0.30.1 generator contains fixtures for callbacks returning
  `Arc<dyn Callback>`, so `StorageProvider` should be re-tested before keeping
  the experiment's API-breaking split into direct keystore/blob-store
  parameters. The earlier workaround is evidence of an experiment, not proof
  that the current exact generator requires it.

The existing logger/vault listener background-dispatch rules remain WalletKit
behavioral requirements even though the callback runtime changes. Keep their
reentrancy/deadlock tests.

### `Uint256` custom type

The UniFFI configuration maps `Uint256` to Kotlin `java.math.BigInteger` and
Swift `BigUInt`. BoltFFI supports Rust-side custom representations through
`custom_type!`/`#[custom_ffi]`
([Custom Types](https://github.com/boltffi/boltffi/blob/8f862c8dd35ec9d8437ac0212c001baf0d700dd2/docs/src/content/docs/custom-types.mdx#L9-L105)),
and this branch now registers `Uint256` as a custom type represented by a
padded hexadecimal string. Strict release-feature generation consequently
succeeds, but it does not reproduce those language-native mappings.

That is an observable API change. Before merging, choose one of:

1. preserve native `BigInteger`/`BigUInt` through supported target type
   mappings plus generated-code compile tests;
2. intentionally standardize on a documented 32-byte or padded-hex wire type;
3. expose a WalletKit value class with explicit decimal/hex conversion methods.

Do not leave the representation as an incidental generator workaround.

## Build and packaging integration

BoltFFI separates `generate` (source only) from `pack` (build, generate, and
platform packaging), which permits either adoption of its layouts or reuse of
WalletKit's existing package assembly
([Packaging](https://github.com/boltffi/boltffi/blob/8f862c8dd35ec9d8437ac0212c001baf0d700dd2/docs/src/content/docs/packaging.mdx#L9-L23)).

Integration in this draft:

- Swift uses `boltffi generate swift` inside the existing `cargo xtask` flow
  to preserve WalletKit's XCFramework/SwiftPM artifact layout;
- Android uses `boltffi pack android`, which links the generated JNI glue and
  emits the four configured ABI directories;
- `[targets.apple.swift] module_name = "WalletKit"` and the Android package,
  API style, and factory style are pinned in `boltffi.toml`;
- JNA has been removed from the Android modules because BoltFFI's output is
  JNI-based and includes `jniLibs` plus generated Kotlin/JNI glue
  ([Android packaging](https://github.com/boltffi/boltffi/blob/8f862c8dd35ec9d8437ac0212c001baf0d700dd2/docs/src/content/docs/packaging.mdx#L329-L359));
- preserve the existing Swift wrapper/support sources and SwiftPM product name
  while replacing only the generated source and binary internals. BoltFFI's
  full Apple packager otherwise creates its own XCFramework and SwiftPM layout
  ([Apple packaging](https://github.com/boltffi/boltffi/blob/8f862c8dd35ec9d8437ac0212c001baf0d700dd2/docs/src/content/docs/packaging.mdx#L203-L239)).

The tracked `boltffi.toml` now configures Apple, Android, and the experimental
WASM target with deterministic names and output directories.

The generated Kotlin source compiles in the Android module. The JVM-only
Kotlin test task still needs a host `libwalletkit_jni` link step; copying the
Rust cdylib alone does not include BoltFFI's generated JNI glue. Android
packaging is wired through the packager, but neither its AAR nor the Swift
package has yet been compiled end to end in this draft.

Tool/runtime requirements:

- `boltffi_cli` must be pinned to exactly the Rust `boltffi` crate version;
- Apple builds still require Xcode and installed Rust iOS targets;
- Android builds require the NDK and Rust Android targets;
- Kotlin generated async support needs `kotlinx-coroutines`; JNA is no longer
  the native call runtime;
- CI must run generator drift checks or compile freshly generated bindings,
  rather than accepting source generation as sufficient validation.

## Browser/WASM status

The browser target must not be presented as parity with the native migration.
The existing experiment proves synchronous WASM records, classes, callbacks,
packaging, and Node loading. It does not expose the async Authenticator and
proof/network surface.

There are two exact 0.30.1 blockers:

1. the future runtime requires `Send + 'static`, but browser Reqwest/Alloy
   futures are `!Send`;
2. BoltFFI's TypeScript runtime installs throwing placeholders for
   `wasm-bindgen` import modules, so WalletKit's secure
   `getRandomValues` path traps unless the runtime forwards the required Web
   Crypto imports
   ([runtime source](https://github.com/boltffi/boltffi/blob/8f862c8dd35ec9d8437ac0212c001baf0d700dd2/runtime/typescript/src/module.ts#L1691-L1726)).

Do not add insecure randomness. Browser parity requires upstream local-future
support plus a secure runtime import bridge, or a separate WalletKit-owned
WASM facade.

## Required acceptance matrix

Before calling the replacement complete:

| Area | Required evidence |
| --- | --- |
| Scanner | BoltFFI check/generation succeeds with no skipped public APIs except explicitly documented target exclusions. |
| Rust | `cargo check`, tests, Clippy, and frozen storage-format tests pass. |
| Swift API | Generated package compiles; constructors, enums, records, errors, callbacks, and an async network operation are invoked from XCTest. |
| Kotlin API | Generated Android/JVM sources compile; the same categories are invoked from JUnit, including all intended build variants. |
| Callbacks | Foreign keystore/blob store, logger, vault listener, and artifact provider behavior is covered, including callback errors and retention. |
| Packaging | XCFramework slices and four Android ABIs are present; SwiftPM and AAR/Maven consumers load the native library. |
| Compatibility | A checked-in migration table shows old UniFFI and new BoltFFI call sites for every public constructor/factory, renamed enum/error, and custom type. |
| Release | Existing Swift/Kotlin release workflow produces artifacts and minimal downstream consumers compile them. |

Current validation on this branch:

- strict Swift and Kotlin generation succeeds with
  `compress-zkeys,embed-zkeys,v3` and `--deny-skipped`;
- the generated Kotlin source compiles with Gradle after selecting companion
  factories;
- `walletkit-core` and `walletkit` compile with those exact release features;
- `xtask` compiles and its Android toolchain test passes;
- formatting, diff checks, and Nix flake evaluation pass;
- Swift generated-source compilation fails on the seven async factories with
  `extra argument in call`, matching the future-handle rendering defect above;
- AAR/XCFramework package builds, JNI host tests, callback runtime tests, and
  real network async tests remain open release gates.

## Suggested PR description summary

The draft PR should state that BoltFFI changes the generated source API even
where the Rust API is unchanged: the Kotlin package, factory placement,
exception types, Swift/Kotlin generated ownership wrappers, and `Uint256`
representation all require downstream attention. It should distinguish source
generation from runtime validation and explicitly list the Swift async-factory
bug, native Tokio executor work, host JNI test link, and browser limitations
until they are resolved.
