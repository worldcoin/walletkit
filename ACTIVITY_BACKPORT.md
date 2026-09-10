# Activity-only WalletKit candidate

This local candidate starts at `v0.21.4` (`f0e3795`) and backports only the
credential-activity changes from #481 (`555497e`) and #506 (`f7c15ee`), plus the
native SQLite isolation fix and its regression tests. Imports are adapted to
the original `walletkit-db` crate; the SQLite crate split is not required.

The Flamingo changes, WASM OPFS persistence, session-seed cache changes,
World Chain endpoint changes, and dependency updates in 0.22.0 are excluded.
`Cargo.lock` remains the 0.21.4 lockfile. This is a local development candidate,
not the published 0.21.4 artifact: assign a distinct reviewed version before
publishing any package or binary.

## Reproduced failure

The unchanged 0.22.0 SQLite crate passes its ten unit tests in isolation. A
small native host linked with Apple's `-lsqlite3` before the WalletKit static
archive reproduces the reported error exactly:

```text
WalletKit SQLite version: 3.51.0; cipher: None
vault db error: sqlite error 101: query returned no rows
```

WalletKit's unprefixed `sqlite3_*` references resolve to the host's SQLite.
The cipher validation introduced by #493 discovers that `PRAGMA cipher`
returns no row. This happens before vault schema/leaf-index initialization.
The vault schema itself did not change between 0.21.4 and 0.22.0.

Removing that check in the same disposable reproducer makes initialization
succeed, but creates a plaintext SQLite database and accepts the wrong key.
Therefore removing the check, or backporting activity alone, is insufficient.
These experiments use synthetic keys and records only; no real wallet stores
were inspected or modified.

## Fix

Compile the original, checksum-verified sqlite3mc amalgamation inside
`crates/walletkit-db/src/native_sqlite.c`, with its SQLite API given internal
C linkage. Expose only the 21 WalletKit-prefixed wrappers needed by Rust's
native FFI. Both allocations and operations on every SQLite handle remain
within the same engine, independent of the app's link order.

The original SQLite version, compile settings, ChaCha20 cipher, key encoding,
vault/envelope formats, and content IDs are preserved. A cipher check fails
closed with a diagnostic if the required engine is unavailable. The activity
table and behavior are those of the two backported upstream PRs.

## Validation

Run with the Rust and Nargo versions pinned by the repository:

```sh
cargo test -p walletkit-core --lib storage:: --locked
cargo test -p walletkit-db --locked
cargo clippy -p walletkit-db --all-targets --locked -- -D warnings
bash crates/walletkit-db/examples/test_native_linking.sh
bash crates/walletkit-db/examples/test_native_linking.sh release
```

The native host tests both library orders with dead stripping enabled. They
check that the host retains its own SQLite engine, encrypted records survive
reopening, wrong keys fail, failed opens preserve existing file bytes, and
plaintext stores are not silently accepted. The archive is also checked for
unprefixed SQLite API symbols. Both profiles are wired into the existing
macOS Swift CI job.

Local results on 2026-09-10:

- All 64 core storage tests and all 20 database tests pass.
- Clippy, Rust formatting, and ShellCheck pass.
- Native debug and optimized release regressions pass in both link orders.
- The optimized Swift package builds for iOS device, ARM simulator, and Intel
  simulator with the normal `compress-zkeys,embed-zkeys,v3` features.
- A native host using the actual ARM simulator release archive passes the
  cipher-isolation check in both link orders on the iPhone 17 / iOS 26.5
  simulator. This probe uses only in-memory databases.
- `timeout 600 make build-id` succeeds in `world-app-ios` with the local
  package temporarily selected. Required SwiftLint autofix/check passes with
  zero violations. The published dependency pin and lockfile are restored
  afterward.

This validates compilation and native database linkage, not an end-to-end
IDKit verification on a real account. No device account data was accessed.

Build the local Swift package with `cargo xtask swift local`. Its output is
`swift/local_build/walletkit-swift`; the iOS dependency can point to that
package for testing without publishing a release.

## Review and rollout constraints

GUARD-01, GUARD-02, and GUARD-06 require explicit human review of this
cryptographic storage/dependency change before release. No cipher check is
disabled, and no vault deletion, identity reset, or automatic storage migration
is introduced.

An existing database previously written through the wrong SQLite engine may
be plaintext. This candidate preserves that file and rejects it; it does not
invent a recovery or migration policy. Assess affected existing accounts and
any required data-preserving migration before distribution. Validate real
IDKit initialization/proof flows and credential activity in both app targets,
including existing encrypted stores, before a narrow internal rollout.

The SDK binary is shared: an activity/UI feature flag does not undo this
dependency change. Keep the prior SDK artifact available for rollback, and
confirm old/new versions retain data on upgrade and downgrade. Publishing,
tagging, and shipping this candidate are outside the local experiment.
