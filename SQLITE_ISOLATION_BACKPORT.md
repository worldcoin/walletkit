# Native SQLite isolation for v0.21.4

This candidate starts at `v0.21.4` (`f0e3795`) and changes only the native
SQLite linkage and engine validation, with regression tests and documentation.
Credential activity history is backported separately in PR #533.

Native apps can link both WalletKit's bundled sqlite3mc and another SQLite
implementation. The original generic `sqlite3_*` symbols allow host link order
to select the wrong engine. v0.21.4 does not check cipher availability, so
successful initialization alone does not establish that encryption is active.

The fix gives the bundled SQLite API internal C linkage and exposes the 21
`walletkit_sqlite3_*` wrappers used by Rust. Every SQLite handle and allocation
stays with its creating engine. The encrypted open path verifies the ChaCha20
cipher before applying a key or initializing a schema.

The SQLite amalgamation, build settings, dependency lockfile, workspace
manifest, toolchain pins, cipher parameters, key encoding, and vault/envelope
formats remain those of v0.21.4. Future native FFI functions must add a matching
prefixed C wrapper. This isolates SQLite's API, not every third-party crypto
symbol in the amalgamation.

## Validation

On macOS with the pinned Rust toolchain, run:

```sh
cargo test -p walletkit-db --locked
cargo clippy -p walletkit-db --all-targets --locked -- -D warnings
bash crates/walletkit-db/examples/test_native_linking.sh
bash crates/walletkit-db/examples/test_native_linking.sh release
```

The probes check defined and undefined global archive symbols, link Apple's
SQLite before and after WalletKit with dead stripping enabled, and verify
independent host and WalletKit engines. They test encrypted persistence and
reopening, wrong-key rejection, and unchanged file bytes after failed
wrong-key and plaintext-store opens. All data and keys are synthetic.

Results from the earlier combined activity/SQLite candidate are not results
for this fix-only revision. The PR description records validation after the
split. These probes do not replace testing existing stores and real app flows.

The new linking tests currently run manually. GitHub rejected workflow edits
with the available push credential, so the CI workflow remains unchanged.
Before release, a maintainer with workflow-write access should add both
profiles to the macOS Swift job with a bounded step timeout.

## Before distribution

Review the native storage/encryption linkage change and test existing
encrypted-store upgrade/downgrade and real initialization/proof flows. The
low-level encrypted-open checks preserve and reject plaintext stores; recovery
policy and host-level error handling require separate review.

The source retains v0.21.4 version numbers. Assign a distinct reviewed version
before publishing, use a narrow internal rollout, and retain the prior SDK
artifact with a tested data-preserving rollback path.
