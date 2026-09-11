# walletkit-sqlite

Low-level encrypted SQLite support for WalletKit.

The crate provides safe Rust wrappers for connections, statements,
transactions, values, and sqlite3mc cipher operations. On native targets it
builds and statically links sqlite3mc; on WASM it delegates to
`sqlite-wasm-rs` and stores encrypted database pages in OPFS through the
SAH-pool VFS.

Browser hosts must run WalletKit in a dedicated worker and await
`walletkit_core::storage::initialize_persistent_storage()` before initializing
the credential store. The page key remains in Rust memory for the unlocked
store lifetime; persistent connections fail closed until the encrypted OPFS
VFS is installed.

## Native SQLite isolation

Native apps may also link system SQLite or another SQLite distribution. The
bundled sqlite3mc API has internal C linkage, and Rust uses only the
`walletkit_sqlite3_*` wrappers in `src/native_sqlite.c`. This prevents link
order from substituting the host engine for WalletKit's encrypted engine or
replacing the host engine with WalletKit's copy. New native FFI functions must
add a matching prefixed wrapper; visibility attributes alone do not isolate
symbols when linking static archives.

The amalgamation, cipher configuration, key encoding, and encrypted on-disk
format are unchanged. Cipher validation remains enabled. If a host previously
caused WalletKit to create a plaintext database, opening it read-write now
preserves its records and encrypts it in place with the supplied WalletKit key.
The migration checkpoints a plaintext WAL and switches to a rollback journal
because sqlite3mc cannot rekey in WAL mode; normal WAL policy is restored after
encryption. A read-only open fails without modifying plaintext data.

On macOS, run the link-order regressions with synthetic disposable data:

```sh
bash crates/walletkit-sqlite/examples/test_native_linking.sh
bash crates/walletkit-sqlite/examples/test_native_linking.sh release
```

Run both profiles when changing native linkage. The tests check the static
archive for unprefixed SQLite API symbols, link with Apple's SQLite in both library orders
with dead stripping enabled, and verify that both engines remain independent.
They also cover encrypted reopening, wrong-key rejection, plaintext-WAL
migration, and record preservation. These probes do not replace upgrade/
downgrade and end-to-end account-flow testing before an SDK rollout.
