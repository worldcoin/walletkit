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

## Encryption format compatibility

WalletKit leaves the first 32 bytes of every encrypted database header in
plaintext on all targets. The visible header contains SQLite format metadata;
database pages and application data remain encrypted with the supplied
WalletKit key.

On the first successful read-write open, WalletKit migrates databases created
with the earlier fully encrypted header format to the plaintext-header format.
It also preserves and encrypts records if a host previously caused WalletKit to
create a plaintext database. Migration checkpoints any existing WAL, switches
temporarily to a rollback journal because sqlite3mc cannot rekey in WAL mode,
and restores the target's normal journal policy afterward.

This format migration is forward-only. WalletKit versions that predate the
32-byte plaintext header cannot open a newly created or migrated database. To
support application rollback, preserve a compatible database backup before
upgrading.
