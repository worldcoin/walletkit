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
