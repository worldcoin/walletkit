//! Persistent storage backends for WASM builds.
//!
//! By default, `sqlite-wasm-rs` uses an in-memory VFS that loses all data on
//! page reload. This module provides two persistent alternatives:
//!
//! * **OPFS** (`sahpool`) — uses the Origin Private File System via
//!   `FileSystemSyncAccessHandle`. Requires a **Dedicated Worker** context.
//!   Offers full durability.
//!
//! * **IndexedDB** (`relaxed-idb`) — stores database blocks in IndexedDB.
//!   Works in **any** browsing context (main thread, worker, etc.).
//!   Provides relaxed durability (data is flushed asynchronously).
//!
//! # Usage
//!
//! Call one of the `install_*` functions **once** before opening any database
//! connection. The chosen VFS will be registered as the default so that
//! [`Connection::open`](crate::Connection::open) uses it transparently.
//!
//! ```rust,ignore
//! use std::path::Path;
//! use walletkit_db::Connection;
//!
//! // In a Dedicated Worker — OPFS-backed (full durability):
//! walletkit_db::wasm_storage::install_opfs_sahpool(None).await?;
//!
//! // — or — in any context — IndexedDB-backed (relaxed durability):
//! walletkit_db::wasm_storage::install_relaxed_idb(None).await?;
//!
//! // Then open databases as usual — they will be persisted.
//! let conn = Connection::open(Path::new("app.db"), false)?;
//! ```

pub use sqlite_wasm_vfs::sahpool::{
    install as install_sahpool_inner, OpfsSAHPoolCfg, OpfsSAHError,
};
pub use sqlite_wasm_vfs::relaxed_idb::{
    install as install_idb_inner, RelaxedIdbCfg, RelaxedIdbError,
};

/// Errors that can occur during persistent VFS installation.
#[derive(Debug)]
pub enum WasmStorageError {
    /// OPFS sahpool VFS installation failed.
    Opfs(OpfsSAHError),
    /// IndexedDB relaxed-idb VFS installation failed.
    Idb(RelaxedIdbError),
}

impl std::fmt::Display for WasmStorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Opfs(e) => write!(f, "OPFS sahpool VFS install failed: {e}"),
            Self::Idb(e) => write!(f, "IndexedDB relaxed-idb VFS install failed: {e}"),
        }
    }
}

impl std::error::Error for WasmStorageError {}

impl From<OpfsSAHError> for WasmStorageError {
    fn from(e: OpfsSAHError) -> Self {
        Self::Opfs(e)
    }
}

impl From<RelaxedIdbError> for WasmStorageError {
    fn from(e: RelaxedIdbError) -> Self {
        Self::Idb(e)
    }
}

/// Install the **OPFS `sahpool`** VFS as the default SQLite VFS.
///
/// This must be called **once** from a **Dedicated Worker** context before
/// opening any database. If `cfg` is `None`, sensible defaults are used.
///
/// After this call, all databases opened via [`Connection::open`](crate::Connection::open)
/// will be persisted to the Origin Private File System.
///
/// # Errors
///
/// Returns [`WasmStorageError::Opfs`] if VFS registration fails (e.g. called
/// outside a Dedicated Worker, or OPFS is not available).
pub async fn install_opfs_sahpool(
    cfg: Option<OpfsSAHPoolCfg>,
) -> Result<(), WasmStorageError> {
    let cfg = cfg.unwrap_or_default();
    install_sahpool_inner::<sqlite_wasm_rs::WasmOsCallback>(&cfg, true).await?;
    Ok(())
}

/// Install the **IndexedDB `relaxed-idb`** VFS as the default SQLite VFS.
///
/// This must be called **once** before opening any database. Works in any
/// browsing context (main thread, worker, etc.). If `cfg` is `None`, sensible
/// defaults are used.
///
/// After this call, all databases opened via [`Connection::open`](crate::Connection::open)
/// will be persisted to IndexedDB with relaxed durability guarantees.
///
/// # Errors
///
/// Returns [`WasmStorageError::Idb`] if VFS registration fails.
pub async fn install_relaxed_idb(
    cfg: Option<RelaxedIdbCfg>,
) -> Result<(), WasmStorageError> {
    let cfg = cfg.unwrap_or_default();
    install_idb_inner::<sqlite_wasm_rs::WasmOsCallback>(&cfg, true).await?;
    Ok(())
}

