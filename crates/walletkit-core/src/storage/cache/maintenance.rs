//! Cache DB maintenance helpers (open with rebuild-on-corruption).

use std::path::Path;

use secrecy::SecretBox;
use walletkit_db::Vault;

use super::schema;

use crate::storage::error::StorageResult;
use crate::storage::StorageError;

/// Opens the cache DB through `Vault`, rebuilding on any open / key /
/// integrity failure.
///
/// Cache contents are non-authoritative and regenerable, so the policy
/// here is "blow it away and retry" rather than the credential vault's
/// fatal-on-integrity contract.
///
/// # Errors
///
/// Returns an error if the database cannot be opened or rebuilt.
pub(super) fn open_or_rebuild(
    path: &Path,
    k_intermediate: &SecretBox<[u8; 32]>,
) -> StorageResult<Vault> {
    if let Ok(vault) = Vault::open(path, k_intermediate, schema::ensure_schema) {
        return Ok(vault);
    }
    delete_cache_files(path)?;
    Vault::open(path, k_intermediate, schema::ensure_schema).map_err(Into::into)
}

/// Deletes the cache DB and its WAL/SHM sidecar files if present.
fn delete_cache_files(path: &Path) -> StorageResult<()> {
    #[cfg(target_arch = "wasm32")]
    {
        return walletkit_sqlite::opfs::delete_database_files(path)
            .map_err(|err| StorageError::CacheDb(err.to_string()));
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        delete_if_exists(path)?;
        delete_if_exists(&path.with_extension("sqlite-wal"))?;
        delete_if_exists(&path.with_extension("sqlite-shm"))?;
        Ok(())
    }
}

/// Deletes the file at `path` if it exists.
#[cfg(not(target_arch = "wasm32"))]
fn delete_if_exists(path: &Path) -> StorageResult<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(StorageError::CacheDb((&err).to_string())),
    }
}
