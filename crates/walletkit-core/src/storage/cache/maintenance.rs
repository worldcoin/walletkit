//! Cache DB maintenance helpers (open with rebuild-on-corruption).

use std::path::Path;

use secrecy::SecretBox;
use walletkit_db::Vault;

use super::schema;

use crate::storage::delete_database_files;
use crate::storage::error::StorageResult;

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
    delete_database_files(path);
    Vault::open(path, k_intermediate, schema::ensure_schema).map_err(Into::into)
}
