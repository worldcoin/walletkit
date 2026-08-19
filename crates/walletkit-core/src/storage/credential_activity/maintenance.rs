//! Corruption recovery for the credential-activity database.
//!
//! Implements a wipe-and-rebuild strategy. Losing a device-local activity log
//! has no security or correctness impact, so a corrupted file is deleted and
//! rebuilt empty rather than hard-failing the whole [`CredentialStore::init`].

use std::fs;
use std::path::Path;

use crate::storage::error::{StorageError, StorageResult};
use secrecy::SecretBox;
use walletkit_db::Vault;

use super::schema;

pub(super) fn open_or_rebuild(
    path: &Path,
    k_intermediate: &SecretBox<[u8; 32]>,
) -> StorageResult<(Vault, (i64, i64))> {
    if let Ok(result) = try_open(path, k_intermediate) {
        return Ok(result);
    }

    delete_activity_files(path)?;
    try_open(path, k_intermediate)
}

fn try_open(
    path: &Path,
    k_intermediate: &SecretBox<[u8; 32]>,
) -> StorageResult<(Vault, (i64, i64))> {
    let versions = std::cell::Cell::new((0i64, 0i64));
    let vault = Vault::open(path, k_intermediate, |conn| {
        let result = schema::perform_migrations(conn)?;
        versions.set(result);
        Ok(())
    })?;

    Ok((vault, versions.get()))
}

fn delete_activity_files(path: &Path) -> StorageResult<()> {
    delete_if_exists(path)?;
    delete_if_exists(&path.with_extension("sqlite-wal"))?;
    delete_if_exists(&path.with_extension("sqlite-shm"))?;
    Ok(())
}

fn delete_if_exists(path: &Path) -> StorageResult<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(StorageError::CredentialActivityDb(format!(
            "failed to delete {}: {e}",
            path.display()
        ))),
    }
}
