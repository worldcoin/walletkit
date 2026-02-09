//! Cache DB maintenance helpers (integrity checks, rebuilds).

use std::fs;
use std::path::Path;

use crate::storage::db::cipher;
use crate::storage::db::Connection;
use crate::storage::error::StorageResult;

use super::schema;
use super::util::{map_db_err_owned, map_io_err};

/// Opens the cache DB or rebuilds it if integrity checks fail.
///
/// # Errors
///
/// Returns an error if the database cannot be opened or rebuilt.
pub(super) fn open_or_rebuild(
    path: &Path,
    k_intermediate: [u8; 32],
) -> StorageResult<Connection> {
    match open_prepared(path, k_intermediate) {
        Ok(conn) => {
            let integrity_ok = cipher::integrity_check(&conn).map_err(|e| map_db_err_owned(&e))?;
            if integrity_ok {
                Ok(conn)
            } else {
                drop(conn);
                rebuild(path, k_intermediate)
            }
        }
        Err(err) => rebuild(path, k_intermediate).map_or_else(|_| Err(err), Ok),
    }
}

/// Opens the cache DB, applies encryption settings, and ensures schema.
///
/// # Errors
///
/// Returns an error if the DB cannot be opened or configured.
fn open_prepared(path: &Path, k_intermediate: [u8; 32]) -> StorageResult<Connection> {
    let conn =
        cipher::open_encrypted(path, k_intermediate, false).map_err(|e| map_db_err_owned(&e))?;
    schema::ensure_schema(&conn)?;
    Ok(conn)
}

/// Rebuilds the cache database by deleting and recreating it.
///
/// # Errors
///
/// Returns an error if deletion or re-open fails.
fn rebuild(path: &Path, k_intermediate: [u8; 32]) -> StorageResult<Connection> {
    delete_cache_files(path)?;
    open_prepared(path, k_intermediate)
}

/// Deletes the cache DB and its WAL/SHM sidecar files if present.
///
/// # Errors
///
/// Returns an error for IO failures other than missing files.
fn delete_cache_files(path: &Path) -> StorageResult<()> {
    delete_if_exists(path)?;
    delete_if_exists(&path.with_extension("sqlite-wal"))?;
    delete_if_exists(&path.with_extension("sqlite-shm"))?;
    Ok(())
}

/// Deletes the file at `path` if it exists.
///
/// # Errors
///
/// Returns an error for IO failures other than missing files.
fn delete_if_exists(path: &Path) -> StorageResult<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(map_io_err(&err)),
    }
}
