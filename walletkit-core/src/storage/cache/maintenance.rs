//! Cache DB maintenance helpers (integrity checks, rebuilds).

use std::fs;
use std::path::Path;

use rusqlite::Connection;

use crate::storage::error::StorageResult;
use crate::storage::sqlcipher;

use super::schema;
use super::util::{map_io_err, map_sqlcipher_err};

pub(super) fn open_or_rebuild(
    path: &Path,
    k_intermediate: [u8; 32],
) -> StorageResult<Connection> {
    match open_prepared(path, k_intermediate) {
        Ok(conn) => {
            let integrity_ok =
                sqlcipher::integrity_check(&conn).map_err(map_sqlcipher_err)?;
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

fn open_prepared(path: &Path, k_intermediate: [u8; 32]) -> StorageResult<Connection> {
    let conn =
        sqlcipher::open_connection(path, false).map_err(map_sqlcipher_err)?;
    sqlcipher::apply_key(&conn, k_intermediate).map_err(map_sqlcipher_err)?;
    sqlcipher::configure_connection(&conn).map_err(map_sqlcipher_err)?;
    schema::ensure_schema(&conn)?;
    Ok(conn)
}

fn rebuild(path: &Path, k_intermediate: [u8; 32]) -> StorageResult<Connection> {
    delete_cache_files(path)?;
    open_prepared(path, k_intermediate)
}

fn delete_cache_files(path: &Path) -> StorageResult<()> {
    delete_if_exists(path)?;
    delete_if_exists(&path.with_extension("sqlite-wal"))?;
    delete_if_exists(&path.with_extension("sqlite-shm"))?;
    Ok(())
}

fn delete_if_exists(path: &Path) -> StorageResult<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(map_io_err(&err)),
    }
}
