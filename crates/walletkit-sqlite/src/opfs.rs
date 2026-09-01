//! Persistent browser storage backed by the OPFS SAH-pool VFS.
//!
//! Installation is asynchronous and must complete in a dedicated Web Worker
//! before opening an encrypted database. Database connections themselves stay
//! synchronous after the VFS has acquired its OPFS sync access handles.

use std::cell::RefCell;
use std::path::Path;

use sqlite_wasm_vfs::sahpool::{
    install as install_sahpool, OpfsSAHPoolCfgBuilder, OpfsSAHPoolUtil,
};

use crate::{error::DbResult, Error};

const OPFS_VFS_NAME: &str = "opfs-sahpool";
const OPFS_DIRECTORY: &str = ".walletkit-opfs-sahpool";
const OPFS_MINIMUM_CAPACITY: u32 = 6;

/// `SQLite3MC`'s encrypted wrapper around the SAH-pool VFS.
pub(crate) const ENCRYPTED_VFS_NAME: &str = "multipleciphers-opfs-sahpool";

thread_local! {
    static OPFS_POOL: RefCell<Option<OpfsSAHPoolUtil>> = const { RefCell::new(None) };
}

/// Installs `WalletKit`'s persistent OPFS VFS in the current dedicated worker.
///
/// This function is idempotent within a worker. The raw OPFS VFS is
/// deliberately not made `SQLite`'s default: encrypted connections explicitly
/// open through [`ENCRYPTED_VFS_NAME`] so persistence can never silently bypass
/// `SQLite3MC`.
///
/// # Errors
///
/// Returns an error when called outside a supported dedicated worker, when the
/// pool is already locked by another browsing context, or when OPFS setup
/// fails.
#[expect(
    clippy::future_not_send,
    reason = "OPFS and its JavaScript handles are dedicated-worker local"
)]
pub async fn install() -> DbResult<()> {
    if is_installed() {
        return Ok(());
    }

    let options = OpfsSAHPoolCfgBuilder::new()
        .vfs_name(OPFS_VFS_NAME)
        .directory(OPFS_DIRECTORY)
        .clear_on_init(false)
        .initial_capacity(OPFS_MINIMUM_CAPACITY)
        .build();
    let pool = install_sahpool::<sqlite_wasm_rs::WasmOsCallback>(&options, false)
        .await
        .map_err(|err| {
            Error::new(-1, format!("failed to install OPFS SAH-pool VFS: {err}"))
        })?;
    pool.reserve_minimum_capacity(OPFS_MINIMUM_CAPACITY)
        .await
        .map_err(|err| {
            Error::new(
                -1,
                format!("failed to reserve OPFS SAH-pool capacity: {err}"),
            )
        })?;

    OPFS_POOL.with(|slot| {
        *slot.borrow_mut() = Some(pool);
    });
    Ok(())
}

/// Returns whether the persistent VFS was installed in this worker.
#[must_use]
pub fn is_installed() -> bool {
    OPFS_POOL.with(|slot| slot.borrow().is_some())
}

/// Deletes a closed database and any persistent journal sidecars from OPFS.
///
/// # Errors
///
/// Returns an error if the VFS has not been installed or OPFS deletion fails.
pub fn delete_database_files(path: &Path) -> DbResult<()> {
    let filenames = [
        path.to_path_buf(),
        path.with_extension("sqlite-journal"),
        path.with_extension("sqlite-wal"),
        path.with_extension("sqlite-shm"),
    ];
    OPFS_POOL.with(|slot| {
        let pool = slot.borrow();
        let pool = pool
            .as_ref()
            .ok_or_else(|| Error::new(-1, "OPFS SAH-pool VFS is not installed"))?;
        for filename in filenames {
            let filename = filename.to_string_lossy();
            pool.delete_db(&filename).map_err(|err| {
                Error::new(
                    -1,
                    format!("failed to delete OPFS database file {filename}: {err}"),
                )
            })?;
        }
        Ok(())
    })
}

#[cfg(test)]
fn export_database(path: &Path) -> DbResult<Vec<u8>> {
    OPFS_POOL.with(|slot| {
        let pool = slot.borrow();
        let pool = pool
            .as_ref()
            .ok_or_else(|| Error::new(-1, "OPFS SAH-pool VFS is not installed"))?;
        let filename = path.to_string_lossy();
        pool.export_db(&filename).map_err(|err| {
            Error::new(
                -1,
                format!("failed to export OPFS database file {filename}: {err}"),
            )
        })
    })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use secrecy::SecretBox;
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::{delete_database_files, export_database, install, ENCRYPTED_VFS_NAME};
    use crate::cipher::open_encrypted;

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_dedicated_worker);

    #[wasm_bindgen_test]
    fn encrypted_vfs_name_wraps_sahpool() {
        assert_eq!(ENCRYPTED_VFS_NAME, "multipleciphers-opfs-sahpool");
    }

    #[wasm_bindgen_test]
    #[expect(
        clippy::future_not_send,
        reason = "OPFS and its JavaScript handles are dedicated-worker local"
    )]
    async fn encrypted_database_persists_without_plaintext_at_rest() {
        const DATABASE_PATH: &str = "walletkit-encrypted-opfs-test.sqlite";
        const SECRET: &str = "walletkit-opfs-secret-marker";

        install().await.expect("install persistent VFS");
        let path = Path::new(DATABASE_PATH);
        delete_database_files(path).expect("remove stale test database");

        let key = SecretBox::init_with(|| [0xAB; 32]);
        {
            let conn = open_encrypted(path, &key, false).expect("create database");
            conn.execute_batch(
                "CREATE TABLE secrets (value TEXT NOT NULL);\
                 INSERT INTO secrets (value) VALUES ('walletkit-opfs-secret-marker');",
            )
            .expect("write secret");
        }

        let stored = export_database(path).expect("export encrypted bytes");
        assert!(!stored.starts_with(b"SQLite format 3\0"));
        assert!(!stored
            .windows(SECRET.len())
            .any(|window| window == SECRET.as_bytes()));

        {
            let conn = open_encrypted(path, &key, false).expect("reopen database");
            let value = conn
                .query_row("SELECT value FROM secrets", &[], |row| {
                    Ok(row.column_text(0))
                })
                .expect("read secret");
            assert_eq!(value, SECRET);
        }

        let wrong_key = SecretBox::init_with(|| [0xCD; 32]);
        assert!(open_encrypted(path, &wrong_key, false).is_err());

        delete_database_files(path).expect("delete test database");
    }
}
