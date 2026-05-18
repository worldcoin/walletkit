//! Encrypted vault: opens an encrypted database with a caller-supplied
//! schema and exposes read / mutate handles.
//!
//! The vault owns its own [`Lock`] so the type system can enforce "no
//! mutation without holding the lock." Reads bypass the lock — `sqlite3mc`
//! is opened in WAL mode and `SQLite`'s own reader/writer serialization
//! handles concurrent readers.
//!
//! The lock is acquired around three things:
//!
//! - the open sequence (open + key + `ensure_schema` + integrity check),
//!   preventing two processes from racing on first-install envelope init,
//! - every closure passed to [`Vault::mutate`], serializing multi-statement
//!   mutations across processes,
//! - implicitly nothing else: callers can read freely via [`Vault::read`].

use std::path::Path;

use secrecy::SecretBox;

use crate::error::{StoreError, StoreResult};
use crate::lock::Lock;
use crate::sqlite::{cipher, Connection, DbResult};

/// Open encrypted database paired with the lock that serializes its
/// mutations.
///
/// Read access via [`Vault::read`]; mutations via [`Vault::mutate`].
#[derive(Debug)]
pub struct Vault {
    conn: Connection,
    lock: Lock,
}

impl Vault {
    /// Opens (or creates) the encrypted database at `db_path`, holding
    /// `lock` for the duration of the open + key + schema + integrity-check
    /// sequence. The lock is released before this returns; subsequent
    /// mutations re-acquire it via [`Vault::mutate`].
    ///
    /// `ensure_schema` runs after the database is opened and keyed but
    /// before the integrity check.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Db`] if open / key / schema fails,
    /// [`StoreError::IntegrityCheckFailed`] on corruption, or
    /// [`StoreError::Lock`] if the lock cannot be acquired.
    pub fn open<F>(
        db_path: &Path,
        key: &SecretBox<[u8; 32]>,
        lock: Lock,
        ensure_schema: F,
    ) -> StoreResult<Self>
    where
        F: FnOnce(&Connection) -> DbResult<()>,
    {
        let guard = lock.lock()?;
        let conn = cipher::open_encrypted(db_path, key, false)?;
        ensure_schema(&conn)?;
        if !cipher::integrity_check(&conn)? {
            return Err(StoreError::IntegrityCheckFailed(
                "integrity_check failed".to_string(),
            ));
        }
        drop(guard);
        Ok(Self { conn, lock })
    }

    /// Borrows the underlying connection for read-only SQL. `SQLite` handles
    /// concurrent readers in WAL mode; no lock is acquired.
    ///
    /// Do not mutate via this handle. Mutations belong inside
    /// [`Vault::mutate`].
    #[must_use]
    pub const fn read(&self) -> &Connection {
        &self.conn
    }

    /// Runs `f` under a freshly-acquired lock guard. The guard is held for
    /// the entire closure (any number of SQL transactions) and released on
    /// return.
    ///
    /// The closure's error type must convert from [`StoreError`] so the
    /// lock-acquisition failure flows through. Most consumers use the
    /// crate's [`StoreResult`] directly.
    ///
    /// # Errors
    ///
    /// Propagates the closure's error, plus [`StoreError::Lock`] if the
    /// lock cannot be acquired.
    pub fn mutate<R, E, F>(&self, f: F) -> Result<R, E>
    where
        F: FnOnce(&Connection) -> Result<R, E>,
        E: From<StoreError>,
    {
        let _guard = self.lock.lock().map_err(E::from)?;
        f(&self.conn)
    }
}
