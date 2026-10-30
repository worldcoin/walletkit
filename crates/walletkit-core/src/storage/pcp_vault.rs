//! Host-facing storage for sealed PCPs.

use std::sync::Arc;

use super::{CredentialStore, PcpMetadata, PcpRecord, StorageResult};

#[uniffi::export]
impl CredentialStore {
    /// Returns a handle to this store's sealed PCPs.
    #[must_use]
    pub fn pcp_vault(self: Arc<Self>) -> Arc<PcpVault> {
        Arc::new(PcpVault { store: self })
    }
}

/// Sealed PCP storage in the account vault.
///
/// Ids and kinds are opaque to `WalletKit`; hosts own id normalization and
/// typically use the backup designator (such as `orb_pkg`) as the kind. PCPs are
/// excluded from credential backups and do not notify the vault-changed listener.
///
/// Operations require [`CredentialStore::init`] with the account's leaf index.
/// [`CredentialStore::destroy_storage`] permanently removes PCPs.
#[derive(Debug, uniffi::Object)]
pub struct PcpVault {
    store: Arc<CredentialStore>,
}

#[uniffi::export]
impl PcpVault {
    /// Stores sealed PCP bytes under the host's exact id. Replaces an existing
    /// entry only when `kind` matches, preserving its creation time.
    ///
    /// # Errors
    /// Returns an error if storage is uninitialized, `id` contains a NUL
    /// character, `kind` is invalid or conflicts with an existing entry, `now` is
    /// out of range, or the database write fails.
    pub fn put(
        &self,
        id: &str,
        kind: &str,
        data: &[u8],
        now: u64,
    ) -> StorageResult<()> {
        self.store
            .with_vault(|vault| vault.pcps().put(id, kind, data, now))
    }

    /// Retrieves a PCP. Returns `None` if absent.
    ///
    /// # Errors
    /// Returns an error if storage is uninitialized or the database read fails.
    /// Errors never include the id.
    pub fn get(&self, id: &str) -> StorageResult<Option<PcpRecord>> {
        self.store.with_vault(|vault| vault.pcps().get(id))
    }

    /// Lists PCP metadata in id order, optionally restricted to one kind.
    /// Does not load package data; use [`Self::get`] to read it.
    ///
    /// # Errors
    /// Returns an error if storage is uninitialized, stored metadata is corrupt,
    /// or the database query fails.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "UniFFI passes optional strings by value"
    )]
    pub fn list(&self, kind: Option<String>) -> StorageResult<Vec<PcpMetadata>> {
        self.store
            .with_vault(|vault| vault.pcps().list(kind.as_deref()))
    }

    /// Deletes a PCP, returning whether it existed.
    ///
    /// # Errors
    /// Returns an error if storage is uninitialized or the database write fails.
    pub fn delete(&self, id: &str) -> StorageResult<bool> {
        self.store.with_vault(|vault| vault.pcps().delete(id))
    }
}
