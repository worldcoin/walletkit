//! Platform interfaces for credential storage.
//!
//! ## Key structure
//!
//! - `K_device`: device-bound root key managed by `DeviceKeystore`.
//! - `account_keys.bin`: account key envelope stored via `AtomicBlobStore` and
//!   containing `DeviceKeystore::seal` of `K_intermediate` with associated data
//!   `worldid:account-key-envelope`.
//! - `K_intermediate`: 32-byte per-account key unsealed at init and kept in
//!   memory for the lifetime of the storage handle.
//! - `SQLCipher` databases: `account.vault.sqlite` (authoritative) and
//!   `account.cache.sqlite` (non-authoritative) are opened with `K_intermediate`.
//! - Derived keys: per relying-party session keys may be derived from
//!   `K_intermediate` and cached in `account.cache.sqlite` for performance.
//!   cached in `account.cache.sqlite` for performance.

use std::sync::Arc;

use walletkit_secure_store::{
    AtomicBlobStore as SecureAtomicBlobStore, Keystore as SecureKeystore,
    StoreError, StoreResult,
};

use super::error::StorageResult;
use super::paths::StoragePaths;

/// Device keystore interface used to seal and open account keys.
#[uniffi::export(with_foreign)]
pub trait DeviceKeystore: Send + Sync {
    /// Seals plaintext under the device-bound key, authenticating `associated_data`.
    ///
    /// The associated data is not encrypted, but it is integrity-protected as part
    /// of the seal operation. Any mismatch when opening must fail.
    ///
    /// # Errors
    ///
    /// Returns an error if the keystore refuses the operation or the seal fails.
    fn seal(
        &self,
        associated_data: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> StorageResult<Vec<u8>>;

    /// Opens ciphertext under the device-bound key, verifying `associated_data`.
    ///
    /// The same associated data used during sealing must be supplied or the open
    /// operation must fail.
    ///
    /// # Errors
    ///
    /// Returns an error if authentication fails or the keystore cannot open.
    fn open_sealed(
        &self,
        associated_data: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> StorageResult<Vec<u8>>;
}

/// Atomic blob store for small binary files (e.g., `account_keys.bin`).
#[uniffi::export(with_foreign)]
pub trait AtomicBlobStore: Send + Sync {
    /// Reads the blob at `path`, if present.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    fn read(&self, path: String) -> StorageResult<Option<Vec<u8>>>;

    /// Writes bytes atomically to `path`.
    ///
    /// # Errors
    ///
    /// Returns an error if the write fails.
    fn write_atomic(&self, path: String, bytes: Vec<u8>) -> StorageResult<()>;

    /// Deletes the blob at `path`.
    ///
    /// # Errors
    ///
    /// Returns an error if the delete fails.
    fn delete(&self, path: String) -> StorageResult<()>;
}

/// Provider responsible for platform-specific storage components and paths.
#[uniffi::export(with_foreign)]
pub trait StorageProvider: Send + Sync {
    /// Returns the device keystore implementation.
    fn keystore(&self) -> Arc<dyn DeviceKeystore>;

    /// Returns the blob store implementation.
    fn blob_store(&self) -> Arc<dyn AtomicBlobStore>;

    /// Returns the storage paths selected by the platform.
    fn paths(&self) -> Arc<StoragePaths>;
}

/// Adapter that lets a [`DeviceKeystore`] satisfy the
/// [`walletkit_secure_store::Keystore`](SecureKeystore) trait.
///
/// `walletkit-secure-store` is a plain-Rust crate with no FFI awareness; the
/// adapter bridges its trait surface to the `uniffi`-annotated traits exposed
/// here. Errors are converted via the `String` payload — variant identity is
/// preserved by `walletkit-core`'s [`From<StoreError> for
/// StorageError`](super::error::StorageError).
pub(crate) struct DeviceKeystoreAdapter<'a> {
    inner: &'a dyn DeviceKeystore,
}

impl<'a> DeviceKeystoreAdapter<'a> {
    pub(crate) const fn new(inner: &'a dyn DeviceKeystore) -> Self {
        Self { inner }
    }
}

impl SecureKeystore for DeviceKeystoreAdapter<'_> {
    fn seal(
        &self,
        associated_data: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> StoreResult<Vec<u8>> {
        self.inner
            .seal(associated_data, plaintext)
            .map_err(|err| StoreError::Keystore(err.to_string()))
    }

    fn open_sealed(
        &self,
        associated_data: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> StoreResult<Vec<u8>> {
        self.inner
            .open_sealed(associated_data, ciphertext)
            .map_err(|err| StoreError::Keystore(err.to_string()))
    }
}

/// Adapter that lets an [`AtomicBlobStore`] satisfy the
/// [`walletkit_secure_store::AtomicBlobStore`](SecureAtomicBlobStore) trait.
pub(crate) struct AtomicBlobStoreAdapter<'a> {
    inner: &'a dyn AtomicBlobStore,
}

impl<'a> AtomicBlobStoreAdapter<'a> {
    pub(crate) const fn new(inner: &'a dyn AtomicBlobStore) -> Self {
        Self { inner }
    }
}

impl SecureAtomicBlobStore for AtomicBlobStoreAdapter<'_> {
    fn read(&self, path: String) -> StoreResult<Option<Vec<u8>>> {
        self.inner
            .read(path)
            .map_err(|err| StoreError::BlobStore(err.to_string()))
    }

    fn write_atomic(&self, path: String, bytes: Vec<u8>) -> StoreResult<()> {
        self.inner
            .write_atomic(path, bytes)
            .map_err(|err| StoreError::BlobStore(err.to_string()))
    }

    fn delete(&self, path: String) -> StoreResult<()> {
        self.inner
            .delete(path)
            .map_err(|err| StoreError::BlobStore(err.to_string()))
    }
}

/// Listener notified when the credential vault contents change and a new
/// backup is needed.
///
/// Register via [`super::CredentialStore::set_vault_changed_listener`]. The
/// callback is delivered on a dedicated background thread to avoid re-entering
/// the `UniFFI` call stack (see `logger.rs` for rationale).
///
/// This is only called when individual credentials are added or removed.
///
/// # Expected usage
///
/// The host app should treat this as a trigger to schedule a backup of the
/// vault. It should contain synchronous actions only.
///
/// # Safety
///
/// **Warning:** implementors **must not** call back into
/// [`super::CredentialStore`] from
/// [`on_vault_changed`](VaultChangedListener::on_vault_changed) — doing so
/// will deadlock.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(with_foreign))]
pub trait VaultChangedListener: Send + Sync {
    /// Called after a credential is added or removed.
    fn on_vault_changed(&self);
}
