//! Platform interfaces for credential storage.
//!
//! These traits are the platform integration boundary. The host selects the storage
//! root and provides a [`DeviceKeystore`] and [`AtomicBlobStore`]; core storage code
//! is root-agnostic and consumes a provider-supplied [`StoragePaths`].
//!
//! # Expected platform components
//!
//! - **iOS (Swift):** [`DeviceKeystore`] backed by Keychain / Secure Enclave;
//!   [`AtomicBlobStore`] over the app container filesystem (atomic replace).
//! - **Android (Kotlin):** [`DeviceKeystore`] backed by the Android Keystore;
//!   [`AtomicBlobStore`] over app internal storage (atomic replace).
//! - **Node.js:** file-backed [`DeviceKeystore`] (development; production can use an
//!   OS keystore); [`AtomicBlobStore`] over app internal storage.
//! - **Browser (WASM):** `WebCrypto`-backed [`DeviceKeystore`]; [`AtomicBlobStore`]
//!   over an origin-private storage namespace.

use std::sync::Arc;

use super::error::StorageError;
use super::paths::StoragePaths;

/// Device keystore interface used to seal and open account keys.
#[boltffi::export]
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
    ) -> Result<Vec<u8>, StorageError>;

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
    ) -> Result<Vec<u8>, StorageError>;
}

/// Atomic blob store for small binary files (e.g., `account_keys.bin`).
#[boltffi::export]
pub trait AtomicBlobStore: Send + Sync {
    /// Reads the blob at `path`, if present.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    fn read(&self, path: String) -> Result<Option<Vec<u8>>, StorageError>;

    /// Writes bytes atomically to `path`.
    ///
    /// # Errors
    ///
    /// Returns an error if the write fails.
    fn write_atomic(&self, path: String, bytes: Vec<u8>) -> Result<(), StorageError>;

    /// Deletes the blob at `path`.
    ///
    /// # Errors
    ///
    /// Returns an error if the delete fails.
    fn delete(&self, path: String) -> Result<(), StorageError>;
}

/// Provider responsible for platform-specific storage components and paths.
pub trait StorageProvider: Send + Sync {
    /// Returns the device keystore implementation.
    fn keystore(&self) -> Arc<dyn DeviceKeystore>;

    /// Returns the blob store implementation.
    fn blob_store(&self) -> Arc<dyn AtomicBlobStore>;

    /// Returns the storage paths selected by the platform.
    fn paths(&self) -> Arc<StoragePaths>;
}

/// Listener notified when the credential vault contents change and a new
/// backup is needed.
///
/// Register via [`super::CredentialStore::set_vault_changed_listener`]. The
/// callback is delivered on a dedicated background thread to avoid re-entering
/// the foreign-binding call stack (see `logger.rs` for rationale).
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
#[boltffi::export]
pub trait VaultChangedListener: Send + Sync {
    /// Called after a credential is added or removed.
    fn on_vault_changed(&self);
}
