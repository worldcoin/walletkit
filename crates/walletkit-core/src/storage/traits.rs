//! Platform interfaces for credential storage.
//!
//! These traits are the platform integration boundary. The host selects the storage
//! root and provides a [`KeySealer`] and [`AtomicBlobStore`]; core storage code
//! is root-agnostic and consumes a provider-supplied [`StoragePaths`].
//!
//! # Expected platform components
//!
//! - **iOS (Swift):** [`KeySealer`] backed by Keychain / Secure Enclave;
//!   [`AtomicBlobStore`] over the app container filesystem (atomic replace).
//! - **Android (Kotlin):** [`KeySealer`] backed by the Android Keystore;
//!   [`AtomicBlobStore`] over app internal storage (atomic replace).
//! - **Node.js:** file-backed [`KeySealer`] (development; production can use an
//!   OS keystore); [`AtomicBlobStore`] over app internal storage.
//! - **Browser (WASM):** host-provided [`KeySealer`] and [`AtomicBlobStore`]
//!   implementations; sqlite persistence itself uses encrypted OPFS storage.

use std::sync::Arc;

use super::error::StorageResult;
use super::paths::StoragePaths;

/// Host interface used to seal and unseal account keys.
#[uniffi::export(with_foreign)]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait KeySealer: Send + Sync {
    /// Seals plaintext and binds it to `context`.
    ///
    /// Implementations may bind the context as AEAD additional authenticated data,
    /// by selecting a context-specific key, or through an equivalent mechanism.
    /// Unsealing with a different context must fail.
    ///
    /// # Errors
    ///
    /// Returns an error if the key sealer refuses the operation or sealing fails.
    async fn seal(
        &self,
        context: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> StorageResult<Vec<u8>>;

    /// Unseals ciphertext after verifying its binding to `context`.
    ///
    /// The same context used during sealing must be supplied or the operation must
    /// fail.
    ///
    /// # Errors
    ///
    /// Returns an error if authentication fails or the key cannot be unsealed.
    async fn unseal(
        &self,
        context: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> StorageResult<Vec<u8>>;
}

/// Atomic blob store for small binary files (e.g., `account_keys.bin`).
#[uniffi::export(with_foreign)]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait AtomicBlobStore: Send + Sync {
    /// Reads the blob at `path`, if present.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    async fn read(&self, path: String) -> StorageResult<Option<Vec<u8>>>;

    /// Writes bytes atomically to `path`.
    ///
    /// # Errors
    ///
    /// Returns an error if the write fails.
    async fn write_atomic(&self, path: String, bytes: Vec<u8>) -> StorageResult<()>;

    /// Deletes the blob at `path`.
    ///
    /// # Errors
    ///
    /// Returns an error if the delete fails.
    async fn delete(&self, path: String) -> StorageResult<()>;
}

/// Provider responsible for platform-specific storage components and paths.
#[uniffi::export(with_foreign)]
pub trait StorageProvider: Send + Sync {
    /// Returns the key sealer implementation.
    fn key_sealer(&self) -> Arc<dyn KeySealer>;

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
