//! Platform interfaces for credential storage.
//!
//! This module defines the platform integration boundary for the storage engine.
//! The platform layer selects the storage root and wires together the keystore
//! and blob store. Core storage code is root-agnostic and consumes a
//! provider-supplied [`StoragePaths`].
//!
//! ## Key structure
//!
//! - `K_device`: device-bound root key managed by [`DeviceKeystore`].
//! - `account_keys.bin`: account key envelope stored via [`AtomicBlobStore`] and
//!   containing `DeviceKeystore::seal` of `K_intermediate` with associated data
//!   `worldid:account-key-envelope`.
//! - `K_intermediate`: 32-byte per-account key unsealed at init and kept in
//!   memory for the lifetime of the storage handle.
//! - sqlite3mc databases: `account.vault.sqlite` (authoritative) and
//!   `account.cache.sqlite` (non-authoritative) are opened with `K_intermediate`.
//! - Derived keys: per relying-party session keys may be derived from
//!   `K_intermediate` and cached in `account.cache.sqlite` for performance.
//!
//! ## Platform Bindings
//!
//! ### iOS (Swift)
//!
//! Default platform components:
//! - [`DeviceKeystore`]: Keychain / Secure Enclave-backed keystore
//! - [`AtomicBlobStore`]: app container filesystem (atomic replace)
//!
//! ### Android (Kotlin)
//!
//! Default platform components:
//! - [`DeviceKeystore`]: Android Keystore-backed
//! - [`AtomicBlobStore`]: app internal storage (atomic replace)
//!
//! ### Node.js
//!
//! Default platform components:
//! - [`DeviceKeystore`]: file-backed keystore stored under `<root>/worldid/device_keystore.bin`
//!   (development; production can use OS keystore)
//! - [`AtomicBlobStore`]: app internal storage (atomic replace)
//!
//! ### Browser (WASM)
//!
//! Default platform components:
//! - [`DeviceKeystore`]: `WebCrypto`-backed device keystore
//! - [`AtomicBlobStore`]: origin-private storage namespace

use std::sync::Arc;

use super::error::StorageResult;
use super::paths::StoragePaths;

/// Device keystore interface used to seal and open account keys.
///
/// Represents the device-bound root key (`K_device`) provided by the platform keystore.
/// This key MUST be non-exportable when supported by the platform (Secure Enclave on iOS,
/// Android Keystore on Android, `WebCrypto` on browsers).
///
/// `K_device` is used **only** to unwrap the per-account intermediate key (`K_intermediate`)
/// during initialization. It is never used directly for database encryption.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(with_foreign))]
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

/// Atomic blob store for small binary files.
///
/// Used to persist the account key envelope (`account_keys.bin`) which contains
/// `K_intermediate` sealed under `K_device`. Writes MUST be atomic (write-then-rename
/// or equivalent) to avoid partial-write corruption.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(with_foreign))]
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
///
/// The platform layer selects the storage root and wires together the keystore
/// and blob store. Core storage code is root-agnostic and consumes a
/// provider-supplied [`StoragePaths`].
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(with_foreign))]
pub trait StorageProvider: Send + Sync {
    /// Returns the device keystore implementation.
    fn keystore(&self) -> Arc<dyn DeviceKeystore>;

    /// Returns the blob store implementation.
    fn blob_store(&self) -> Arc<dyn AtomicBlobStore>;

    /// Returns the storage paths selected by the platform.
    fn paths(&self) -> Arc<StoragePaths>;
}

/// Listener notified when the credential vault is mutated.
///
/// Register via [`super::CredentialStore::set_vault_changed_listener`]. The
/// callback is delivered on a dedicated background thread to avoid re-entering
/// the `UniFFI` call stack (see `logger.rs` for rationale).
///
/// # Expected usage
///
/// The host app should treat this as a trigger to take actions when the vault
/// state has mutated. It should contain synchronous actions only.
///
/// # Safety
///
/// **Warning:** implementors **must not** call back into
/// [`super::CredentialStore`] from
/// [`on_vault_changed`](VaultChangedListener::on_vault_changed) — doing so
/// will deadlock.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(with_foreign))]
pub trait VaultChangedListener: Send + Sync {
    /// Called after a successful vault mutation (store, delete, purge).
    fn on_vault_changed(&self);
}
