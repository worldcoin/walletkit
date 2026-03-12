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

use super::error::StorageResult;
use super::paths::StoragePaths;

/// Device keystore interface used to seal and open account keys.
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

/// Atomic blob store for small binary files (e.g., `account_keys.bin`).
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
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(with_foreign))]
pub trait StorageProvider: Send + Sync {
    /// Returns the device keystore implementation.
    fn keystore(&self) -> Arc<dyn DeviceKeystore>;

    /// Returns the blob store implementation.
    fn blob_store(&self) -> Arc<dyn AtomicBlobStore>;

    /// Returns the storage paths selected by the platform.
    fn paths(&self) -> Arc<StoragePaths>;
}

/// Callback interface for notifying the host app that the credential vault
/// has changed and needs to be synced to the backup.
///
/// The host app (e.g. iOS) implements this trait and passes it to
/// `CredentialStore::set_backup_manager`. `WalletKit` calls
/// [`on_vault_changed`](WalletKitBackupManager::on_vault_changed) after
/// `store_credential`, `delete_credential`, and `danger_delete_all_credentials`, passing the path
/// to a freshly-exported plaintext vault file.
///
/// **Important:** the exported file is deleted automatically when this
/// callback returns. The implementor must copy or upload the file contents
/// synchronously during this call.
///
/// **Warning:** the implementor must **not** call back into
/// `CredentialStore` (e.g. `store_credential`, `delete_credential`) from
/// within `on_vault_changed`. Doing so will deadlock because the
/// notification path holds an internal lock for the duration of the
/// callback.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(with_foreign))]
pub trait WalletKitBackupManager: Send + Sync {
    /// Directory where plaintext vault exports are written before the
    /// callback is invoked.
    fn dest_dir(&self) -> String;

    /// Called after the vault has been mutated and exported.
    ///
    /// `vault_file_path` is the path to the exported plaintext vault file.
    /// The file is deleted automatically when this method returns, so the
    /// implementor must finish reading or copying it before returning.
    ///
    /// # Errors
    ///
    /// Returning `Err` is treated as best-effort — the error is logged but
    /// does not affect the vault mutation that triggered this call. Returning
    /// `Result` (rather than `()`) ensures that host-side exceptions are
    /// translated into a Rust `Err` by `UniFFI` instead of panicking.
    fn on_vault_changed(&self, vault_file_path: String) -> StorageResult<()>;
}
