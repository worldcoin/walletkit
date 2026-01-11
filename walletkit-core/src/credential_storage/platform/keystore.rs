//! Device keystore trait for hardware-backed encryption.
//!
//! The device keystore provides device-protected encryption for sensitive data
//! that should not leave the device, such as account state and the wrapped
//! vault key.

use crate::credential_storage::StorageResult;

/// Device-protected encryption for account state and vault key wrapping.
///
/// Platform implementations should use hardware-backed keystores where available:
/// - iOS: Keychain Services with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
/// - Android: Android Keystore with hardware-backed keys
/// - Browser: `WebCrypto` with non-extractable keys in `IndexedDB`
/// - Node.js: File-backed key (less secure, for development/testing)
///
/// # Security Requirements
///
/// - The device key (`K_device`) MUST be non-exportable when supported by the platform.
/// - The key MUST be bound to the device (not transferable via backup/restore).
/// - Implementations MUST use authenticated encryption (AEAD).
///
/// # Associated Data
///
/// The `associated_data` parameter provides domain separation and binding.
/// It MUST be included in the AEAD authentication tag computation.
///
/// For account state and pending actions:
/// ```text
/// associated_data = account_id || device_id || "worldid:device-state"
/// ```
///
/// For vault key wrapping:
/// ```text
/// associated_data = account_id || device_id || "worldid:vault-key-wrap"
/// ```
pub trait DeviceKeystore: Send + Sync {
    /// Encrypts plaintext with the device-bound key.
    ///
    /// # Arguments
    ///
    /// * `associated_data` - Domain separation and binding data included in AEAD tag
    /// * `plaintext` - The data to encrypt
    ///
    /// # Returns
    ///
    /// The ciphertext (including nonce and authentication tag).
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails (e.g., keystore unavailable).
    fn seal(&self, associated_data: &[u8], plaintext: &[u8]) -> StorageResult<Vec<u8>>;

    /// Decrypts ciphertext with the device-bound key.
    ///
    /// # Arguments
    ///
    /// * `associated_data` - Must match the value used during encryption
    /// * `ciphertext` - The data to decrypt (including nonce and auth tag)
    ///
    /// # Returns
    ///
    /// The decrypted plaintext.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Authentication fails (tampered data or wrong associated data)
    /// - The ciphertext is malformed
    /// - The keystore is unavailable
    fn open(&self, associated_data: &[u8], ciphertext: &[u8]) -> StorageResult<Vec<u8>>;
}
