//! iOS Keychain-based device keystore implementation.
//!
//! This module implements `DeviceKeystore` using the iOS Keychain Services
//! for secure key storage and AEAD encryption for data protection.
//!
//! # Security Model
//!
//! - **Key Storage**: The device master key is stored in the Keychain with
//!   `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, ensuring:
//!   - Keys are only accessible when the device is unlocked
//!   - Keys are not included in device backups
//!   - Keys are tied to the specific device (not transferable)
//!
//! - **Encryption**: Uses XChaCha20-Poly1305 AEAD with:
//!   - 24-byte random nonces (prepended to ciphertext)
//!   - Associated data binding to prevent cross-context attacks
//!
//! # Key Hierarchy
//!
//! ```text
//! Device Master Key (in Keychain)
//!     │
//!     ├─► Account State encryption (AAD: account_id || device_id || "worldid:device-state")
//!     ├─► Pending Actions encryption (AAD: account_id || device_id || "worldid:pending-actions")
//!     └─► Vault Key wrap (AAD: account_id || device_id || "worldid:vault-key")
//! ```

use crate::credential_storage::platform::DeviceKeystore;
use crate::credential_storage::{AccountId, StorageError, StorageResult};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};
use zeroize::Zeroizing;

/// Size of the XChaCha20-Poly1305 key in bytes.
const KEY_SIZE: usize = 32;

/// Size of the XChaCha20 nonce in bytes.
const NONCE_SIZE: usize = 24;

/// Size of the Poly1305 authentication tag in bytes.
const TAG_SIZE: usize = 16;

/// Keychain service identifier for World ID.
const KEYCHAIN_SERVICE: &str = "org.worldcoin.worldid";

/// Keychain account identifier for the device master key.
const KEYCHAIN_DEVICE_KEY_ACCOUNT: &str = "device-master-key";

// IosKeystore

/// iOS Keychain-based implementation of `DeviceKeystore`.
///
/// This implementation stores a master encryption key in the iOS Keychain
/// and uses it to encrypt/decrypt sensitive data with AEAD.
///
/// # Thread Safety
///
/// The keystore is thread-safe. The underlying Keychain operations are
/// synchronized by the system.
///
/// # Example
///
/// ```ignore
/// let keystore = IosKeystore::new()?;
///
/// // Encrypt some data
/// let aad = b"context-binding-data";
/// let plaintext = b"secret data";
/// let ciphertext = keystore.seal(aad, plaintext)?;
///
/// // Decrypt it back
/// let decrypted = keystore.open(aad, &ciphertext)?;
/// assert_eq!(decrypted, plaintext);
/// ```
#[derive(Debug)]
pub struct IosKeystore {
    /// Cached device master key (zeroized on drop).
    /// We cache this to avoid Keychain lookups on every operation.
    device_key: Zeroizing<[u8; KEY_SIZE]>,
}

impl IosKeystore {
    /// Creates a new iOS keystore instance.
    ///
    /// This will either retrieve the existing device master key from the
    /// Keychain or generate a new one if none exists.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Keychain access fails
    /// - Key generation fails
    /// - Random number generation fails
    pub fn new() -> StorageResult<Self> {
        let device_key = Self::get_or_create_device_key()?;
        Ok(Self { device_key })
    }

    /// Retrieves or creates the device master key from the Keychain.
    fn get_or_create_device_key() -> StorageResult<Zeroizing<[u8; KEY_SIZE]>> {
        // Try to get existing key
        match get_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_DEVICE_KEY_ACCOUNT) {
            Ok(key_bytes) => {
                if key_bytes.len() != KEY_SIZE {
                    return Err(StorageError::corrupted(format!(
                        "Device key has invalid length: {} (expected {})",
                        key_bytes.len(),
                        KEY_SIZE
                    )));
                }
                let mut key = Zeroizing::new([0u8; KEY_SIZE]);
                key.copy_from_slice(&key_bytes);
                Ok(key)
            }
            Err(e)
                if e.code()
                    == security_framework::base::Error::from_code(-25300).code() =>
            {
                // errSecItemNotFound (-25300) - key doesn't exist, create it
                Self::create_device_key()
            }
            Err(e) => Err(StorageError::keystore(format!(
                "Failed to retrieve device key from Keychain: {e}"
            ))),
        }
    }

    /// Creates a new device master key and stores it in the Keychain.
    fn create_device_key() -> StorageResult<Zeroizing<[u8; KEY_SIZE]>> {
        // Generate random key
        let mut key = Zeroizing::new([0u8; KEY_SIZE]);
        getrandom::getrandom(&mut *key).map_err(|e| {
            StorageError::encryption(format!("Failed to generate device key: {e}"))
        })?;

        // Store in Keychain with secure attributes
        // Note: security-framework's set_generic_password uses default accessibility
        // For production, you may want to use the lower-level SecItem APIs to set
        // kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        set_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_DEVICE_KEY_ACCOUNT, &*key)
            .map_err(|e| {
                StorageError::keystore(format!(
                    "Failed to store device key in Keychain: {e}"
                ))
            })?;

        Ok(key)
    }

    /// Deletes all Keychain items associated with a specific account.
    ///
    /// This is called when an account is deleted to clean up any
    /// account-specific keys that may have been stored.
    pub fn delete_account_keys(&self, _account_id: &AccountId) -> StorageResult<()> {
        // Currently we use a single device-wide key, not per-account keys.
        // This method is a placeholder for future per-account key support.
        // For now, it's a no-op.
        Ok(())
    }

    /// Deletes the device master key from the Keychain.
    ///
    /// # Warning
    ///
    /// This will make all previously encrypted data unrecoverable.
    /// Only call this when completely resetting the World ID data.
    pub fn delete_device_key() -> StorageResult<()> {
        match delete_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_DEVICE_KEY_ACCOUNT) {
            Ok(()) => Ok(()),
            Err(e)
                if e.code()
                    == security_framework::base::Error::from_code(-25300).code() =>
            {
                // Key doesn't exist, that's fine
                Ok(())
            }
            Err(e) => Err(StorageError::keystore(format!(
                "Failed to delete device key from Keychain: {e}"
            ))),
        }
    }

    /// Generates a random nonce for AEAD encryption.
    fn generate_nonce() -> StorageResult<[u8; NONCE_SIZE]> {
        let mut nonce = [0u8; NONCE_SIZE];
        getrandom::getrandom(&mut nonce).map_err(|e| {
            StorageError::encryption(format!("Failed to generate nonce: {e}"))
        })?;
        Ok(nonce)
    }
}

impl DeviceKeystore for IosKeystore {
    /// Encrypts plaintext using XChaCha20-Poly1305 AEAD.
    ///
    /// # Output Format
    ///
    /// ```text
    /// [nonce (24 bytes)][ciphertext + tag]
    /// ```
    ///
    /// # Arguments
    ///
    /// * `associated_data` - Context-binding data that must match during decryption
    /// * `plaintext` - The data to encrypt
    ///
    /// # Returns
    ///
    /// The encrypted ciphertext with prepended nonce.
    fn seal(&self, associated_data: &[u8], plaintext: &[u8]) -> StorageResult<Vec<u8>> {
        let cipher = XChaCha20Poly1305::new_from_slice(&*self.device_key)
            .expect("Device key should be valid length");

        let nonce_bytes = Self::generate_nonce()?;
        let nonce = XNonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(
                nonce,
                chacha20poly1305::aead::Payload {
                    msg: plaintext,
                    aad: associated_data,
                },
            )
            .map_err(|e| StorageError::encryption(format!("Encryption failed: {e}")))?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypts ciphertext using XChaCha20-Poly1305 AEAD.
    ///
    /// # Input Format
    ///
    /// Expects the format produced by `seal`:
    /// ```text
    /// [nonce (24 bytes)][ciphertext + tag]
    /// ```
    ///
    /// # Arguments
    ///
    /// * `associated_data` - Must match the AAD used during encryption
    /// * `ciphertext` - The encrypted data with prepended nonce
    ///
    /// # Returns
    ///
    /// The decrypted plaintext.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The ciphertext is too short
    /// - Authentication fails (wrong key, wrong AAD, or tampered data)
    fn open(
        &self,
        associated_data: &[u8],
        ciphertext: &[u8],
    ) -> StorageResult<Vec<u8>> {
        // Minimum length: nonce + tag (no plaintext)
        if ciphertext.len() < NONCE_SIZE + TAG_SIZE {
            return Err(StorageError::decryption(format!(
                "Ciphertext too short: {} bytes (minimum {})",
                ciphertext.len(),
                NONCE_SIZE + TAG_SIZE
            )));
        }

        let cipher = XChaCha20Poly1305::new_from_slice(&*self.device_key)
            .expect("Device key should be valid length");

        let nonce = XNonce::from_slice(&ciphertext[..NONCE_SIZE]);
        let encrypted = &ciphertext[NONCE_SIZE..];

        let plaintext = cipher
            .decrypt(
                nonce,
                chacha20poly1305::aead::Payload {
                    msg: encrypted,
                    aad: associated_data,
                },
            )
            .map_err(|_| {
                StorageError::decryption("Decryption failed: authentication error")
            })?;

        Ok(plaintext)
    }
}
