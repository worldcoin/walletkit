//! Cryptographic operations for vault encryption.
//!
//! This module provides XChaCha20-Poly1305 AEAD encryption for vault contents
//! and SHA256-based content ID computation.

// Type names like VaultIndex appear in docs without backticks for readability
#![allow(clippy::doc_markdown)]

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::credential_storage::{AccountId, BlobKind, ContentId, StorageError};

use super::format::{LABEL_VAULT_BLOB_AD, LABEL_VAULT_BLOB_CRED, LABEL_VAULT_INDEX, NONCE_SIZE};

// =============================================================================
// VaultKey
// =============================================================================

/// Vault encryption key (256-bit).
///
/// The vault key (`K_vault`) is used to encrypt all data in the vault file.
/// It is generated randomly when an account is created and wrapped with
/// the device key for storage.
///
/// # Security
///
/// - The key is zeroized on drop to prevent memory leaks.
/// - The key should never be logged or serialized in plaintext.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VaultKey([u8; 32]);

impl VaultKey {
    /// Creates a new vault key from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Generates a new random vault key.
    ///
    /// # Panics
    ///
    /// Panics if the system's random number generator fails.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).expect("getrandom failed");
        Self(bytes)
    }

    /// Returns a reference to the raw key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultKey")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

// =============================================================================
// Content ID Computation
// =============================================================================

/// Computes the content ID (SHA256 hash) of plaintext data.
///
/// The content ID enables deduplication of identical blobs in the vault.
#[must_use]
pub fn compute_content_id(plaintext: &[u8]) -> ContentId {
    let hash = Sha256::digest(plaintext);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    ContentId::new(bytes)
}

// =============================================================================
// AEAD Encryption
// =============================================================================

/// Constructs associated data for vault encryption.
///
/// Format varies by object type:
/// - Index: `account_id || "vault:index"`
/// - Blob:  `account_id || label || content_id`
fn build_associated_data(
    account_id: &AccountId,
    label: &[u8],
    content_id: Option<&ContentId>,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32 + label.len() + content_id.map_or(0, |_| 32));
    aad.extend_from_slice(account_id.as_bytes());
    aad.extend_from_slice(label);
    if let Some(cid) = content_id {
        aad.extend_from_slice(cid.as_bytes());
    }
    aad
}

/// Generates a random nonce for XChaCha20-Poly1305.
///
/// # Panics
///
/// Panics if the system's random number generator fails.
fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    getrandom::getrandom(&mut nonce).expect("getrandom failed");
    nonce
}

/// Encrypts plaintext for vault storage.
///
/// Uses XChaCha20-Poly1305 AEAD with:
/// - Key: `K_vault`
/// - Nonce: 24 random bytes
/// - Associated data: depends on object type
///
/// # Arguments
///
/// * `key` - The vault encryption key
/// * `account_id` - Account this data belongs to
/// * `label` - Domain separation label (e.g., `b"vault:index"`)
/// * `content_id` - Optional content ID for blob encryption
/// * `plaintext` - Data to encrypt
///
/// # Returns
///
/// A tuple of (ciphertext with auth tag, nonce).
///
/// # Errors
///
/// Returns an error if encryption fails (should not happen with valid inputs).
///
/// # Panics
///
/// This function will not panic - the `expect` is for a condition that cannot fail
/// (key length is always 32 bytes by construction).
pub fn vault_encrypt(
    key: &VaultKey,
    account_id: &AccountId,
    label: &[u8],
    content_id: Option<&ContentId>,
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; NONCE_SIZE]), StorageError> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_bytes()).expect("key length is always 32");

    let nonce_bytes = generate_nonce();
    let nonce = XNonce::from_slice(&nonce_bytes);

    let aad = build_associated_data(account_id, label, content_id);

    let ciphertext = cipher
        .encrypt(nonce, chacha20poly1305::aead::Payload { msg: plaintext, aad: &aad })
        .map_err(|_| StorageError::encryption("XChaCha20-Poly1305 encryption failed"))?;

    Ok((ciphertext, nonce_bytes))
}

/// Decrypts ciphertext from vault storage.
///
/// # Arguments
///
/// * `key` - The vault encryption key
/// * `account_id` - Account this data belongs to
/// * `label` - Domain separation label (must match encryption)
/// * `content_id` - Optional content ID (must match encryption)
/// * `nonce` - The nonce used during encryption
/// * `ciphertext` - Data to decrypt (includes auth tag)
///
/// # Returns
///
/// The decrypted plaintext.
///
/// # Errors
///
/// Returns an error if:
/// - Authentication fails (wrong key, tampered data, wrong associated data)
/// - The ciphertext is malformed
///
/// # Panics
///
/// This function will not panic - the `expect` is for a condition that cannot fail
/// (key length is always 32 bytes by construction).
pub fn vault_decrypt(
    key: &VaultKey,
    account_id: &AccountId,
    label: &[u8],
    content_id: Option<&ContentId>,
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
) -> Result<Vec<u8>, StorageError> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_bytes()).expect("key length is always 32");

    let nonce = XNonce::from_slice(nonce);
    let aad = build_associated_data(account_id, label, content_id);

    let plaintext = cipher
        .decrypt(nonce, chacha20poly1305::aead::Payload { msg: ciphertext, aad: &aad })
        .map_err(|_| StorageError::decryption("XChaCha20-Poly1305 decryption failed"))?;

    Ok(plaintext)
}

/// Encrypts a vault index.
///
/// # Arguments
///
/// * `key` - The vault encryption key
/// * `account_id` - Account this index belongs to
/// * `plaintext` - Serialized `VaultIndex` bytes
///
/// # Returns
///
/// A tuple of (ciphertext, nonce).
pub fn encrypt_index(
    key: &VaultKey,
    account_id: &AccountId,
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; NONCE_SIZE]), StorageError> {
    vault_encrypt(key, account_id, LABEL_VAULT_INDEX, None, plaintext)
}

/// Decrypts a vault index.
///
/// # Arguments
///
/// * `key` - The vault encryption key
/// * `account_id` - Account this index belongs to
/// * `nonce` - The nonce from the encrypted index record
/// * `ciphertext` - The encrypted index data
///
/// # Returns
///
/// The decrypted `VaultIndex` bytes.
pub fn decrypt_index(
    key: &VaultKey,
    account_id: &AccountId,
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
) -> Result<Vec<u8>, StorageError> {
    vault_decrypt(key, account_id, LABEL_VAULT_INDEX, None, nonce, ciphertext)
}

/// Encrypts a blob for vault storage.
///
/// # Arguments
///
/// * `key` - The vault encryption key
/// * `account_id` - Account this blob belongs to
/// * `blob_kind` - Type of blob (credential or associated data)
/// * `plaintext` - The blob data to encrypt
///
/// # Returns
///
/// A tuple of (`content_id`, ciphertext, nonce).
pub fn encrypt_blob(
    key: &VaultKey,
    account_id: &AccountId,
    blob_kind: BlobKind,
    plaintext: &[u8],
) -> Result<(ContentId, Vec<u8>, [u8; NONCE_SIZE]), StorageError> {
    let content_id = compute_content_id(plaintext);
    let label = match blob_kind {
        BlobKind::CredentialBlob => LABEL_VAULT_BLOB_CRED,
        BlobKind::AssociatedData => LABEL_VAULT_BLOB_AD,
    };

    let (ciphertext, nonce) = vault_encrypt(key, account_id, label, Some(&content_id), plaintext)?;

    Ok((content_id, ciphertext, nonce))
}

/// Decrypts a blob from vault storage.
///
/// # Arguments
///
/// * `key` - The vault encryption key
/// * `account_id` - Account this blob belongs to
/// * `blob_kind` - Type of blob (must match encryption)
/// * `content_id` - Content ID (must match encryption)
/// * `nonce` - The nonce from the encrypted blob record
/// * `ciphertext` - The encrypted blob data
///
/// # Returns
///
/// The decrypted blob data.
pub fn decrypt_blob(
    key: &VaultKey,
    account_id: &AccountId,
    blob_kind: BlobKind,
    content_id: &ContentId,
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
) -> Result<Vec<u8>, StorageError> {
    let label = match blob_kind {
        BlobKind::CredentialBlob => LABEL_VAULT_BLOB_CRED,
        BlobKind::AssociatedData => LABEL_VAULT_BLOB_AD,
    };

    vault_decrypt(key, account_id, label, Some(content_id), nonce, ciphertext)
}

/// Computes SHA256 hash of a record body for `TxnCommit`.
#[must_use]
pub fn hash_record_body(body: &[u8]) -> [u8; 32] {
    let hash = Sha256::digest(body);
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    result
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_key_generation() {
        let key1 = VaultKey::generate();
        let key2 = VaultKey::generate();

        // Keys should be different (with overwhelming probability)
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_vault_key_from_bytes() {
        let bytes = [0x42u8; 32];
        let key = VaultKey::from_bytes(bytes);
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn test_vault_key_debug_redacted() {
        let key = VaultKey::generate();
        let debug = format!("{key:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("42")); // Shouldn't contain any key bytes
    }

    #[test]
    fn test_content_id_computation() {
        let data = b"hello, world!";
        let content_id = compute_content_id(data);

        // SHA256 of "hello, world!" is known
        let expected_hex = "68e656b251e67e8358bef8483ab0d51c6619f3e7a1a9f0e75838d41ff368f728";
        assert_eq!(content_id.to_hex(), expected_hex);

        // Same data should produce same content ID
        let content_id2 = compute_content_id(data);
        assert_eq!(content_id, content_id2);

        // Different data should produce different content ID
        let content_id3 = compute_content_id(b"different data");
        assert_ne!(content_id, content_id3);
    }

    #[test]
    fn test_vault_encrypt_decrypt_roundtrip() {
        let key = VaultKey::generate();
        let account_id = AccountId::new([0x11u8; 32]);
        let plaintext = b"secret vault data";

        let (ciphertext, nonce) =
            vault_encrypt(&key, &account_id, LABEL_VAULT_INDEX, None, plaintext).unwrap();

        // Ciphertext should be different from plaintext
        assert_ne!(&ciphertext[..plaintext.len()], plaintext);

        // Ciphertext should include auth tag (16 bytes longer)
        assert_eq!(ciphertext.len(), plaintext.len() + 16);

        let decrypted =
            vault_decrypt(&key, &account_id, LABEL_VAULT_INDEX, None, &nonce, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_vault_encrypt_wrong_key() {
        let key1 = VaultKey::generate();
        let key2 = VaultKey::generate();
        let account_id = AccountId::new([0u8; 32]);
        let plaintext = b"secret data";

        let (ciphertext, nonce) =
            vault_encrypt(&key1, &account_id, LABEL_VAULT_INDEX, None, plaintext).unwrap();

        // Decrypting with wrong key should fail
        let result =
            vault_decrypt(&key2, &account_id, LABEL_VAULT_INDEX, None, &nonce, &ciphertext);
        assert!(matches!(result, Err(StorageError::DecryptionFailed { .. })));
    }

    #[test]
    fn test_vault_encrypt_wrong_account_id() {
        let key = VaultKey::generate();
        let account_id1 = AccountId::new([0x11u8; 32]);
        let account_id2 = AccountId::new([0x22u8; 32]);
        let plaintext = b"secret data";

        let (ciphertext, nonce) =
            vault_encrypt(&key, &account_id1, LABEL_VAULT_INDEX, None, plaintext).unwrap();

        // Decrypting with wrong account ID should fail
        let result =
            vault_decrypt(&key, &account_id2, LABEL_VAULT_INDEX, None, &nonce, &ciphertext);
        assert!(matches!(result, Err(StorageError::DecryptionFailed { .. })));
    }

    #[test]
    fn test_vault_encrypt_wrong_label() {
        let key = VaultKey::generate();
        let account_id = AccountId::new([0u8; 32]);
        let plaintext = b"secret data";

        let (ciphertext, nonce) =
            vault_encrypt(&key, &account_id, LABEL_VAULT_INDEX, None, plaintext).unwrap();

        // Decrypting with wrong label should fail
        let result =
            vault_decrypt(&key, &account_id, LABEL_VAULT_BLOB_CRED, None, &nonce, &ciphertext);
        assert!(matches!(result, Err(StorageError::DecryptionFailed { .. })));
    }

    #[test]
    fn test_vault_encrypt_tampered_ciphertext() {
        let key = VaultKey::generate();
        let account_id = AccountId::new([0u8; 32]);
        let plaintext = b"secret data";

        let (mut ciphertext, nonce) =
            vault_encrypt(&key, &account_id, LABEL_VAULT_INDEX, None, plaintext).unwrap();

        // Tamper with ciphertext
        ciphertext[0] ^= 0xFF;

        // Decryption should fail
        let result =
            vault_decrypt(&key, &account_id, LABEL_VAULT_INDEX, None, &nonce, &ciphertext);
        assert!(matches!(result, Err(StorageError::DecryptionFailed { .. })));
    }

    #[test]
    fn test_encrypt_decrypt_index() {
        let key = VaultKey::generate();
        let account_id = AccountId::new([0x33u8; 32]);
        let index_data = b"serialized vault index data here";

        let (ciphertext, nonce) = encrypt_index(&key, &account_id, index_data).unwrap();
        let decrypted = decrypt_index(&key, &account_id, &nonce, &ciphertext).unwrap();

        assert_eq!(decrypted, index_data);
    }

    #[test]
    fn test_encrypt_decrypt_blob() {
        let key = VaultKey::generate();
        let account_id = AccountId::new([0x44u8; 32]);
        let blob_data = b"credential blob data";

        let (content_id, ciphertext, nonce) =
            encrypt_blob(&key, &account_id, BlobKind::CredentialBlob, blob_data).unwrap();

        // Content ID should be SHA256 of plaintext
        assert_eq!(content_id, compute_content_id(blob_data));

        let decrypted = decrypt_blob(
            &key,
            &account_id,
            BlobKind::CredentialBlob,
            &content_id,
            &nonce,
            &ciphertext,
        )
        .unwrap();

        assert_eq!(decrypted, blob_data);
    }

    #[test]
    fn test_encrypt_blob_wrong_kind() {
        let key = VaultKey::generate();
        let account_id = AccountId::new([0u8; 32]);
        let blob_data = b"some blob";

        let (content_id, ciphertext, nonce) =
            encrypt_blob(&key, &account_id, BlobKind::CredentialBlob, blob_data).unwrap();

        // Decrypting with wrong blob kind should fail
        let result = decrypt_blob(
            &key,
            &account_id,
            BlobKind::AssociatedData, // Wrong kind
            &content_id,
            &nonce,
            &ciphertext,
        );
        assert!(matches!(result, Err(StorageError::DecryptionFailed { .. })));
    }

    #[test]
    fn test_encrypt_blob_wrong_content_id() {
        let key = VaultKey::generate();
        let account_id = AccountId::new([0u8; 32]);
        let blob_data = b"some blob";

        let (_, ciphertext, nonce) =
            encrypt_blob(&key, &account_id, BlobKind::CredentialBlob, blob_data).unwrap();

        // Decrypting with wrong content ID should fail
        let wrong_content_id = ContentId::new([0xFFu8; 32]);
        let result = decrypt_blob(
            &key,
            &account_id,
            BlobKind::CredentialBlob,
            &wrong_content_id,
            &nonce,
            &ciphertext,
        );
        assert!(matches!(result, Err(StorageError::DecryptionFailed { .. })));
    }

    #[test]
    fn test_hash_record_body() {
        let body = b"transaction commit body";
        let hash = hash_record_body(body);

        // Same input should produce same hash
        let hash2 = hash_record_body(body);
        assert_eq!(hash, hash2);

        // Different input should produce different hash
        let hash3 = hash_record_body(b"different body");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_empty_plaintext() {
        let key = VaultKey::generate();
        let account_id = AccountId::new([0u8; 32]);

        let (ciphertext, nonce) =
            vault_encrypt(&key, &account_id, LABEL_VAULT_INDEX, None, b"").unwrap();

        // Empty plaintext should encrypt to just the auth tag (16 bytes)
        assert_eq!(ciphertext.len(), 16);

        let decrypted =
            vault_decrypt(&key, &account_id, LABEL_VAULT_INDEX, None, &nonce, &ciphertext).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_large_plaintext() {
        let key = VaultKey::generate();
        let account_id = AccountId::new([0u8; 32]);
        let plaintext = vec![0xABu8; 1_000_000]; // 1 MB

        let (ciphertext, nonce) =
            vault_encrypt(&key, &account_id, LABEL_VAULT_INDEX, None, &plaintext).unwrap();

        let decrypted =
            vault_decrypt(&key, &account_id, LABEL_VAULT_INDEX, None, &nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
