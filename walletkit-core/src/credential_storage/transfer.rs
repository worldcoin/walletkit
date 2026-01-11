//! Credential transfer format for device-to-device sync.
//!
//! This module implements the encrypted credential transfer format that
//! enables secure synchronization of credentials between devices.
//!
//! # Transfer Format
//!
//! Transfer bytes are AEAD-encrypted under `K_vault` with:
//! - Algorithm: XChaCha20-Poly1305
//! - Associated data: `account_id || "worldid:credential-transfer"`
//!
//! # Plaintext Structure
//!
//! ```text
//! transfer_version: u32
//! account_id: [u8; 32]
//! credential_id: [u8; 16]
//! record: CredentialRecord (serialized)
//! is_tombstone: u8 (0 = active with blobs, 1 = tombstone)
//! if is_tombstone == 0:
//!     credential_blob_len: u32
//!     credential_blob: [u8; credential_blob_len]
//!     has_associated_data: u8
//!     if has_associated_data == 1:
//!         associated_data_len: u32
//!         associated_data: [u8; associated_data_len]
//! ```
//!
//! # Import Semantics
//!
//! - Import verifies `account_id` matches local account
//! - If `incoming.updated_at <= existing.updated_at`: return `NoOp`
//! - Active credentials include blobs; tombstones propagate retirement status
//! - Import is idempotent and transactional

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use serde::{Deserialize, Serialize};

use crate::credential_storage::{
    vault::{VaultKey, NONCE_SIZE},
    AccountId, CredentialId, CredentialRecord, CredentialTransferBytes,
    StorageError, StorageResult,
};

// Constants

/// Current transfer format version.
pub const TRANSFER_VERSION: u32 = 1;

/// Label for credential transfer AEAD.
const LABEL_CREDENTIAL_TRANSFER: &[u8] = b"worldid:credential-transfer";


/// Internal representation of decrypted transfer payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferPayload {
    /// Transfer format version.
    pub version: u32,
    /// Account this credential belongs to.
    pub account_id: AccountId,
    /// Credential metadata.
    pub record: CredentialRecord,
    /// Whether this is a tombstone (retired credential without blobs).
    pub is_tombstone: bool,
    /// Credential blob (None for tombstones).
    pub credential_blob: Option<Vec<u8>>,
    /// Associated data blob (optional).
    pub associated_data: Option<Vec<u8>>,
}


impl CredentialTransferBytes {
    /// Exports a credential to transfer format.
    ///
    /// # Arguments
    ///
    /// * `vault_key` - The vault encryption key
    /// * `account_id` - Account the credential belongs to
    /// * `record` - Credential metadata
    /// * `credential_blob` - The credential data (None for tombstones)
    /// * `associated_data` - Optional associated data
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails.
    pub fn export(
        vault_key: &VaultKey,
        account_id: &AccountId,
        record: &CredentialRecord,
        credential_blob: Option<&[u8]>,
        associated_data: Option<&[u8]>,
    ) -> StorageResult<Self> {
        let is_tombstone = credential_blob.is_none();

        let payload = TransferPayload {
            version: TRANSFER_VERSION,
            account_id: *account_id,
            record: record.clone(),
            is_tombstone,
            credential_blob: credential_blob.map(|b| b.to_vec()),
            associated_data: associated_data.map(|b| b.to_vec()),
        };

        // Serialize payload
        let plaintext = bincode::serialize(&payload).map_err(|e| {
            StorageError::serialization(format!("Failed to serialize transfer payload: {e}"))
        })?;

        // Encrypt with XChaCha20-Poly1305
        let (ciphertext, nonce) = encrypt_transfer(vault_key, account_id, &plaintext)?;

        // Combine nonce + ciphertext
        let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);

        Ok(Self(output))
    }

    /// Decrypts and parses transfer bytes.
    ///
    /// # Arguments
    ///
    /// * `vault_key` - The vault encryption key
    /// * `expected_account_id` - Account ID to verify against
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Decryption fails
    /// - Account ID doesn't match
    /// - Payload is malformed
    pub fn decrypt(
        &self,
        vault_key: &VaultKey,
        expected_account_id: &AccountId,
    ) -> StorageResult<TransferPayload> {
        if self.0.len() < NONCE_SIZE {
            return Err(StorageError::corrupted("Transfer bytes too short"));
        }

        // Extract nonce and ciphertext
        let nonce: [u8; NONCE_SIZE] = self.0[..NONCE_SIZE]
            .try_into()
            .map_err(|_| StorageError::corrupted("Invalid nonce length"))?;
        let ciphertext = &self.0[NONCE_SIZE..];

        // Decrypt
        let plaintext = decrypt_transfer(vault_key, expected_account_id, &nonce, ciphertext)?;

        // Deserialize
        let payload: TransferPayload = bincode::deserialize(&plaintext).map_err(|e| {
            StorageError::serialization(format!("Failed to deserialize transfer payload: {e}"))
        })?;

        // Verify account ID
        if payload.account_id != *expected_account_id {
            return Err(StorageError::AccountIdMismatch {
                expected: *expected_account_id,
                found: payload.account_id,
            });
        }

        // Verify version
        if payload.version > TRANSFER_VERSION {
            return Err(StorageError::InvalidVersion {
                expected: TRANSFER_VERSION,
                found: payload.version,
            });
        }

        // Validate payload consistency
        if payload.is_tombstone && payload.credential_blob.is_some() {
            return Err(StorageError::corrupted(
                "Tombstone transfer should not contain credential blob",
            ));
        }

        if !payload.is_tombstone && payload.credential_blob.is_none() {
            return Err(StorageError::corrupted(
                "Active transfer must contain credential blob",
            ));
        }

        Ok(payload)
    }

    /// Returns the credential ID from the transfer bytes without full decryption.
    ///
    /// This requires decryption but is provided as a convenience method.
    pub fn credential_id(
        &self,
        vault_key: &VaultKey,
        account_id: &AccountId,
    ) -> StorageResult<CredentialId> {
        let payload = self.decrypt(vault_key, account_id)?;
        Ok(payload.record.credential_id)
    }
}


/// Result of comparing transfer payload with existing credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportDecision {
    /// Should apply the import (newer or new credential).
    Apply,
    /// Should skip the import (existing is newer or equal).
    Skip,
}

/// Determines whether an import should be applied based on timestamps.
///
/// # Arguments
///
/// * `incoming` - The incoming transfer payload
/// * `existing` - The existing credential record (if any)
///
/// # Returns
///
/// `Apply` if the import should proceed, `Skip` if it should be ignored.
#[must_use]
pub fn decide_import(incoming: &TransferPayload, existing: Option<&CredentialRecord>) -> ImportDecision {
    match existing {
        Some(existing_record) => {
            // If incoming is newer, apply it
            if incoming.record.updated_at > existing_record.updated_at {
                ImportDecision::Apply
            } else {
                ImportDecision::Skip
            }
        }
        // No existing record, always apply
        None => ImportDecision::Apply,
    }
}

/// Applies an import to update the credential record.
///
/// This function:
/// 1. Updates the record with incoming data
/// 2. For tombstones, marks the credential as retired
/// 3. For active imports, updates blobs
///
/// # Returns
///
/// The updated `CredentialRecord` and blob data to store.
pub fn apply_import(
    incoming: TransferPayload,
) -> (CredentialRecord, Option<Vec<u8>>, Option<Vec<u8>>) {
    let record = incoming.record;
    let credential_blob = incoming.credential_blob;
    let associated_data = incoming.associated_data;

    (record, credential_blob, associated_data)
}


/// Builds associated data for transfer encryption.
fn build_transfer_aad(account_id: &AccountId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32 + LABEL_CREDENTIAL_TRANSFER.len());
    aad.extend_from_slice(account_id.as_bytes());
    aad.extend_from_slice(LABEL_CREDENTIAL_TRANSFER);
    aad
}

/// Generates a random nonce.
fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    getrandom::getrandom(&mut nonce).expect("getrandom failed");
    nonce
}

/// Encrypts transfer payload.
fn encrypt_transfer(
    key: &VaultKey,
    account_id: &AccountId,
    plaintext: &[u8],
) -> StorageResult<(Vec<u8>, [u8; NONCE_SIZE])> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_bytes()).expect("key length is always 32");

    let nonce_bytes = generate_nonce();
    let nonce = XNonce::from_slice(&nonce_bytes);

    let aad = build_transfer_aad(account_id);

    let ciphertext = cipher
        .encrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| StorageError::encryption("Transfer encryption failed"))?;

    Ok((ciphertext, nonce_bytes))
}

/// Decrypts transfer payload.
fn decrypt_transfer(
    key: &VaultKey,
    account_id: &AccountId,
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
) -> StorageResult<Vec<u8>> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_bytes()).expect("key length is always 32");

    let nonce = XNonce::from_slice(nonce);
    let aad = build_transfer_aad(account_id);

    let plaintext = cipher
        .decrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| StorageError::decryption("Transfer decryption failed"))?;

    Ok(plaintext)
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential_storage::{ContentId, CredentialStatus};

    fn create_test_record() -> CredentialRecord {
        CredentialRecord {
            credential_id: CredentialId::generate(),
            issuer_schema_id: 42,
            created_at: 1000,
            updated_at: 1000,
            expires_at: Some(2000),
            credential_blob_cid: ContentId::new([0xAAu8; 32]),
            associated_data_cid: Some(ContentId::new([0xBBu8; 32])),
            status: CredentialStatus::Active,
        }
    }

    #[test]
    fn test_export_import_roundtrip() {
        let vault_key = VaultKey::generate();
        let account_id = AccountId::new([0x11u8; 32]);
        let record = create_test_record();
        let cred_blob = b"test credential data";
        let transfer = CredentialTransferBytes::export(&vault_key, &account_id, &record, Some(cred_blob), Some(b"assoc")).unwrap();
        let payload = transfer.decrypt(&vault_key, &account_id).unwrap();
        assert_eq!(payload.record.credential_id, record.credential_id);
        assert_eq!(payload.credential_blob.as_deref(), Some(cred_blob.as_slice()));
    }

    #[test]
    fn test_export_import_tombstone() {
        let vault_key = VaultKey::generate();
        let account_id = AccountId::new([0x22u8; 32]);
        let mut record = create_test_record();
        record.status = CredentialStatus::Retired;
        let transfer = CredentialTransferBytes::export(&vault_key, &account_id, &record, None, None).unwrap();
        let payload = transfer.decrypt(&vault_key, &account_id).unwrap();
        assert!(payload.is_tombstone);
        assert_eq!(payload.record.status, CredentialStatus::Retired);
    }

    #[test]
    fn test_conflict_resolution() {
        let mut existing = create_test_record();
        existing.updated_at = 1000;
        let mut incoming = create_test_record();
        incoming.updated_at = 2000;
        let payload = TransferPayload {
            version: TRANSFER_VERSION,
            account_id: AccountId::new([0u8; 32]),
            record: incoming.clone(),
            is_tombstone: false,
            credential_blob: Some(vec![1, 2, 3]),
            associated_data: None,
        };
        assert_eq!(decide_import(&payload, Some(&existing)), ImportDecision::Apply);
        existing.updated_at = 2000;
        incoming.updated_at = 1000;
        let payload = TransferPayload {
            version: TRANSFER_VERSION,
            account_id: AccountId::new([0u8; 32]),
            record: incoming,
            is_tombstone: false,
            credential_blob: Some(vec![1, 2, 3]),
            associated_data: None,
        };
        assert_eq!(decide_import(&payload, Some(&existing)), ImportDecision::Skip);
        assert_eq!(decide_import(&payload, None), ImportDecision::Apply);
    }
}
