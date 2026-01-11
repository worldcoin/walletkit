//! Error types for the credential storage system.
//!
//! This module defines all error conditions that can occur during
//! credential storage operations.

use std::fmt;

use super::types::{AccountId, ContentId, CredentialId};

/// Errors that can occur during credential storage operations.
#[derive(Debug)]
pub enum StorageError {
    // I/O Errors
    /// An I/O operation failed.
    IoError {
        /// Context describing the operation.
        context: String,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// Invalid magic bytes in file header.
    InvalidMagic {
        /// Expected magic bytes.
        expected: &'static [u8],
        /// Actual bytes found.
        found: Vec<u8>,
    },

    /// Unsupported format version.
    InvalidVersion {
        /// Expected version.
        expected: u32,
        /// Actual version found.
        found: u32,
    },

    /// Checksum validation failed.
    ChecksumMismatch {
        /// Context describing what was being validated.
        context: String,
    },

    /// Data is corrupted or malformed.
    CorruptedData {
        /// Description of the corruption.
        context: String,
    },

    /// Invalid input parameter.
    InvalidInput {
        /// Name of the invalid parameter.
        parameter: String,
        /// Description of the issue.
        reason: String,
    },

    /// Unexpected end of data while parsing.
    UnexpectedEof {
        /// Context describing what was being parsed.
        context: String,
    },

    /// Decryption failed (authentication failure or corrupted ciphertext).
    DecryptionFailed {
        /// Context describing what was being decrypted.
        context: String,
    },

    /// Encryption failed.
    EncryptionFailed {
        /// Context describing what was being encrypted.
        context: String,
    },

    /// Key derivation failed.
    KeyDerivationFailed {
        /// Context describing what was being derived.
        context: String,
    },

    /// No valid superblock found in vault file.
    NoValidSuperblock,

    /// Transaction failed to commit.
    TransactionFailed {
        /// Reason for failure.
        reason: String,
    },

    /// Vault is locked by another process.
    VaultLocked,

    /// Vault file is not initialized.
    VaultNotInitialized,

    /// Account not found.
    AccountNotFound {
        /// The account ID that was not found.
        account_id: AccountId,
    },

    /// Account already exists.
    AccountAlreadyExists {
        /// The account ID that already exists.
        account_id: AccountId,
    },

    /// Credential not found.
    CredentialNotFound {
        /// The credential ID that was not found.
        credential_id: CredentialId,
    },

    /// Blob not found.
    BlobNotFound {
        /// The content ID that was not found.
        content_id: ContentId,
    },

    /// Nullifier has already been consumed.
    NullifierAlreadyConsumed,

    /// An action is already pending for this scope.
    ActionAlreadyPending {
        /// The action scope hash.
        action_scope: [u8; 32],
    },

    /// No pending action found for this scope.
    PendingActionNotFound {
        /// The action scope hash.
        action_scope: [u8; 32],
    },

    /// Pending action store is at capacity.
    PendingActionStoreFull,

    /// Account ID in transfer doesn't match local account.
    AccountIdMismatch {
        /// Expected account ID.
        expected: AccountId,
        /// Account ID found in transfer.
        found: AccountId,
    },

    /// Transfer data is invalid.
    InvalidTransfer {
        /// Description of what's wrong.
        reason: String,
    },

    /// Device keystore operation failed.
    KeystoreError {
        /// Error message from the keystore.
        message: String,
    },

    /// Failed to acquire lock.
    LockError {
        /// Error message.
        message: String,
    },

    /// Serialization failed.
    SerializationError {
        /// Error message.
        message: String,
    },

    /// Deserialization failed.
    DeserializationError {
        /// Error message.
        message: String,
    },

    /// Operation is not supported.
    NotSupported {
        /// Description of what's not supported.
        operation: String,
    },

    /// An internal error occurred.
    Internal {
        /// Description of the error.
        message: String,
    },
}

impl fmt::Display for StorageError {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IoError { context, source } => write!(f, "I/O error during {context}: {source}"),
            Self::InvalidMagic { expected, found } => {
                write!(f, "invalid magic bytes: expected {expected:?}, found {found:?}")
            }
            Self::InvalidVersion { expected, found } => {
                write!(f, "invalid format version: expected {expected}, found {found}")
            }
            Self::ChecksumMismatch { context } => write!(f, "checksum mismatch: {context}"),
            Self::CorruptedData { context } => write!(f, "corrupted data: {context}"),
            Self::InvalidInput { parameter, reason } => {
                write!(f, "invalid input '{parameter}': {reason}")
            }
            Self::UnexpectedEof { context } => write!(f, "unexpected end of data: {context}"),
            Self::DecryptionFailed { context } => write!(f, "decryption failed: {context}"),
            Self::EncryptionFailed { context } => write!(f, "encryption failed: {context}"),
            Self::KeyDerivationFailed { context } => write!(f, "key derivation failed: {context}"),
            Self::NoValidSuperblock => write!(f, "no valid superblock found in vault file"),
            Self::TransactionFailed { reason } => write!(f, "transaction failed: {reason}"),
            Self::VaultLocked => write!(f, "vault is locked by another process"),
            Self::VaultNotInitialized => write!(f, "vault file is not initialized"),
            Self::AccountNotFound { account_id } => write!(f, "account not found: {account_id}"),
            Self::AccountAlreadyExists { account_id } => {
                write!(f, "account already exists: {account_id}")
            }
            Self::CredentialNotFound { credential_id } => {
                write!(f, "credential not found: {credential_id}")
            }
            Self::BlobNotFound { content_id } => write!(f, "blob not found: {content_id}"),
            Self::NullifierAlreadyConsumed => write!(f, "nullifier has already been consumed"),
            Self::ActionAlreadyPending { action_scope } => {
                write!(f, "action already pending for scope: {}", hex::encode(action_scope))
            }
            Self::PendingActionNotFound { action_scope } => {
                write!(f, "pending action not found for scope: {}", hex::encode(action_scope))
            }
            Self::PendingActionStoreFull => write!(f, "pending action store is at capacity"),
            Self::AccountIdMismatch { expected, found } => {
                write!(f, "account ID mismatch: expected {expected}, found {found}")
            }
            Self::InvalidTransfer { reason } => write!(f, "invalid transfer data: {reason}"),
            Self::KeystoreError { message } => write!(f, "keystore error: {message}"),
            Self::LockError { message } => write!(f, "lock error: {message}"),
            Self::SerializationError { message } => write!(f, "serialization error: {message}"),
            Self::DeserializationError { message } => {
                write!(f, "deserialization error: {message}")
            }
            Self::NotSupported { operation } => write!(f, "operation not supported: {operation}"),
            Self::Internal { message } => write!(f, "internal error: {message}"),
        }
    }
}

impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IoError { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<std::io::Error> for StorageError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError {
            context: "unspecified".to_string(),
            source: err,
        }
    }
}

impl StorageError {
    /// Creates an I/O error with context.
    pub fn io<S: Into<String>>(context: S, source: std::io::Error) -> Self {
        Self::IoError {
            context: context.into(),
            source,
        }
    }

    /// Creates a corrupted data error.
    pub fn corrupted<S: Into<String>>(context: S) -> Self {
        Self::CorruptedData {
            context: context.into(),
        }
    }

    /// Creates an invalid input error.
    pub fn invalid_input<P: Into<String>, R: Into<String>>(parameter: P, reason: R) -> Self {
        Self::InvalidInput {
            parameter: parameter.into(),
            reason: reason.into(),
        }
    }

    /// Creates a decryption failed error.
    pub fn decryption<S: Into<String>>(context: S) -> Self {
        Self::DecryptionFailed {
            context: context.into(),
        }
    }

    /// Creates an encryption failed error.
    pub fn encryption<S: Into<String>>(context: S) -> Self {
        Self::EncryptionFailed {
            context: context.into(),
        }
    }

    /// Creates a serialization error.
    pub fn serialization<S: Into<String>>(message: S) -> Self {
        Self::SerializationError {
            message: message.into(),
        }
    }

    /// Creates a deserialization error.
    pub fn deserialization<S: Into<String>>(message: S) -> Self {
        Self::DeserializationError {
            message: message.into(),
        }
    }

    /// Creates a transaction failed error.
    pub fn transaction<S: Into<String>>(reason: S) -> Self {
        Self::TransactionFailed {
            reason: reason.into(),
        }
    }

    /// Creates an internal error.
    pub fn internal<S: Into<String>>(message: S) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }

    /// Creates a keystore error.
    pub fn keystore<S: Into<String>>(message: S) -> Self {
        Self::KeystoreError {
            message: message.into(),
        }
    }

    /// Creates a lock error.
    pub fn lock<S: Into<String>>(message: S) -> Self {
        Self::LockError {
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = StorageError::InvalidMagic {
            expected: b"WIDVAULT",
            found: vec![0, 1, 2, 3],
        };
        assert!(format!("{err}").contains("invalid magic bytes"));
        let err = StorageError::AccountNotFound {
            account_id: AccountId::new([0x42; 32]),
        };
        assert!(format!("{err}").contains("account not found"));
        let err = StorageError::NullifierAlreadyConsumed;
        assert!(format!("{err}").contains("nullifier has already been consumed"));
    }
}
