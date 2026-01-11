//! FFI-safe error types for credential storage.
//!
//! This module provides error types that can be exported across the FFI boundary
//! to Swift and Kotlin using UniFFI.

use crate::credential_storage::StorageError as InternalStorageError;

/// Error type for credential storage operations.
///
/// This enum provides FFI-safe error variants that can be easily
/// represented in Swift and Kotlin.
#[derive(Debug, Clone, uniffi::Error, thiserror::Error)]
#[uniffi(flat_error)]
pub enum StorageError {
    /// I/O error (file operations).
    #[error("I/O error: {message}")]
    IoError {
        /// Error message.
        message: String,
    },

    /// Cryptographic operation failed.
    #[error("Crypto error: {message}")]
    CryptoError {
        /// Error message.
        message: String,
    },

    /// Data format or corruption error.
    #[error("Format error: {message}")]
    FormatError {
        /// Error message.
        message: String,
    },

    /// Account not found.
    #[error("Account not found: {account_id}")]
    AccountNotFound {
        /// The account ID that was not found (hex string).
        account_id: String,
    },

    /// Account already exists.
    #[error("Account already exists: {account_id}")]
    AccountAlreadyExists {
        /// The account ID that already exists (hex string).
        account_id: String,
    },

    /// Credential not found.
    #[error("Credential not found: {credential_id}")]
    CredentialNotFound {
        /// The credential ID that was not found (hex string).
        credential_id: String,
    },

    /// Invalid input parameter.
    #[error("Invalid input: {parameter} - {message}")]
    InvalidInput {
        /// Parameter name.
        parameter: String,
        /// Error message.
        message: String,
    },

    /// Lock acquisition failed.
    #[error("Lock error: {message}")]
    LockError {
        /// Error message.
        message: String,
    },

    /// Nullifier already consumed.
    #[error("Nullifier already consumed")]
    NullifierConsumed,

    /// Action already pending.
    #[error("Action already pending")]
    ActionPending,

    /// Pending action not found.
    #[error("Pending action not found")]
    PendingActionNotFound,

    /// Pending action store is full.
    #[error("Pending action store is full")]
    PendingStoreFull,

    /// Platform-specific error.
    #[error("Platform error: {message}")]
    PlatformError {
        /// Error message.
        message: String,
    },

    /// Generic error (catch-all for unexpected errors).
    #[error("Generic error: {error_message}")]
    Generic {
        /// The error message.
        error_message: String,
    },
}

impl From<InternalStorageError> for StorageError {
    fn from(error: InternalStorageError) -> Self {
        match error {
            InternalStorageError::IoError { context, .. } => {
                StorageError::IoError { message: context }
            }

            InternalStorageError::EncryptionFailed { context } => {
                StorageError::CryptoError { message: context }
            }
            InternalStorageError::DecryptionFailed { context } => {
                StorageError::CryptoError { message: context }
            }
            InternalStorageError::KeyDerivationFailed { context } => {
                StorageError::CryptoError { message: context }
            }

            InternalStorageError::InvalidMagic { .. }
            | InternalStorageError::InvalidVersion { .. }
            | InternalStorageError::ChecksumMismatch { .. }
            | InternalStorageError::CorruptedData { .. }
            | InternalStorageError::UnexpectedEof { .. } => StorageError::FormatError {
                message: error.to_string(),
            },

            InternalStorageError::AccountNotFound { account_id } => StorageError::AccountNotFound {
                account_id: account_id.to_string(),
            },
            InternalStorageError::AccountAlreadyExists { account_id } => {
                StorageError::AccountAlreadyExists {
                    account_id: account_id.to_string(),
                }
            }
            InternalStorageError::AccountIdMismatch { expected, found } => {
                StorageError::FormatError {
                    message: format!("Account ID mismatch: expected {expected}, found {found}"),
                }
            }

            InternalStorageError::CredentialNotFound { credential_id } => {
                StorageError::CredentialNotFound {
                    credential_id: credential_id.to_string(),
                }
            }
            InternalStorageError::BlobNotFound { content_id } => StorageError::FormatError {
                message: format!("Blob not found: {content_id}"),
            },

            InternalStorageError::InvalidInput { parameter, reason } => StorageError::InvalidInput {
                parameter,
                message: reason,
            },

            InternalStorageError::LockError { message } => StorageError::LockError { message },

            InternalStorageError::ActionAlreadyPending { .. } => StorageError::ActionPending,

            InternalStorageError::PendingActionNotFound { .. } => {
                StorageError::PendingActionNotFound
            }

            InternalStorageError::KeystoreError { message } => {
                StorageError::PlatformError { message }
            }

            InternalStorageError::SerializationError { message }
            | InternalStorageError::DeserializationError { message } => {
                StorageError::Generic { error_message: message }
            }

            InternalStorageError::TransactionFailed { reason } => {
                StorageError::Generic { error_message: reason }
            }

            InternalStorageError::InvalidTransfer { reason } => {
                StorageError::FormatError { message: reason }
            }

            InternalStorageError::NotSupported { operation } => StorageError::Generic {
                error_message: format!("Not supported: {operation}"),
            },

            InternalStorageError::Internal { message } => {
                StorageError::Generic { error_message: message }
            }

            InternalStorageError::NoValidSuperblock => StorageError::FormatError {
                message: "No valid superblock found".to_string(),
            },

            InternalStorageError::VaultLocked => StorageError::LockError {
                message: "Vault is locked".to_string(),
            },

            InternalStorageError::VaultNotInitialized => StorageError::FormatError {
                message: "Vault is not initialized".to_string(),
            },

            InternalStorageError::NullifierAlreadyConsumed => StorageError::NullifierConsumed,

            InternalStorageError::PendingActionStoreFull => StorageError::PendingStoreFull,
        }
    }
}

/// Result type for FFI operations.
pub type Result<T> = std::result::Result<T, StorageError>;
