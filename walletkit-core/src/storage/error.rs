//! Error types for credential storage components.

use thiserror::Error;

/// Result type for storage operations.
pub type StorageResult<T> = Result<T, StorageError>;

/// Errors raised by credential storage primitives.
#[derive(Debug, Error, uniffi::Error)]
pub enum StorageError {
    /// Errors coming from the device keystore.
    #[error("keystore error: {0}")]
    Keystore(String),

    /// Errors coming from the blob store.
    #[error("blob store error: {0}")]
    BlobStore(String),

    /// Errors coming from the storage lock.
    #[error("storage lock error: {0}")]
    Lock(String),

    /// Serialization/deserialization failures.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Cryptographic failures (AEAD, HKDF, etc.).
    #[error("crypto error: {0}")]
    Crypto(String),

    /// Invalid or malformed account key envelope.
    #[error("invalid envelope: {0}")]
    InvalidEnvelope(String),

    /// Unsupported envelope version.
    #[error("unsupported envelope version: {0}")]
    UnsupportedEnvelopeVersion(u32),

    /// Errors coming from the vault database.
    #[error("vault db error: {0}")]
    VaultDb(String),

    /// Errors coming from the cache database.
    #[error("cache db error: {0}")]
    CacheDb(String),

    /// Leaf index mismatch during initialization.
    #[error("leaf index mismatch: expected {expected}, got {provided}")]
    InvalidLeafIndex {
        /// Leaf index stored in the vault.
        expected: u64,
        /// Leaf index provided by the caller.
        provided: u64,
    },

    /// Vault database integrity check failed.
    #[error("vault integrity check failed: {0}")]
    CorruptedVault(String),

    /// Storage has not been initialized yet.
    #[error("storage not initialized")]
    NotInitialized,

    /// Nullifier already disclosed for a different request.
    #[error("nullifier already disclosed")]
    NullifierAlreadyDisclosed,

    /// Credential not found in the vault.
    #[error("credential not found")]
    CredentialNotFound,

    /// Credential ID not found when deleting from the vault.
    #[error("credential id not found: {credential_id}")]
    CredentialIdNotFound {
        /// Credential ID provided by the caller.
        credential_id: u64,
    },

    /// Corrupted cache entry
    #[error("corrupted cache entry at {key_prefix}")]
    CorruptedCacheEntry {
        /// The prefix of the corrupted cache entry (identifies the type of entry).
        key_prefix: u8,
    },

    /// Unexpected `UniFFI` callback error.
    #[error("unexpected uniffi callback error: {0}")]
    UnexpectedUniFFICallbackError(String),
}

impl From<uniffi::UnexpectedUniFFICallbackError> for StorageError {
    fn from(error: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::UnexpectedUniFFICallbackError(error.reason)
    }
}

impl From<walletkit_db::StoreError> for StorageError {
    fn from(err: walletkit_db::StoreError) -> Self {
        match err {
            walletkit_db::StoreError::Keystore(s) => Self::Keystore(s),
            walletkit_db::StoreError::BlobStore(s) => Self::BlobStore(s),
            walletkit_db::StoreError::Lock(s) => Self::Lock(s),
            walletkit_db::StoreError::Serialization(s) => Self::Serialization(s),
            walletkit_db::StoreError::Crypto(s) => Self::Crypto(s),
            walletkit_db::StoreError::InvalidEnvelope(s) => Self::InvalidEnvelope(s),
            walletkit_db::StoreError::UnsupportedEnvelopeVersion(v) => {
                Self::UnsupportedEnvelopeVersion(v)
            }
            walletkit_db::StoreError::Db(e) => Self::VaultDb(e.to_string()),
            walletkit_db::StoreError::IntegrityCheckFailed(s) => {
                Self::CorruptedVault(s)
            }
        }
    }
}
