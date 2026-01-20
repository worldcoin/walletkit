//! Error types for credential storage components.

use thiserror::Error;

/// Result type for storage operations.
pub type StorageResult<T> = Result<T, StorageError>;

/// Errors raised by credential storage primitives.
#[derive(Debug, Error)]
pub enum StorageError {
    /// Errors coming from the device keystore.
    #[error("keystore error: {0}")]
    Keystore(String),

    /// Errors coming from the blob store.
    #[error("blob store error: {0}")]
    BlobStore(String),

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

    /// Nullifier already disclosed for a different request.
    #[error("nullifier already disclosed")]
    NullifierAlreadyDisclosed,

    /// Credential not found in the vault.
    #[error("credential not found")]
    CredentialNotFound,
}
