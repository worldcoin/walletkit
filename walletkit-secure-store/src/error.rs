//! Error type for `walletkit-secure-store` primitives.

use thiserror::Error;
use walletkit_db::DbError;

/// Result alias for [`StoreError`].
pub type StoreResult<T> = Result<T, StoreError>;

/// Errors produced by the primitives in this crate.
///
/// Consumers typically wrap this in a richer error enum at their boundary
/// (e.g. `walletkit-core`'s `StorageError`) so the `uniffi` surface stays
/// under their control.
#[derive(Debug, Error)]
pub enum StoreError {
    /// Errors coming from the device keystore.
    #[error("keystore error: {0}")]
    Keystore(String),

    /// Errors coming from the atomic blob store.
    #[error("blob store error: {0}")]
    BlobStore(String),

    /// Errors coming from the cross-process lock.
    #[error("lock error: {0}")]
    Lock(String),

    /// Serialization or deserialization failures (e.g. CBOR envelope).
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Cryptographic failures (AEAD, HKDF, etc.).
    #[error("crypto error: {0}")]
    Crypto(String),

    /// Invalid or malformed envelope.
    #[error("invalid envelope: {0}")]
    InvalidEnvelope(String),

    /// Unsupported envelope version.
    #[error("unsupported envelope version: {0}")]
    UnsupportedEnvelopeVersion(u32),

    /// Errors coming from the underlying database.
    #[error("db error: {0}")]
    Db(String),

    /// Database integrity check failed.
    #[error("integrity check failed: {0}")]
    IntegrityCheckFailed(String),
}

impl From<DbError> for StoreError {
    fn from(err: DbError) -> Self {
        Self::Db(err.to_string())
    }
}
