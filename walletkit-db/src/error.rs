//! Error types for the storage primitives layer.

use crate::sqlite::Error as DbError;

/// Result alias for [`StoreError`].
pub type StoreResult<T> = Result<T, StoreError>;

/// Errors raised by the storage primitives (vault, blobs, envelope, lock).
///
/// Variants carry a stringified detail rather than a concrete cause to keep
/// the error type cheap to clone and FFI-friendly when consumers wrap it in
/// their own typed error.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// Errors coming from the device keystore.
    #[error("keystore error: {0}")]
    Keystore(String),
    /// Errors coming from the blob store.
    #[error("blob store error: {0}")]
    BlobStore(String),
    /// Errors coming from the storage lock.
    #[error("storage lock error: {0}")]
    Lock(String),
    /// Serialization / deserialization failures (envelope CBOR, etc.).
    #[error("serialization error: {0}")]
    Serialization(String),
    /// Cryptographic failures (AEAD seal/open, RNG, etc.).
    #[error("crypto error: {0}")]
    Crypto(String),
    /// Invalid or malformed key envelope (e.g. wrong length, bad format).
    #[error("invalid envelope: {0}")]
    InvalidEnvelope(String),
    /// Envelope written by an unsupported version.
    #[error("unsupported envelope version: {0}")]
    UnsupportedEnvelopeVersion(u32),
    /// Underlying database error from [`crate::sqlite`].
    #[error("database error: {0}")]
    Db(#[from] DbError),
    /// `PRAGMA integrity_check` reported corruption.
    #[error("integrity check failed: {0}")]
    IntegrityCheckFailed(String),
}
