use thiserror::Error;

/// Error outputs from `WalletKit`
#[derive(Debug, Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum Error {
    /// The presented input is not valid for the requested operation
    #[error("invalid_input")]
    InvalidInput,
    /// The presented data is not a valid U256 integer
    #[error("invalid_number")]
    InvalidNumber,
    /// Unexpected error serializing information
    #[error("serialization_error")]
    SerializationError,
    /// HTTP request failure
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    /// Unhandled error generating a Zero-Knowledge Proof
    #[error(transparent)]
    ProofGeneration(#[from] semaphore::protocol::ProofError),
}
