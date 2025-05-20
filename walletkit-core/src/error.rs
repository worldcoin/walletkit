use thiserror::Error;

/// Error outputs from `WalletKit`
#[derive(Debug, Error)]
#[cfg_attr(feature = "ffi", derive(uniffi::Error))]
#[cfg_attr(feature = "ffi", uniffi(flat_error))]
pub enum WalletKitError {
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
    ProofGeneration(#[from] semaphore_rs::protocol::ProofError),
    /// The `semaphore` feature flag is not enabled
    #[error("semaphore_not_enabled")]
    SemaphoreNotEnabled,
}
