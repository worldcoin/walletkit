use thiserror::Error;

#[derive(Debug, Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum Error {
    #[error("invalid_input")]
    InvalidInput,
    #[error("invalid_number")] // Number is not a valid U256 integer
    InvalidNumber,
    #[error("serialization_error")]
    SerializationError,
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    ProofGeneration(#[from] semaphore::protocol::ProofError),
}
