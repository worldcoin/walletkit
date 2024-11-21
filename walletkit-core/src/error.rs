use thiserror::Error;

#[derive(Debug, Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum Error {
    #[error("fetching_inclusion_proof_failed")]
    FetchingInclusionProofFailed,
}
