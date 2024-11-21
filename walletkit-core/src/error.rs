use thiserror::Error;

#[derive(Debug, Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum Error {
    #[error("fetching_inclusion_proof_failed")]
    FetchingInclusionProofFailed,
    #[error("invalid_hex_string")]
    U256ParsingError(#[from] ruint::ParseError),
}
