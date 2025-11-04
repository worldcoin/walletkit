use thiserror::Error;

/// Error outputs from `WalletKit`
#[derive(Debug, Error, uniffi::Error)]
pub enum WalletKitError {
    /// The presented input is not valid for the requested operation
    #[error("invalid_input")]
    InvalidInput,

    /// The presented data is not a valid U256 integer
    #[error("invalid_number")]
    InvalidNumber,

    /// Unexpected error serializing information
    #[error("serialization_error")]
    SerializationError {
        /// The error message from the serialization
        error: String,
    },

    /// Network connection error with details
    #[error("network_error")]
    NetworkError {
        /// The URL of the request
        url: String,
        /// The error message from the request
        error: String,
        /// The HTTP status code of the request, if available
        status: Option<u16>,
    },

    /// HTTP request failure
    #[error("request_error")]
    Reqwest {
        /// The error message from the request
        error: String,
    },

    /// Unhandled error generating a Zero-Knowledge Proof
    #[error("proof_generation_error")]
    ProofGeneration {
        /// The error message from the proof generation
        error: String,
    },

    /// The `semaphore` feature flag is not enabled
    #[error("semaphore_not_enabled")]
    SemaphoreNotEnabled,

    /// The requested credential is not issued for this World ID
    #[error("credential_not_issued")]
    CredentialNotIssued,

    /// The requested credential has not been submitted on-chain
    #[error("credential_not_mined")]
    CredentialNotMined,

    /// This operation requires a registered account and an account is not registered
    /// for this authenticator. Call `create_account` first to register it.
    #[error("Account is not registered for this authenticator.")]
    AccountDoesNotExist,

    /// The account already exists for this authenticator. Call `account_index` to get the account index.
    #[error("Account already exists for this authenticator.")]
    AccountAlreadyExists,

    /// An unexpected error occurred with the Authenticator
    #[error("unexpected_authenticator_error")]
    AuthenticatorError {
        /// The error message from the authenticator
        error: String,
    },
}

impl From<reqwest::Error> for WalletKitError {
    fn from(error: reqwest::Error) -> Self {
        Self::Reqwest {
            error: error.to_string(),
        }
    }
}

impl From<semaphore_rs::protocol::ProofError> for WalletKitError {
    fn from(error: semaphore_rs::protocol::ProofError) -> Self {
        Self::ProofGeneration {
            error: error.to_string(),
        }
    }
}

#[cfg(feature = "v4")]
impl From<&world_id_core::AuthenticatorError> for WalletKitError {
    fn from(error: &world_id_core::AuthenticatorError) -> Self {
        match error {
            world_id_core::AuthenticatorError::AccountDoesNotExist => {
                Self::AccountDoesNotExist
            }
            world_id_core::AuthenticatorError::AccountAlreadyExists => {
                Self::AccountAlreadyExists
            }
        }
    }
}
