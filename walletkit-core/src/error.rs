use thiserror::Error;

use world_id_core::primitives::PrimitiveError;

#[cfg(feature = "storage")]
use crate::storage::StorageError;
use world_id_core::AuthenticatorError;

/// Error outputs from `WalletKit`
#[derive(Debug, Error, uniffi::Error)]
pub enum WalletKitError {
    /// Invalid input provided (e.g., incorrect length, format, etc.)
    #[error("invalid_input_{attribute}")]
    InvalidInput {
        /// The attribute that is invalid
        attribute: String,
        /// The reason the input is invalid
        reason: String,
    },

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
    #[error("network_error at {url}: {error}")]
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

    /// The public key was not found in the batch, i.e. the authenticator is not authorized to sign for this action
    #[error("unauthorized_authenticator")]
    UnauthorizedAuthenticator,

    /// An unexpected error occurred with the Authenticator
    #[error("unexpected_authenticator_error")]
    AuthenticatorError {
        /// The error message from the authenticator
        error: String,
    },

    /// An unexpected error occurred
    #[error("unexpected_error: {error}")]
    Generic {
        /// The details of the error
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

impl From<PrimitiveError> for WalletKitError {
    fn from(error: PrimitiveError) -> Self {
        match error {
            PrimitiveError::InvalidInput { attribute, reason } => {
                Self::InvalidInput { attribute, reason }
            }
            PrimitiveError::Serialization(error) => Self::SerializationError { error },
            PrimitiveError::Deserialization(reason) => Self::InvalidInput {
                attribute: "deserialization".to_string(),
                reason,
            },
            PrimitiveError::NotInField => Self::InvalidInput {
                attribute: "field_element".to_string(),
                reason: "Provided value is not in the field".to_string(),
            },
            PrimitiveError::OutOfBounds => Self::InvalidInput {
                attribute: "index".to_string(),
                reason: "Provided index is out of bounds".to_string(),
            },
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

#[cfg(feature = "storage")]
impl From<StorageError> for WalletKitError {
    fn from(error: StorageError) -> Self {
        Self::Generic {
            error: error.to_string(),
        }
    }
}

impl From<AuthenticatorError> for WalletKitError {
    fn from(error: AuthenticatorError) -> Self {
        match error {
            AuthenticatorError::AccountDoesNotExist => Self::AccountDoesNotExist,
            AuthenticatorError::AccountAlreadyExists => Self::AccountAlreadyExists,

            AuthenticatorError::NetworkError(error) => Self::NetworkError {
                url: error
                    .url()
                    .map(std::string::ToString::to_string)
                    .unwrap_or_default(),
                error: error.to_string(),
                status: None,
            },
            AuthenticatorError::PublicKeyNotFound => Self::UnauthorizedAuthenticator,
            AuthenticatorError::GatewayError { status, body } => Self::NetworkError {
                url: "gateway".to_string(),
                error: body,
                status: Some(status.as_u16()),
            },
            AuthenticatorError::PrimitiveError(error) => Self::from(error),

            _ => Self::AuthenticatorError {
                error: error.to_string(),
            },
        }
    }
}
