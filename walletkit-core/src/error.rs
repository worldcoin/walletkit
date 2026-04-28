use thiserror::Error;
use world_id_core::{
    primitives::{oprf::WorldIdRequestAuthError, PrimitiveError},
    AuthenticatorError,
};
use world_id_proof::ProofError;

#[cfg(feature = "storage")]
use crate::storage::StorageError;

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
    #[error("proof_generation_error: {error}")]
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

    /// The public key was not found in the batch, i.e. the authenticator is not authorized to sign for this action
    #[error("unauthorized_authenticator")]
    UnauthorizedAuthenticator,

    /// An unexpected error occurred with the Authenticator
    #[error("unexpected_authenticator_error: {error}")]
    AuthenticatorError {
        /// The error message from the authenticator
        error: String,
    },

    /// The request could not be fulfilled with the credentials the user has available
    #[error("unfulfillable_request")]
    UnfulfillableRequest,

    /// The response generated didn't match the request
    ///
    /// This occurs if the response doesn't match the requested proofs - e.g. by ids
    /// or doesn't satisfy the contraints declared in the request
    #[error("invalid response: {0}")]
    ResponseValidation(String),

    /// The generated nullifier has already been used in a proof submission and cannot be used again
    #[error("nullifier_replay")]
    NullifierReplay,

    /// The RP's signature on the proof request could not be verified.
    #[error("invalid_rp_signature")]
    InvalidRpSignature,

    /// The RP reused a signature nonce.
    #[error("duplicate_nonce")]
    DuplicateNonce,

    /// The RP is unknown to the World ID registry.
    #[error("unknown_rp")]
    UnknownRp,

    /// The RP is inactive and cannot request proofs.
    #[error("inactive_rp")]
    InactiveRp,

    /// The RP's request timestamp is too old.
    #[error("timestamp_too_old")]
    TimestampTooOld,

    /// The RP's request timestamp is too far in the future.
    #[error("timestamp_too_far_in_future")]
    TimestampTooFarInFuture,

    /// The RP's request timestamp could not be parsed.
    #[error("invalid_timestamp")]
    InvalidTimestamp,

    /// The RP's signature has expired.
    #[error("rp_signature_expired")]
    RpSignatureExpired,

    /// Cached Groth16 material could not be parsed or verified.
    #[error("groth16_material_cache_invalid")]
    Groth16MaterialCacheInvalid {
        /// Input path(s) used for loading.
        path: String,
        /// Underlying error message.
        error: String,
    },

    /// Failed to load embedded Groth16 material.
    #[error("groth16_material_embedded_load")]
    Groth16MaterialEmbeddedLoad {
        /// Underlying error message.
        error: String,
    },

    /// An unexpected error occurred
    #[error("unexpected_error: {error}")]
    Generic {
        /// The details of the error
        error: String,
    },

    /// The recovery binding does not exist
    #[error("recovery_binding_does_not_exist")]
    RecoveryBindingDoesNotExist,

    /// The session ID computed for this proof does not match the expected session ID from the proof request.
    ///
    /// This indicates the `session_id` provided by the RP is invalid or compromised, as
    /// the only other failure option is OPRFs not having performed correct computations.
    #[error("the expected session id and the generated session id do not match")]
    SessionIdMismatch,

    /// The NFC uniqueness service rejected the request with a permanent error
    /// that will not resolve on retry (e.g. expired document).
    #[error("nfc_non_retryable: {error_code}")]
    NfcNonRetryable {
        /// The error code from the NFC service (e.g. `document_expired`)
        error_code: String,
    },

    /// The debug report was not found
    #[error("debug_report_not_found")]
    DebugReportNotFound,

    /// The user is not eligible for recovery
    #[error("not_eligible_for_recovery")]
    NotEligibleForRecovery,
    /// An error occurred in the OHTTP privacy layer (relay, encapsulation, or framing).
    #[error("ohttp_error: {error}")]
    OhttpError {
        /// The error message from the OHTTP layer
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

impl From<WorldIdRequestAuthError> for WalletKitError {
    fn from(error: WorldIdRequestAuthError) -> Self {
        match error {
            WorldIdRequestAuthError::InvalidRpSignature => Self::InvalidRpSignature,
            WorldIdRequestAuthError::DuplicateNonce => Self::DuplicateNonce,
            WorldIdRequestAuthError::UnknownRp => Self::UnknownRp,
            WorldIdRequestAuthError::InactiveRp => Self::InactiveRp,
            WorldIdRequestAuthError::TimestampTooOld => Self::TimestampTooOld,
            WorldIdRequestAuthError::TimestampTooFarInFuture => {
                Self::TimestampTooFarInFuture
            }
            WorldIdRequestAuthError::InvalidTimestamp => Self::InvalidTimestamp,
            WorldIdRequestAuthError::RpSignatureExpired => Self::RpSignatureExpired,
            _ => Self::ProofGeneration {
                error: error.to_string(),
            },
        }
    }
}

impl From<ProofError> for WalletKitError {
    fn from(error: ProofError) -> Self {
        match error {
            ProofError::RequestAuthError(error) => Self::from(error),
            _ => Self::ProofGeneration {
                error: error.to_string(),
            },
        }
    }
}

#[cfg(feature = "semaphore")]
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

            AuthenticatorError::ProofError(error) => Self::from(error),

            AuthenticatorError::IndexerError { status, body } => Self::NetworkError {
                url: "indexer".to_string(),
                error: body,
                status: Some(status.as_u16()),
            },
            AuthenticatorError::UnfullfilableRequest => Self::UnfulfillableRequest,
            AuthenticatorError::ResponseValidationError(err) => {
                Self::ResponseValidation(err.to_string())
            }
            AuthenticatorError::SessionIdMismatch => Self::SessionIdMismatch,

            AuthenticatorError::OhttpEncapsulationError(_)
            | AuthenticatorError::BhttpError(_)
            | AuthenticatorError::OhttpRelayError { .. }
            | AuthenticatorError::InvalidServiceResponse(_) => Self::OhttpError {
                error: error.to_string(),
            },

            _ => Self::AuthenticatorError {
                error: error.to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn walletkit_error_from_request_auth_error(
        error: WorldIdRequestAuthError,
    ) -> WalletKitError {
        AuthenticatorError::ProofError(ProofError::RequestAuthError(error)).into()
    }

    fn promoted_error_code(error: &WalletKitError) -> Option<&'static str> {
        match error {
            WalletKitError::InvalidRpSignature => Some("invalid_rp_signature"),
            WalletKitError::DuplicateNonce => Some("duplicate_nonce"),
            WalletKitError::UnknownRp => Some("unknown_rp"),
            WalletKitError::InactiveRp => Some("inactive_rp"),
            WalletKitError::TimestampTooOld => Some("timestamp_too_old"),
            WalletKitError::TimestampTooFarInFuture => {
                Some("timestamp_too_far_in_future")
            }
            WalletKitError::InvalidTimestamp => Some("invalid_timestamp"),
            WalletKitError::RpSignatureExpired => Some("rp_signature_expired"),
            _ => None,
        }
    }

    #[test]
    fn maps_rp_request_auth_errors_to_public_walletkit_errors() {
        let cases = [
            (
                WorldIdRequestAuthError::InvalidRpSignature,
                "invalid_rp_signature",
            ),
            (WorldIdRequestAuthError::DuplicateNonce, "duplicate_nonce"),
            (WorldIdRequestAuthError::UnknownRp, "unknown_rp"),
            (WorldIdRequestAuthError::InactiveRp, "inactive_rp"),
            (
                WorldIdRequestAuthError::TimestampTooOld,
                "timestamp_too_old",
            ),
            (
                WorldIdRequestAuthError::TimestampTooFarInFuture,
                "timestamp_too_far_in_future",
            ),
            (
                WorldIdRequestAuthError::InvalidTimestamp,
                "invalid_timestamp",
            ),
            (
                WorldIdRequestAuthError::RpSignatureExpired,
                "rp_signature_expired",
            ),
        ];

        for (request_auth_error, expected_code) in cases {
            let error = walletkit_error_from_request_auth_error(request_auth_error);

            assert_eq!(promoted_error_code(&error), Some(expected_code));
            assert_eq!(error.to_string(), expected_code);
        }
    }

    #[test]
    fn keeps_non_promoted_request_auth_errors_as_proof_generation_errors() {
        let error = walletkit_error_from_request_auth_error(
            WorldIdRequestAuthError::InvalidMerkleRoot,
        );

        match error {
            WalletKitError::ProofGeneration { error } => {
                assert_eq!(error, "invalid_merkle_root");
            }
            other => panic!("expected proof generation error, got {other:?}"),
        }
    }
}
