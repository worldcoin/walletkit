//! Compatibility entry point for credential preflight checks.
//!
//! New callers can use [`crate::requests::ProofRequest::check_credentials`].
//! The free function and result types remain available for existing consumers.

pub use crate::requests::credential_check::{
    check_credentials_against_proof_request, CredentialConstraintsCheckError,
    CredentialConstraintsCheckItem, CredentialConstraintsCheckResult,
};
