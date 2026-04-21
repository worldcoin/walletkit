//! Shared credential types and JSON helpers for the host-mediated
//! Issuers SDK experiment.
//!
//! This crate defines the domain model used by both the issuer
//! implementations (`orb-kit`, `nfc-kit`) and the host (`issuer-host`).
//! It is compiled as a source dependency — not a cross-binary ABI.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;

/// Result type used across the shared SDK crate.
pub type SdkResult<T> = Result<T, SdkError>;

// ──────────────────────────────────────────────────────────────────────────────
// Domain types
// ──────────────────────────────────────────────────────────────────────────────

/// Type of issuer being requested.
///
/// Inspired by the Orb relay and NFC uniqueness-service pathways found in oxide.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuerType {
    /// World ID credential issued via the Orb hardware device.
    Orb,
    /// World ID credential issued via an NFC identity document.
    Nfc,
}

/// Request sent from the host to a credential issuer.
///
/// Loosely modelled on the PoP / NFC backend request patterns in oxide:
/// the host identifies the subject and the desired issuance pathway.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRequest {
    /// Opaque identifier for the subject requesting a credential.
    /// In production this would be a nullifier hash or World ID commitment.
    pub user_id: String,
    /// Which issuer pathway to use.
    pub issuer_type: IssuerType,
}

/// Credential returned by an issuer.
///
/// In production this would carry a signed SD-JWT or similar structure
/// (see `IdentityCredential` in oxide). Here we keep it simple for the demo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    /// Opaque credential identifier (e.g. UUID).
    pub id: String,
    /// Name of the issuer that produced this credential.
    pub issuer: String,
    /// Encoded credential payload (SD-JWT stub in this demo).
    pub data: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// Error type
// ──────────────────────────────────────────────────────────────────────────────

/// Shared validation and serialization errors.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SdkError {
    /// JSON could not be parsed or serialized.
    #[error("invalid json: {0}")]
    InvalidJson(String),
    /// The `user_id` field was blank after trimming whitespace.
    #[error("user_id must not be empty")]
    EmptyUserId,
}

// ──────────────────────────────────────────────────────────────────────────────
// JSON helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Serializes any serde-compatible value into JSON.
pub fn to_json<T>(value: &T) -> SdkResult<String>
where
    T: Serialize,
{
    serde_json::to_string(value).map_err(|error| SdkError::InvalidJson(error.to_string()))
}

/// Parses any serde-compatible value from JSON.
pub fn from_json<T>(json: &str) -> SdkResult<T>
where
    T: DeserializeOwned,
{
    serde_json::from_str(json).map_err(|error| SdkError::InvalidJson(error.to_string()))
}

// ──────────────────────────────────────────────────────────────────────────────
// Request helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Validates a credential request.
pub fn validate_request(request: &CredentialRequest) -> SdkResult<()> {
    if request.user_id.trim().is_empty() {
        return Err(SdkError::EmptyUserId);
    }
    Ok(())
}

/// Parses and validates a [`CredentialRequest`] from JSON.
pub fn parse_request_json(json: &str) -> SdkResult<CredentialRequest> {
    let request: CredentialRequest = from_json(json)?;
    validate_request(&request)?;
    Ok(request)
}

/// Builds a [`Credential`] and serializes it to JSON.
pub fn build_credential_json(id: &str, issuer: &str, data: String) -> SdkResult<String> {
    to_json(&Credential {
        id: id.to_string(),
        issuer: issuer.to_string(),
        data,
    })
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn orb_request_json() -> &'static str {
        r#"{"user_id":"user-abc","issuer_type":"orb"}"#
    }

    #[test]
    fn parses_valid_orb_request() {
        let req = parse_request_json(orb_request_json()).expect("request should parse");
        assert_eq!(req.user_id, "user-abc");
        assert_eq!(req.issuer_type, IssuerType::Orb);
    }

    #[test]
    fn parses_valid_nfc_request() {
        let json = r#"{"user_id":"user-xyz","issuer_type":"nfc"}"#;
        let req = parse_request_json(json).expect("request should parse");
        assert_eq!(req.issuer_type, IssuerType::Nfc);
    }

    #[test]
    fn rejects_blank_user_id() {
        let json = r#"{"user_id":"   ","issuer_type":"orb"}"#;
        let error = parse_request_json(json).expect_err("blank user_id should fail");
        assert_eq!(error, SdkError::EmptyUserId);
    }

    #[test]
    fn builds_credential_json() {
        let json = build_credential_json("cred-1", "orb-kit", "stub-data".to_string())
            .expect("credential should serialize");
        let cred: Credential = serde_json::from_str(&json).expect("json should parse");
        assert_eq!(cred.issuer, "orb-kit");
        assert_eq!(cred.data, "stub-data");
    }
}
