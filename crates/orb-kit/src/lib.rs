//! OrbKit — Orb-based credential issuer for the host-mediated Issuers SDK experiment.
//!
//! `OrbIssuer` simulates the Orb hardware issuance pathway (see `orb_relay` and
//! `pop_backend_api` in oxide). In a real implementation it would perform a ZKP
//! authentication handshake with the Orb relay service before minting a signed
//! SD-JWT credential.
//!
//! `OrbIssuer` implements [`issuer_sdk::IssuerDriver`] directly, so it can be
//! used from Rust-native code that holds an `Arc<dyn IssuerDriver>` without
//! going through the Python adapter layer.

use issuer_sdk::{build_credential_json, parse_request_json, IssuerDriver, SdkError};
use thiserror::Error;

/// Errors returned by the Orb issuer's async pathway.
#[derive(Debug, Error, uniffi::Error)]
pub enum OrbKitError {
    /// Shared SDK model or JSON error.
    #[error("issuer-sdk error: {0}")]
    Sdk(String),
}

impl From<SdkError> for OrbKitError {
    fn from(error: SdkError) -> Self {
        Self::Sdk(error.to_string())
    }
}

/// Issuer that mints credentials via the Orb hardware device.
///
/// Corresponds to the `NfcBackend` / Orb relay pathway in oxide.
#[derive(uniffi::Object)]
pub struct OrbIssuer;

impl Default for OrbIssuer {
    fn default() -> Self {
        Self::new()
    }
}

// ── Synchronous IssuerDriver impl (Rust-native / host-mediated path) ──────────

/// Implement [`IssuerDriver`] so `OrbIssuer` can be registered directly with
/// an `IssuerHost` from Rust-native code.
///
/// Internally blocks on the async pathway using the current Tokio runtime
/// handle.  This is safe when called from `tokio::task::spawn_blocking`, which
/// is how `IssuerHost::fetch_credential_with` invokes the driver.
impl IssuerDriver for OrbIssuer {
    fn fetch_credential(&self, request_json: String) -> Result<String, SdkError> {
        tokio::runtime::Handle::current()
            .block_on(self.fetch_credential_async(request_json))
            .map_err(|e| SdkError::IssuanceFailed(e.to_string()))
    }
}

// ── Async UniFFI export (Python / Swift / Kotlin adapter path) ────────────────

#[uniffi::export(async_runtime = "tokio")]
impl OrbIssuer {
    /// Creates a new `OrbIssuer`.
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self
    }

    /// Fetches a credential using the Orb issuance pathway (async).
    ///
    /// In production this would:
    /// 1. Generate a ZKP proof (`generate_auth_proof` in oxide).
    /// 2. Exchange it with the PoP backend API for a signed credential.
    /// 3. Return the decoded `IdentityCredential`.
    ///
    /// # Errors
    ///
    /// Returns an error if the request JSON is invalid.
    pub async fn fetch_credential_async(
        &self,
        request_json: String,
    ) -> Result<String, OrbKitError> {
        // Simulate network latency for the Orb relay handshake.
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;

        let request = parse_request_json(&request_json)?;

        // Stub credential — in production this would be a signed SD-JWT.
        let credential_id = uuid::Uuid::new_v4().to_string();
        let stub_data = format!(
            "eyJhbGciOiJFUzI1NiIsInR5cCI6IlNELUpXVCJ9.stub.orb.{}",
            request.user_id
        );

        build_credential_json(&credential_id, "orb-kit", stub_data).map_err(Into::into)
    }
}

uniffi::setup_scaffolding!("orb_kit");

#[cfg(test)]
mod tests {
    use super::OrbIssuer;
    use issuer_sdk::{Credential, IssuerDriver};

    #[tokio::test(flavor = "multi_thread")]
    async fn issues_orb_credential_async() {
        let issuer = OrbIssuer::new();
        let request_json = r#"{"user_id":"user-abc"}"#.to_string();
        let response = issuer
            .fetch_credential_async(request_json)
            .await
            .expect("should issue credential");

        let cred: Credential = serde_json::from_str(&response).expect("should parse credential");
        assert_eq!(cred.issuer, "orb-kit");
        assert!(cred.data.contains("user-abc"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn rejects_blank_user_id_async() {
        let issuer = OrbIssuer::new();
        let request_json = r#"{"user_id":""}"#.to_string();
        assert!(issuer.fetch_credential_async(request_json).await.is_err());
    }

    /// Verify the synchronous `IssuerDriver` impl works from a blocking
    /// context inside a multi-thread Tokio runtime (mirrors `spawn_blocking`).
    #[tokio::test(flavor = "multi_thread")]
    async fn issues_orb_credential_via_driver_trait() {
        let issuer = OrbIssuer::new();
        let request_json = r#"{"user_id":"user-driver"}"#.to_string();

        // block_in_place lets us call block_on from within an async context.
        let response = tokio::task::block_in_place(|| {
            issuer.fetch_credential(request_json)
        })
        .expect("IssuerDriver::fetch_credential should succeed");

        let cred: Credential = serde_json::from_str(&response).expect("should parse credential");
        assert_eq!(cred.issuer, "orb-kit");
        assert!(cred.data.contains("user-driver"));
    }
}
