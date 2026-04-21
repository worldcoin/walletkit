//! NfcKit — NFC identity-document credential issuer for the host-mediated Issuers SDK experiment.
//!
//! `NfcIssuer` simulates the NFC uniqueness-service issuance pathway (see
//! `NfcBackend` / `nfc_backend_api` in oxide). In a real implementation it
//! would decrypt the Personal Custody Package (PCP), verify the NFC document
//! data, and return a signed SD-JWT credential.
//!
//! `NfcIssuer` implements [`issuer_sdk::IssuerDriver`] directly, so it can be
//! used from Rust-native code that holds an `Arc<dyn IssuerDriver>` without
//! going through the Python adapter layer.

use issuer_sdk::{build_credential_json, parse_request_json, IssuerDriver, SdkError};
use thiserror::Error;

/// Errors returned by the NFC issuer's async pathway.
#[derive(Debug, Error, uniffi::Error)]
pub enum NfcKitError {
    /// Shared SDK model or JSON error.
    #[error("issuer-sdk error: {0}")]
    Sdk(String),
}

impl From<SdkError> for NfcKitError {
    fn from(error: SdkError) -> Self {
        Self::Sdk(error.to_string())
    }
}

/// Issuer that mints credentials via an NFC identity document.
///
/// Corresponds to the `NfcBackend` in oxide which interacts with the
/// NFC uniqueness service to verify passport / identity-card data.
#[derive(uniffi::Object)]
pub struct NfcIssuer;

impl Default for NfcIssuer {
    fn default() -> Self {
        Self::new()
    }
}

// ── Synchronous IssuerDriver impl (Rust-native / host-mediated path) ──────────

/// Implement [`IssuerDriver`] so `NfcIssuer` can be registered directly with
/// an `IssuerHost` from Rust-native code.
///
/// Internally blocks on the async pathway using the current Tokio runtime
/// handle.  This is safe when called from `tokio::task::spawn_blocking`, which
/// is how `IssuerHost::fetch_credential_with` invokes the driver.
impl IssuerDriver for NfcIssuer {
    fn fetch_credential(&self, request_json: String) -> Result<String, SdkError> {
        tokio::runtime::Handle::current()
            .block_on(self.fetch_credential_async(request_json))
            .map_err(|e| SdkError::IssuanceFailed(e.to_string()))
    }
}

// ── Async UniFFI export (Python / Swift / Kotlin adapter path) ────────────────

#[uniffi::export(async_runtime = "tokio")]
impl NfcIssuer {
    /// Creates a new `NfcIssuer`.
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self
    }

    /// Fetches a credential using the NFC document issuance pathway (async).
    ///
    /// In production this would:
    /// 1. Load and decrypt the Personal Custody Package (PCP) from device storage.
    /// 2. Call `/v2/decrypt-pcp-keys` on the NFC uniqueness service.
    /// 3. Unseal the identity credential and decode the SD-JWT.
    /// 4. Return the decoded `IdentityCredential`.
    ///
    /// # Errors
    ///
    /// Returns an error if the request JSON is invalid.
    pub async fn fetch_credential_async(
        &self,
        request_json: String,
    ) -> Result<String, NfcKitError> {
        // Simulate NFC document read + network round-trip latency.
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;

        let request = parse_request_json(&request_json)?;

        // Stub credential — in production this would be an unsealed SD-JWT
        // extracted from the NFC Personal Custody Package.
        let credential_id = uuid::Uuid::new_v4().to_string();
        let stub_data = format!(
            "eyJhbGciOiJFUzI1NiIsInR5cCI6IlNELUpXVCJ9.stub.nfc.{}",
            request.user_id
        );

        build_credential_json(&credential_id, "nfc-kit", stub_data).map_err(Into::into)
    }
}

uniffi::setup_scaffolding!("nfc_kit");

#[cfg(test)]
mod tests {
    use super::NfcIssuer;
    use issuer_sdk::{Credential, IssuerDriver};

    #[tokio::test(flavor = "multi_thread")]
    async fn issues_nfc_credential_async() {
        let issuer = NfcIssuer::new();
        let request_json = r#"{"user_id":"user-xyz"}"#.to_string();
        let response = issuer
            .fetch_credential_async(request_json)
            .await
            .expect("should issue credential");

        let cred: Credential = serde_json::from_str(&response).expect("should parse credential");
        assert_eq!(cred.issuer, "nfc-kit");
        assert!(cred.data.contains("user-xyz"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn rejects_blank_user_id_async() {
        let issuer = NfcIssuer::new();
        let request_json = r#"{"user_id":""}"#.to_string();
        assert!(issuer.fetch_credential_async(request_json).await.is_err());
    }

    /// Verify the synchronous `IssuerDriver` impl works from a blocking
    /// context inside a multi-thread Tokio runtime (mirrors `spawn_blocking`).
    #[tokio::test(flavor = "multi_thread")]
    async fn issues_nfc_credential_via_driver_trait() {
        let issuer = NfcIssuer::new();
        let request_json = r#"{"user_id":"user-driver"}"#.to_string();

        // block_in_place lets us call block_on from within an async context.
        let response = tokio::task::block_in_place(|| {
            issuer.fetch_credential(request_json)
        })
        .expect("IssuerDriver::fetch_credential should succeed");

        let cred: Credential = serde_json::from_str(&response).expect("should parse credential");
        assert_eq!(cred.issuer, "nfc-kit");
        assert!(cred.data.contains("user-driver"));
    }
}
