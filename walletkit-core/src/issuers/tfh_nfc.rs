//! TFH NFC credential issuer (passport, eID, MNC).
use crate::Credential;
use crate::{error::WalletKitError, http_request::Request, Environment};

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use std::collections::HashMap;

/// Response from NFC refresh endpoint
#[derive(Debug, Clone, Deserialize)]
struct NfcRefreshResponse {
    result: NfcRefreshResultRaw,
}

/// Raw credential wrapper (base64-encoded JSON)
#[derive(Debug, Clone, Deserialize)]
struct NfcRefreshResultRaw {
    credential: String,
}

impl NfcRefreshResultRaw {
    fn parse(&self) -> Result<Credential, WalletKitError> {
        let credential_bytes = STANDARD.decode(&self.credential).map_err(|e| {
            WalletKitError::SerializationError {
                error: format!("Failed to decode NFC base64 credential: {e}"),
            }
        })?;

        Credential::from_bytes(credential_bytes).map_err(|e| {
            WalletKitError::SerializationError {
                error: format!("Failed to deserialize NFC credential: {e}"),
            }
        })
    }
}

/// TFH NFC credential issuer API client
#[derive(uniffi::Object)]
pub struct TfhNfcIssuer {
    base_url: String,
    request: Request,
}

#[uniffi::export]
impl TfhNfcIssuer {
    /// Create a new TFH NFC issuer for the specified environment
    #[uniffi::constructor]
    #[must_use]
    pub fn new(environment: &Environment) -> Self {
        let base_url = match environment {
            Environment::Staging => "https://nfc.stage-crypto.worldcoin.org",
            Environment::Production => "https://nfc.crypto.worldcoin.org",
        }
        .to_string();

        Self {
            base_url,
            request: Request::new(),
        }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl TfhNfcIssuer {
    /// Refresh an NFC credential (migrate PCP to v4).
    ///
    /// Calls the `/v2/refresh` endpoint and returns a parsed [`Credential`].
    ///
    /// # Errors
    ///
    /// Returns error on network failure or invalid response.
    pub async fn refresh_nfc_credential(
        &self,
        request_body: &str,
        headers: HashMap<String, String>,
    ) -> Result<Credential, WalletKitError> {
        let url = format!("{}/v2/refresh", self.base_url);

        let mut request_builder = self
            .request
            .post(&url)
            .header("Content-Type", "application/json")
            .body(request_body.to_string());
        for (name, value) in &headers {
            request_builder = request_builder.header(name, value);
        }
        let response = self.request.handle(request_builder).await?;

        let status = response.status();
        if !status.is_success() {
            let error_body = response.text().await.unwrap_or_default();
            return Err(WalletKitError::NetworkError {
                url,
                status: Some(status.as_u16()),
                error: format!("NFC refresh failed: {error_body}"),
            });
        }

        let refresh_response: NfcRefreshResponse =
            response
                .json()
                .await
                .map_err(|e| WalletKitError::SerializationError {
                    error: format!("Failed to parse NFC refresh response: {e}"),
                })?;

        refresh_response.result.parse()
    }
}

#[cfg(test)]
impl TfhNfcIssuer {
    /// Create an issuer with a custom base URL (for testing).
    #[must_use]
    pub fn with_base_url(base_url: &str) -> Self {
        Self {
            base_url: base_url.to_string(),
            request: Request::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_staging_url() {
        let issuer = TfhNfcIssuer::new(&Environment::Staging);
        assert_eq!(issuer.base_url, "https://nfc.stage-crypto.worldcoin.org");
    }

    #[test]
    fn test_production_url() {
        let issuer = TfhNfcIssuer::new(&Environment::Production);
        assert_eq!(issuer.base_url, "https://nfc.crypto.worldcoin.org");
    }

    #[test]
    fn test_parse_credential() {
        let core_cred = world_id_core::Credential::new();
        let credential_json = serde_json::to_vec(&core_cred).unwrap();
        let credential_base64 = STANDARD.encode(&credential_json);

        let raw = NfcRefreshResultRaw {
            credential: credential_base64,
        };

        let parsed = raw.parse().unwrap();
        assert_eq!(parsed.version, core_cred.version);
        assert_eq!(parsed.issuer_schema_id(), core_cred.issuer_schema_id);
    }

    #[test]
    fn test_parse_credential_invalid_base64() {
        let raw = NfcRefreshResultRaw {
            credential: "not valid base64!!!".to_string(),
        };

        let err = raw.parse().unwrap_err();
        assert!(matches!(err, WalletKitError::SerializationError { .. }));
    }

    #[test]
    fn test_parse_credential_invalid_json() {
        let raw = NfcRefreshResultRaw {
            credential: STANDARD.encode(b"not valid json"),
        };

        let err = raw.parse().unwrap_err();
        assert!(matches!(err, WalletKitError::SerializationError { .. }));
    }
}
