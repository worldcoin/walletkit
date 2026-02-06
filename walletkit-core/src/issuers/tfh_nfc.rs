//! TFH NFC credential issuer (passport, eID, MNC).

use std::collections::HashMap;

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;

use crate::{error::WalletKitError, request::Request, Environment};

// ============================================================================
// Types
// ============================================================================

/// Response from NFC refresh endpoint.
#[derive(Debug, Clone, Deserialize)]
struct NfcRefreshResponse {
    result: NfcRefreshResultRaw,
}

/// Raw credential wrapper (base64-encoded JSON).
#[derive(Debug, Clone, Deserialize)]
struct NfcRefreshResultRaw {
    credential: String,
}

/// Raw NFC credential blob. Client parses metadata from it.
#[derive(Debug, Clone, uniffi::Record)]
pub struct NfcCredential {
    /// Raw credential bytes (decoded from base64).
    pub credential_blob: Vec<u8>,
}

impl NfcRefreshResultRaw {
    fn parse(&self) -> Result<NfcCredential, WalletKitError> {
        let credential_blob = STANDARD.decode(&self.credential).map_err(|e| {
            WalletKitError::SerializationError {
                error: format!("Failed to decode NFC base64 credential: {e}"),
            }
        })?;

        Ok(NfcCredential { credential_blob })
    }
}

// ============================================================================
// Issuer
// ============================================================================

/// TFH NFC credential issuer API client.
#[derive(uniffi::Object)]
pub struct TfhNfcIssuer {
    base_url: String,
    request: Request,
}

#[uniffi::export(async_runtime = "tokio")]
impl TfhNfcIssuer {
    /// Create a new TFH NFC issuer for the specified environment.
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

    /// Refresh an NFC credential (migrate legacy PCP to v4).
    ///
    /// # Errors
    ///
    /// Returns error on network failure or invalid response.
    pub async fn refresh_nfc_credential(
        &self,
        request_body: &str,
        headers: HashMap<String, String>,
    ) -> Result<NfcCredential, WalletKitError> {
        let url = format!("{}/v2/refresh", self.base_url);

        let headers_vec: Vec<(&str, &str)> =
            headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();

        let response = self.request.post_raw_json(&url, request_body, &headers_vec).await?;

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
            response.json().await.map_err(|e| WalletKitError::SerializationError {
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
        let credential_bytes = b"raw credential data";
        let credential_base64 = STANDARD.encode(credential_bytes);

        let raw = NfcRefreshResultRaw {
            credential: credential_base64,
        };

        let parsed = raw.parse().unwrap();
        assert_eq!(parsed.credential_blob, credential_bytes);
    }

    #[test]
    fn test_parse_credential_invalid_base64() {
        let raw = NfcRefreshResultRaw {
            credential: "not valid base64!!!".to_string(),
        };

        let err = raw.parse().unwrap_err();
        assert!(matches!(err, WalletKitError::SerializationError { .. }));
    }
}
