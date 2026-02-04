use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;

use crate::error::WalletKitError;

/// Response from NFC refresh endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct NfcRefreshResponse {
    pub result: NfcRefreshResultRaw,
}

/// Raw credential wrapper (base64-encoded JSON).
#[derive(Debug, Clone, Deserialize)]
pub struct NfcRefreshResultRaw {
    pub credential: String,
}

/// Parsed NFC credential for storage.
// TODO: Do we need to expose `associated_data_hash` from credential JSON?
#[derive(Debug, Clone, uniffi::Record)]
pub struct NfcCredential {
    /// Credential type (passport, eID, MNC).
    pub issuer_schema_id: u64,
    /// First issuance timestamp.
    pub genesis_issued_at: u64,
    /// Expiration timestamp.
    pub expires_at: u64,
    /// Raw credential bytes for storage.
    pub credential_blob: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct CredentialMetadata {
    issuer_schema_id: u64,
    genesis_issued_at: u64,
    expires_at: u64,
}

impl NfcRefreshResultRaw {
    pub(crate) fn parse(&self) -> Result<NfcCredential, WalletKitError> {
        let credential_bytes = STANDARD.decode(&self.credential).map_err(|e| {
            WalletKitError::SerializationError {
                error: format!("Failed to decode NFC base64 credential: {e}"),
            }
        })?;

        let metadata: CredentialMetadata = serde_json::from_slice(&credential_bytes)
            .map_err(|e| WalletKitError::SerializationError {
                error: format!("Failed to parse NFC credential JSON: {e}"),
            })?;

        Ok(NfcCredential {
            issuer_schema_id: metadata.issuer_schema_id,
            genesis_issued_at: metadata.genesis_issued_at,
            expires_at: metadata.expires_at,
            credential_blob: credential_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_credential() {
        // Create a mock credential JSON
        let credential_json = serde_json::json!({
            "issuer_schema_id": 9303,
            "genesis_issued_at": 1_700_000_000_u64,
            "expires_at": 1_800_000_000_u64,
            "sub": "0x123",
            "claims": ["0x1"],
            "associated_data_hash": "0x456",
            "signature": "0x789"
        });

        let credential_bytes = serde_json::to_vec(&credential_json).unwrap();
        let credential_base64 = STANDARD.encode(&credential_bytes);

        let raw = NfcRefreshResultRaw {
            credential: credential_base64,
        };

        let parsed = raw.parse().unwrap();

        assert_eq!(parsed.issuer_schema_id, 9303);
        assert_eq!(parsed.genesis_issued_at, 1_700_000_000);
        assert_eq!(parsed.expires_at, 1_800_000_000);
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

    #[test]
    fn test_parse_credential_invalid_json() {
        let raw = NfcRefreshResultRaw {
            credential: STANDARD.encode(b"not json"),
        };

        let err = raw.parse().unwrap_err();
        assert!(matches!(err, WalletKitError::SerializationError { .. }));
    }
}
