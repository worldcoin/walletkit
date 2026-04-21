//! NfcKit — NFC identity-document credential issuer for the host-mediated Issuers SDK.

use issuer_sdk::{
    build_credential_json, parse_request_json, Issuer, IssuerDriver, IssuerMsg, IssuerValue,
    SdkError,
};

/// Issuer that mints credentials via an NFC identity document.
#[derive(uniffi::Object)]
pub struct NfcIssuer;

impl Default for NfcIssuer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Issuer for NfcIssuer {
    async fn fetch_credential(&self, request_json: String) -> Result<String, SdkError> {
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        let request = parse_request_json(&request_json)?;
        let id = uuid::Uuid::new_v4().to_string();
        let data = format!(
            "eyJhbGciOiJFUzI1NiIsInR5cCI6IlNELUpXVCJ9.stub.nfc.{}",
            request.user_id
        );
        build_credential_json(&id, "nfc-kit", data)
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl NfcIssuer {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self
    }

    pub async fn handle_message(&self, msg: IssuerMsg) -> Result<IssuerValue, SdkError> {
        <Self as IssuerDriver>::handle_message(self, msg).await
    }
}

uniffi::setup_scaffolding!("nfc_kit");

#[cfg(test)]
mod tests {
    use super::NfcIssuer;
    use issuer_sdk::{Credential, Issuer, IssuerDriver, IssuerMsg, IssuerValue};

    #[tokio::test]
    async fn issues_nfc_credential() {
        let json = NfcIssuer::new()
            .fetch_credential(r#"{"user_id":"user-xyz"}"#.to_string())
            .await
            .unwrap();
        let cred: Credential = serde_json::from_str(&json).unwrap();
        assert_eq!(cred.issuer, "nfc-kit");
        assert!(cred.data.contains("user-xyz"));
    }

    #[tokio::test]
    async fn rejects_blank_user_id() {
        assert!(NfcIssuer::new()
            .fetch_credential(r#"{"user_id":""}"#.to_string())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn blanket_handle_message_fetch_credential() {
        let driver: &dyn IssuerDriver = &NfcIssuer::new();
        let value = driver
            .handle_message(IssuerMsg::FetchCredential {
                request_json: r#"{"user_id":"blanket-nfc"}"#.to_string(),
            })
            .await
            .unwrap();
        let IssuerValue::Credential { json } = value;
        let cred: Credential = serde_json::from_str(&json).unwrap();
        assert_eq!(cred.issuer, "nfc-kit");
        assert!(cred.data.contains("blanket-nfc"));
    }
}
