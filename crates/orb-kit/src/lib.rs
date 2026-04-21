//! OrbKit — Orb-based credential issuer for the host-mediated Issuers SDK.

use issuer_sdk::{
    build_credential_json, parse_request_json, Issuer, IssuerDriver, IssuerMsg, IssuerValue,
    SdkError,
};

/// Issuer that mints credentials via the Orb hardware device.
#[derive(uniffi::Object)]
pub struct OrbIssuer;

impl Default for OrbIssuer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Issuer for OrbIssuer {
    async fn fetch_credential(&self, request_json: String) -> Result<String, SdkError> {
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        let request = parse_request_json(&request_json)?;
        let id = uuid::Uuid::new_v4().to_string();
        let data = format!(
            "eyJhbGciOiJFUzI1NiIsInR5cCI6IlNELUpXVCJ9.stub.orb.{}",
            request.user_id
        );
        build_credential_json(&id, "orb-kit", data)
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl OrbIssuer {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self
    }

    pub async fn handle_message(&self, msg: IssuerMsg) -> Result<IssuerValue, SdkError> {
        <Self as IssuerDriver>::handle_message(self, msg).await
    }
}

uniffi::setup_scaffolding!("orb_kit");

#[cfg(test)]
mod tests {
    use super::OrbIssuer;
    use issuer_sdk::{Credential, Issuer, IssuerDriver, IssuerMsg, IssuerValue};

    #[tokio::test]
    async fn issues_orb_credential() {
        let json = OrbIssuer::new()
            .fetch_credential(r#"{"user_id":"user-abc"}"#.to_string())
            .await
            .unwrap();
        let cred: Credential = serde_json::from_str(&json).unwrap();
        assert_eq!(cred.issuer, "orb-kit");
        assert!(cred.data.contains("user-abc"));
    }

    #[tokio::test]
    async fn rejects_blank_user_id() {
        assert!(OrbIssuer::new()
            .fetch_credential(r#"{"user_id":""}"#.to_string())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn blanket_handle_message_fetch_credential() {
        let driver: &dyn IssuerDriver = &OrbIssuer::new();
        let value = driver
            .handle_message(IssuerMsg::FetchCredential {
                request_json: r#"{"user_id":"blanket-orb"}"#.to_string(),
            })
            .await
            .unwrap();
        let IssuerValue::Credential { json } = value;
        let cred: Credential = serde_json::from_str(&json).unwrap();
        assert_eq!(cred.issuer, "orb-kit");
        assert!(cred.data.contains("blanket-orb"));
    }
}
