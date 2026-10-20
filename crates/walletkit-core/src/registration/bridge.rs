//! Associates the shared bridge client with a WIP-109 Pairing URI domain.

use message_bridge_client::{
    BridgeClient as Client, BridgeError as ClientError, EncryptedPayload as Payload,
};
use reqwest::Url;
use world_id_core::registration::{BridgeDomain, EncryptedPayload, RequestId};

/// A client for an allowed bridge deployment, as named in a Pairing URI.
#[derive(Clone, Debug, uniffi::Object)]
pub struct BridgeClient {
    client: Client,
    domain: BridgeDomain,
}

/// Errors from talking to the bridge.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum BridgeError {
    /// The bridge domain is not a valid DNS name with a named top-level label.
    #[error("invalid bridge domain: {0}")]
    InvalidDomain(String),
    /// The bridge URL cannot be built.
    #[error("invalid bridge URL: {0}")]
    InvalidUrl(String),
    /// The request failed in transit. The error carries no URL: the bridge routes contain the
    /// request id, which is the only key to the session.
    #[error("bridge request failed: {0}")]
    Transport(String),
    /// The bridge answered with a status the operation does not expect.
    #[error("bridge returned unexpected status {status}")]
    UnexpectedStatus {
        /// The HTTP status code.
        status: u16,
    },
    /// The bridge returned malformed JSON.
    #[error("invalid bridge response: {0}")]
    Json(String),
    /// The bridge response exceeded the bridge's body limit.
    #[error("bridge response exceeds the 5 MiB body limit")]
    TooLarge,
    /// The operation exhausted its time budget.
    #[error("bridge operation timed out")]
    Timeout,
}

pub(super) type ResponseState = message_bridge_client::ResponseState;

#[uniffi::export]
impl BridgeClient {
    /// Creates a client for the bridge at `https://{domain}`.
    ///
    /// # Errors
    ///
    /// Returns an error if `domain` is not a valid bridge domain or the TLS backend cannot be
    /// initialized.
    #[uniffi::constructor]
    pub fn new(domain: &str) -> Result<Self, BridgeError> {
        let parsed: BridgeDomain = domain
            .parse()
            .map_err(|_| BridgeError::InvalidDomain(domain.to_string()))?;
        Self::with_base_url(parsed.as_str(), &format!("https://{parsed}"))
    }

    /// Reaches the bridge named `domain` at `base_url`, e.g. a local test server.
    ///
    /// # Errors
    ///
    /// Returns an error if `domain` is not a valid bridge domain, `base_url` is not a valid
    /// HTTP(S) base URL, or the TLS backend cannot be initialized.
    #[uniffi::constructor]
    pub fn with_base_url(domain: &str, base_url: &str) -> Result<Self, BridgeError> {
        let domain: BridgeDomain = domain
            .parse()
            .map_err(|_| BridgeError::InvalidDomain(domain.to_string()))?;
        let parsed_url = Url::parse(base_url)
            .map_err(|error| BridgeError::InvalidUrl(error.to_string()))?;
        let client = Client::new(parsed_url).map_err(|error| match error {
            ClientError::InvalidUrl => BridgeError::InvalidUrl(base_url.to_string()),
            other => BridgeError::from(other),
        })?;
        Ok(Self { client, domain })
    }

    /// Returns the domain of the bridge deployment, as written into a Pairing URI.
    #[must_use]
    pub fn domain(&self) -> String {
        self.domain.to_string()
    }
}

impl BridgeClient {
    pub(super) const fn bridge_domain(&self) -> &BridgeDomain {
        &self.domain
    }

    pub(super) async fn publish_request(
        &self,
        request_id: &RequestId,
        request: &EncryptedPayload,
    ) -> Result<(), BridgeError> {
        Ok(self
            .client
            .publish_request(&request_id.to_string(), &payload(request))
            .await?)
    }

    pub(super) async fn take_request(
        &self,
        request_id: &RequestId,
    ) -> Result<Option<EncryptedPayload>, BridgeError> {
        Ok(self
            .client
            .take_request(&request_id.to_string())
            .await?
            .map(|p| EncryptedPayload {
                iv: p.iv,
                payload: p.payload,
            }))
    }

    pub(super) async fn fetch_response(
        &self,
        request_id: &RequestId,
    ) -> Result<Option<ResponseState>, BridgeError> {
        Ok(self.client.fetch_response(&request_id.to_string()).await?)
    }

    pub(super) async fn put_response(
        &self,
        request_id: &RequestId,
        response: &EncryptedPayload,
    ) -> Result<(), BridgeError> {
        Ok(self
            .client
            .put_response(&request_id.to_string(), &payload(response))
            .await?)
    }
}

impl From<ClientError> for BridgeError {
    fn from(error: ClientError) -> Self {
        match error {
            ClientError::Transport(error) => {
                Self::Transport(error.without_url().to_string())
            }
            ClientError::UnexpectedStatus(status) => Self::UnexpectedStatus {
                status: status.as_u16(),
            },
            ClientError::Json(error) => Self::Json(error.to_string()),
            ClientError::TooLarge => Self::TooLarge,
            ClientError::Timeout => Self::Timeout,
            ClientError::InvalidUrl => Self::InvalidUrl(error.to_string()),
        }
    }
}

fn payload(encrypted: &EncryptedPayload) -> Payload {
    Payload {
        iv: encrypted.iv.clone(),
        payload: encrypted.payload.clone(),
    }
}
