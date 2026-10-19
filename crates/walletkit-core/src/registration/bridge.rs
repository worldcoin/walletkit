//! Associates the shared bridge client with a WIP-109 Pairing URI domain.

use reqwest::Url;
use world_id_bridge_client::{BridgeClient as Client, EncryptedPayload as Payload};
use world_id_core::registration::{BridgeDomain, EncryptedPayload, RequestId};

pub use world_id_bridge_client::BridgeError;

/// A client for an allowed bridge deployment, as named in a Pairing URI.
#[derive(Clone, Debug)]
pub struct BridgeClient {
    client: Client,
    domain: BridgeDomain,
}

pub(super) type ResponseState = world_id_bridge_client::ResponseState;

impl BridgeClient {
    /// Creates a client for the bridge at `https://{domain}`.
    ///
    /// # Errors
    /// Returns an error if the URL or HTTP client cannot be built.
    pub fn new(domain: BridgeDomain) -> Result<Self, BridgeError> {
        let base_url = Url::parse(&format!("https://{domain}"))
            .map_err(|_| BridgeError::InvalidUrl)?;
        Self::with_base_url(domain, base_url)
    }

    /// Reaches the bridge named `domain` at `base_url`, e.g. a local test server.
    ///
    /// # Errors
    /// Returns an error if the URL or HTTP client cannot be built.
    pub fn with_base_url(
        domain: BridgeDomain,
        base_url: Url,
    ) -> Result<Self, BridgeError> {
        Ok(Self {
            client: Client::new(base_url)?,
            domain,
        })
    }

    /// The domain of the deployment, as written into a Pairing URI.
    #[must_use]
    pub const fn domain(&self) -> &BridgeDomain {
        &self.domain
    }

    pub(super) async fn publish_request(
        &self,
        request_id: &RequestId,
        request: &EncryptedPayload,
    ) -> Result<(), BridgeError> {
        self.client
            .publish_request(&request_id.to_string(), &payload(request))
            .await
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
        self.client.fetch_response(&request_id.to_string()).await
    }

    pub(super) async fn put_response(
        &self,
        request_id: &RequestId,
        response: &EncryptedPayload,
    ) -> Result<(), BridgeError> {
        self.client
            .put_response(&request_id.to_string(), &payload(response))
            .await
    }
}

fn payload(encrypted: &EncryptedPayload) -> Payload {
    Payload {
        iv: encrypted.iv.clone(),
        payload: encrypted.payload.clone(),
    }
}
