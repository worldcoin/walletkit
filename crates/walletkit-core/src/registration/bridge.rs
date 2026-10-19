//! A client for the message-bridge that carries registration messages (WIP-110).

use std::{future::Future, time::Duration};

use backon::{ExponentialBuilder, Retryable as _};
use futures_util::StreamExt as _;
use reqwest::{RequestBuilder, Response, StatusCode, Url};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use web_time::Instant;
use world_id_core::registration::{BridgeDomain, EncryptedPayload, RequestId};

use super::before;

/// The message-bridge's body limit, which the largest WIP-109 response fits within.
const MAX_BODY_SIZE: usize = 5 * 1024 * 1024;

/// The time budget of one operation, including its retries and reading the response.
const OPERATION_TIMEOUT: Duration = Duration::from_mins(1);

/// A client for one bridge deployment.
///
/// Transport failures, `429` and server errors are retried with bounded backoff and jitter.
/// Reading a request or a response is single-use, so a retry after a lost reply can find the
/// message gone.
#[derive(Clone, Debug, uniffi::Object)]
pub struct BridgeClient {
    http: reqwest::Client,
    domain: BridgeDomain,
    base_url: Url,
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

/// The state of a response on the bridge (`GET /response/:id`).
#[derive(Deserialize)]
#[serde(tag = "status", content = "response", rename_all = "snake_case")]
pub(super) enum ResponseState {
    /// The request has not been taken yet.
    Initialized,
    /// The request was taken; the response has not arrived yet.
    Retrieved,
    /// The response, which the read consumed.
    Completed(EncryptedPayload),
}

/// The body of `POST /request`.
#[derive(Serialize)]
struct PublishBody<'a> {
    request_id: String,
    #[serde(flatten)]
    request: &'a EncryptedPayload,
}

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

    /// Creates a client that reaches the bridge named `domain` at `base_url`, e.g. a local
    /// deployment in tests.
    ///
    /// # Errors
    ///
    /// Returns an error if `domain` is not a valid bridge domain, `base_url` cannot be a base
    /// for the bridge routes, or the TLS backend cannot be initialized.
    #[uniffi::constructor]
    pub fn with_base_url(domain: &str, base_url: &str) -> Result<Self, BridgeError> {
        let domain: BridgeDomain = domain
            .parse()
            .map_err(|_| BridgeError::InvalidDomain(domain.to_string()))?;
        let base_url = Url::parse(base_url)
            .map_err(|error| BridgeError::InvalidUrl(error.to_string()))?;
        if base_url.cannot_be_a_base() {
            return Err(BridgeError::InvalidUrl(base_url.to_string()));
        }
        Ok(Self {
            http: http_client()?,
            domain,
            base_url,
        })
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

    /// Stores the encrypted request (`POST /request`). A `409` means that an earlier attempt,
    /// whose reply was lost, stored it.
    pub(super) async fn publish_request(
        &self,
        request_id: &RequestId,
        request: &EncryptedPayload,
    ) -> Result<(), BridgeError> {
        let body = PublishBody {
            request_id: request_id.to_string(),
            request,
        };
        bounded(async {
            let response = self
                .send(self.http.post(self.url(&["request"])).json(&body))
                .await?;
            match response.status() {
                StatusCode::OK | StatusCode::CONFLICT => Ok(()),
                status => Err(BridgeError::from(status)),
            }
        })
        .await
    }

    /// Takes the encrypted request (`GET /request/:id`). Returns `None` if it expired or was
    /// already taken.
    pub(super) async fn take_request(
        &self,
        request_id: &RequestId,
    ) -> Result<Option<EncryptedPayload>, BridgeError> {
        self.read(self.url(&["request", &request_id.to_string()]))
            .await
    }

    /// Reads the state of the response (`GET /response/:id`), consuming a completed one. Returns
    /// `None` if the session expired or its response was already consumed.
    pub(super) async fn fetch_response(
        &self,
        request_id: &RequestId,
    ) -> Result<Option<ResponseState>, BridgeError> {
        self.read(self.url(&["response", &request_id.to_string()]))
            .await
    }

    /// Stores the encrypted response (`PUT /response/:id`). The bridge answers `201` once it
    /// stored it; a `400` or `409` after a failed attempt can mean that attempt was stored.
    pub(super) async fn put_response(
        &self,
        request_id: &RequestId,
        response: &EncryptedPayload,
    ) -> Result<(), BridgeError> {
        let url = self.url(&["response", &request_id.to_string()]);
        bounded(async {
            let reply = self.send(self.http.put(url).json(response)).await?;
            match reply.status() {
                StatusCode::CREATED => Ok(()),
                status => Err(BridgeError::from(status)),
            }
        })
        .await
    }

    async fn read<T: DeserializeOwned>(
        &self,
        url: Url,
    ) -> Result<Option<T>, BridgeError> {
        bounded(async {
            let response = self.send(self.http.get(url)).await?;
            match response.status() {
                StatusCode::OK => read_json(response).await.map(Some),
                StatusCode::NOT_FOUND => Ok(None),
                status => Err(BridgeError::from(status)),
            }
        })
        .await
    }

    /// Sends `request`, retrying transient failures.
    ///
    /// Each attempt owns what it uses, so that the operations stay `Send` for `UniFFI`'s async
    /// exports.
    async fn send(&self, request: RequestBuilder) -> Result<Response, BridgeError> {
        let request = request.build()?;
        let attempt = || {
            let http = self.http.clone();
            let request = request
                .try_clone()
                .expect("bridge requests have buffered bodies");
            async move {
                let response = http.execute(request).await?;
                let status = response.status();
                if status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS {
                    return Err(BridgeError::from(status));
                }
                Ok(response)
            }
        };
        attempt
            .retry(retry_backoff())
            .when(BridgeError::is_transient)
            .await
    }

    fn url(&self, segments: &[&str]) -> Url {
        let mut url = self.base_url.clone();
        url.path_segments_mut()
            .expect("`with_base_url` accepts only URLs that can be a base")
            .pop_if_empty()
            .extend(segments);
        url
    }
}

impl BridgeError {
    const fn is_transient(&self) -> bool {
        match self {
            Self::Transport(_) => true,
            Self::UnexpectedStatus { status } => {
                (*status >= 500 && *status < 600)
                    || *status == StatusCode::TOO_MANY_REQUESTS.as_u16()
            }
            Self::InvalidDomain(_)
            | Self::InvalidUrl(_)
            | Self::Json(_)
            | Self::TooLarge
            | Self::Timeout => false,
        }
    }
}

impl From<StatusCode> for BridgeError {
    fn from(status: StatusCode) -> Self {
        Self::UnexpectedStatus {
            status: status.as_u16(),
        }
    }
}

impl From<reqwest::Error> for BridgeError {
    fn from(error: reqwest::Error) -> Self {
        Self::Transport(error.without_url().to_string())
    }
}

impl From<serde_json::Error> for BridgeError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error.to_string())
    }
}

/// Builds the HTTP client for the bridge. Browsers decide connection and request timeouts
/// themselves.
fn http_client() -> Result<reqwest::Client, BridgeError> {
    let builder = crate::http_client::builder();
    #[cfg(not(target_arch = "wasm32"))]
    let builder = builder
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30));
    Ok(builder.build()?)
}

/// Runs a bridge operation within [`OPERATION_TIMEOUT`].
async fn bounded<T>(
    operation: impl Future<Output = Result<T, BridgeError>>,
) -> Result<T, BridgeError> {
    before(Instant::now() + OPERATION_TIMEOUT, operation)
        .await
        .unwrap_or(Err(BridgeError::Timeout))
}

fn retry_backoff() -> ExponentialBuilder {
    ExponentialBuilder::default()
        .with_min_delay(Duration::from_millis(500))
        .with_max_delay(Duration::from_secs(5))
        .with_max_times(3)
        .with_jitter()
}

async fn read_json<T: DeserializeOwned>(response: Response) -> Result<T, BridgeError> {
    let mut chunks = std::pin::pin!(response.bytes_stream());
    let mut body = Vec::new();
    while let Some(chunk) = chunks.next().await {
        let chunk = chunk?;
        if body.len() + chunk.len() > MAX_BODY_SIZE {
            return Err(BridgeError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&body)?)
}
