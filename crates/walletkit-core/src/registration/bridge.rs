//! A client for the message-bridge that carries registration messages (WIP-110).

use std::{future::Future, time::Duration};

use backon::{BackoffBuilder as _, ExponentialBuilder};
use futures_util::StreamExt as _;
use reqwest::{header::RETRY_AFTER, RequestBuilder, Response, StatusCode, Url};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use web_time::{Instant, SystemTime, UNIX_EPOCH};
use world_id_core::registration::{BridgeDomain, EncryptedPayload, RequestId};

use super::{before, errors::BridgeError, sleep};

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
            http: http_client(&base_url)?,
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
    /// Returns the parsed bridge domain.
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
    /// stored it; a `400` or `409` after a failed attempt can mean that attempt was stored,
    /// but remains an error because anyone who saw the Pairing URI knows `request_id` and
    /// could have filled the response slot first (WIP-109 §3.7.5).
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

    /// Reads and deserializes a single-use bridge resource, returning `None` on `404`.
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

    /// Sends `request`, retrying transient failures while honoring `Retry-After`.
    async fn send(&self, request: RequestBuilder) -> Result<Response, BridgeError> {
        let request = request.timeout(Duration::from_secs(30)).build()?;
        let mut delays = retry_backoff().build();
        loop {
            let attempt = request
                .try_clone()
                .expect("bridge requests have buffered bodies");
            match self.http.execute(attempt).await {
                Ok(response) => {
                    if !same_origin(&self.base_url, response.url()) {
                        return Err(BridgeError::InvalidUrl(
                            "bridge redirected across origins".to_string(),
                        ));
                    }
                    let status = response.status();
                    if !status.is_server_error()
                        && status != StatusCode::TOO_MANY_REQUESTS
                    {
                        return Ok(response);
                    }
                    let retry_after = retry_after(&response);
                    let Some(backoff) = delays.next() else {
                        return Err(BridgeError::from(status));
                    };
                    sleep(retry_after.unwrap_or(backoff).max(backoff)).await;
                }
                Err(error) => {
                    let Some(backoff) = delays.next() else {
                        return Err(BridgeError::from(error));
                    };
                    sleep(backoff).await;
                }
            }
        }
    }

    /// Builds a bridge endpoint URL by appending `segments` to `self.base_url`.
    fn url(&self, segments: &[&str]) -> Url {
        let mut url = self.base_url.clone();
        url.path_segments_mut()
            .expect("`with_base_url` accepts only URLs that can be a base")
            .pop_if_empty()
            .extend(segments);
        url
    }
}

/// Builds the HTTP client for the bridge.
///
/// Native clients stop cross-origin redirects before contacting the target. On `wasm32`,
/// `reqwest`'s Fetch backend does not expose `RequestInit.redirect` (`reqwest::redirect::Policy`
/// is native-only); the allowlisted bridge already receives `request_id` on the initial request
/// (and payloads are end-to-end encrypted), and [`BridgeClient::send`] rejects any response whose
/// final URL left `base_url`'s origin.
fn http_client(base_url: &Url) -> Result<reqwest::Client, BridgeError> {
    let builder = crate::http_client::builder();
    #[cfg(not(target_arch = "wasm32"))]
    let builder = {
        let origin = base_url.clone();
        builder
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::custom(move |attempt| {
                if attempt.previous().len() >= 10 {
                    return attempt.error("too many redirects");
                }
                if same_origin(&origin, attempt.url()) {
                    attempt.follow()
                } else {
                    attempt.stop()
                }
            }))
    };
    #[cfg(target_arch = "wasm32")]
    let _ = base_url;
    Ok(builder.build()?)
}

/// Returns whether `a` and `b` share the same scheme, host and port.
fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

/// Parses a `Retry-After` header (`delay-seconds` or `IMF-fixdate` HTTP-date) from a throttled
/// or unavailable response.
fn retry_after(response: &Response) -> Option<Duration> {
    let raw = response.headers().get(RETRY_AFTER)?.to_str().ok()?.trim();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    parse_retry_after(raw, now)
}

/// Parses a `Retry-After` header value relative to `now_epoch_secs` (RFC 9110 §10.2.3).
fn parse_retry_after(value: &str, now_epoch_secs: u64) -> Option<Duration> {
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    let target = parse_http_date(value)?;
    Some(Duration::from_secs(target.saturating_sub(now_epoch_secs)))
}

/// Parses an RFC 9110 §5.6.7 `IMF-fixdate` (`Day, DD Mon YYYY HH:MM:SS GMT`) into a UNIX
/// timestamp in seconds.
fn parse_http_date(value: &str) -> Option<u64> {
    let (_, rest) = value.split_once(", ")?;
    let mut parts = rest.split_ascii_whitespace();
    let day: u64 = parts.next()?.parse().ok()?;
    let month: u64 = match parts.next()? {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year: i64 = parts.next()?.parse().ok()?;
    let mut hms = parts.next()?.split(':');
    let hour: u64 = hms.next()?.parse().ok()?;
    let minute: u64 = hms.next()?.parse().ok()?;
    let second: u64 = hms.next()?.parse().ok()?;
    if hms.next().is_some() || parts.next()? != "GMT" || parts.next().is_some() {
        return None;
    }
    if !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let y = year - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400) as u64;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + i64::try_from(doe).ok()? - 719_468;
    u64::try_from(days)
        .ok()?
        .checked_mul(86_400)?
        .checked_add(hour * 3_600 + minute * 60 + second.min(59))
}

/// Runs a bridge operation within [`OPERATION_TIMEOUT`].
async fn bounded<T>(
    operation: impl Future<Output = Result<T, BridgeError>>,
) -> Result<T, BridgeError> {
    before(Instant::now() + OPERATION_TIMEOUT, operation)
        .await
        .unwrap_or(Err(BridgeError::Timeout))
}

/// Builds the exponential backoff policy for transient bridge errors.
fn retry_backoff() -> ExponentialBuilder {
    ExponentialBuilder::default()
        .with_min_delay(Duration::from_millis(500))
        .with_max_delay(Duration::from_secs(5))
        .with_max_times(3)
        .with_jitter()
}

/// Reads a JSON response body up to [`MAX_BODY_SIZE`].
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

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use axum::{
        extract::State,
        http::{header::RETRY_AFTER, StatusCode},
        response::Redirect,
        routing::{get, put},
        Json, Router,
    };
    use tokio::net::TcpListener;
    use world_id_core::registration::PairingSecret;

    use super::*;

    fn sample_payload() -> EncryptedPayload {
        EncryptedPayload {
            iv: "aXY=".to_string(),
            payload: "cGF5bG9hZA==".to_string(),
        }
    }

    async fn serve(app: Router) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        url
    }

    #[tokio::test]
    async fn put_response_treats_conflict_as_unconfirmed_delivery() {
        let url = serve(
            Router::new()
                .route("/response/{id}", put(|| async { StatusCode::CONFLICT })),
        )
        .await;
        let client = BridgeClient::with_base_url("bridge.example", &url).unwrap();
        let request_id = PairingSecret::generate().unwrap().request_id();

        let err = client
            .put_response(&request_id, &sample_payload())
            .await
            .unwrap_err();
        assert_eq!(err, BridgeError::UnexpectedStatus { status: 409 });
    }

    #[tokio::test]
    async fn redirect_policy_follows_same_origin_and_stops_cross_origin() {
        let other_hits = Arc::new(AtomicUsize::new(0));
        let other_url = serve(
            Router::new()
                .route(
                    "/request/{id}",
                    get(|State(hits): State<Arc<AtomicUsize>>| async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        Json(sample_payload())
                    }),
                )
                .with_state(other_hits.clone()),
        )
        .await;

        let cross_origin_target = format!("{other_url}/request/1");
        let cross_url = serve(Router::new().route(
            "/request/{id}",
            get(move || {
                let target = cross_origin_target.clone();
                async move { Redirect::temporary(&target) }
            }),
        ))
        .await;
        let client = BridgeClient::with_base_url("bridge.example", &cross_url).unwrap();
        let request_id = PairingSecret::generate().unwrap().request_id();
        let err = client.take_request(&request_id).await.unwrap_err();
        assert_eq!(err, BridgeError::UnexpectedStatus { status: 307 });
        assert_eq!(other_hits.load(Ordering::SeqCst), 0);

        let same_url = serve(
            Router::new()
                .route(
                    "/request/{id}",
                    get(|| async { Redirect::temporary("/v2/request") }),
                )
                .route("/v2/request", get(|| async { Json(sample_payload()) })),
        )
        .await;
        let same_client =
            BridgeClient::with_base_url("bridge.example", &same_url).unwrap();
        assert!(same_client
            .take_request(&request_id)
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn send_honors_retry_after_on_throttled_response() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route(
                "/response/{id}",
                put(|State(attempts): State<Arc<AtomicUsize>>| async move {
                    if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                        (StatusCode::TOO_MANY_REQUESTS, [(RETRY_AFTER, "1")])
                    } else {
                        (StatusCode::CREATED, [(RETRY_AFTER, "0")])
                    }
                }),
            )
            .with_state(attempts.clone());
        let url = serve(app).await;
        let client = BridgeClient::with_base_url("bridge.example", &url).unwrap();
        let request_id = PairingSecret::generate().unwrap().request_id();

        let started = Instant::now();
        client
            .put_response(&request_id, &sample_payload())
            .await
            .unwrap();
        assert!(started.elapsed() >= Duration::from_secs(1));
        assert_eq!(attempts.load(Ordering::SeqCst), 2);

        // RFC 9110 §5.6.7 IMF-fixdate (Sun, 06 Nov 1994 08:49:37 GMT = 784111777).
        assert_eq!(
            parse_retry_after("Sun, 06 Nov 1994 08:49:37 GMT", 784_111_747),
            Some(Duration::from_secs(30))
        );
        assert_eq!(
            parse_retry_after("Sun, 06 Nov 1994 08:49:37 GMT", 784_111_800),
            Some(Duration::ZERO)
        );
    }
}
