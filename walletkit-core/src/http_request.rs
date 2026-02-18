use std::time::Duration;

use backon::{ExponentialBuilder, Retryable};
use reqwest::{Method, RequestBuilder, Response};

use crate::error::WalletKitError;

/// A simple wrapper on an HTTP client for making requests. Sets sensible defaults such as timeouts,
/// user-agent & ensuring HTTPS, and applies retry middleware for transient failures.
pub struct Request {
    client: reqwest::Client,
    timeout: Duration,
    max_retries: u32,
}

impl Request {
    /// Initializes a new `Request` instance.
    pub(crate) fn new() -> Self {
        let client = reqwest::Client::new();
        let timeout = Duration::from_secs(5);
        let max_retries = 3; // total attempts = 4
        Self {
            client,
            timeout,
            max_retries,
        }
    }

    /// Creates a request builder with defaults applied.
    pub(crate) fn req(&self, method: Method, url: &str) -> RequestBuilder {
        #[cfg(not(test))]
        assert!(url.starts_with("https"));

        self.client
            .request(method, url)
            .timeout(self.timeout)
            .header(
                "User-Agent",
                format!("walletkit-core/{}", env!("CARGO_PKG_VERSION")),
            )
    }

    /// Creates a GET request builder with defaults applied.
    #[allow(dead_code)]
    pub(crate) fn get(&self, url: &str) -> RequestBuilder {
        self.req(Method::GET, url)
    }

    /// Creates a POST request builder with defaults applied.
    pub(crate) fn post(&self, url: &str) -> RequestBuilder {
        self.req(Method::POST, url)
    }

    /// Handles sending a request built by `req`/`get`/`post` with retries for transient failures.
    pub(crate) async fn handle(
        &self,
        request_builder: RequestBuilder,
    ) -> Result<Response, WalletKitError> {
        if request_builder.try_clone().is_none() {
            return execute_request_builder(request_builder)
                .await
                .map_err(Into::into);
        }

        let backoff = ExponentialBuilder::default()
            .with_min_delay(Duration::from_millis(200))
            .with_max_delay(Duration::from_secs(2))
            .with_max_times(self.max_retries as usize);

        let template = request_builder.try_clone().ok_or_else(|| {
            WalletKitError::NetworkError {
                url: "<unknown>".to_string(),
                status: None,
                error: "request cannot be retried because it is not cloneable"
                    .to_string(),
            }
        })?;

        (|| async {
            let request_builder = template.try_clone().ok_or_else(|| {
                RequestHandleError::permanent(
                    "<unknown>".to_string(),
                    None,
                    "request cannot be retried because it is not cloneable".to_string(),
                )
            })?;
            execute_request_builder(request_builder).await
        })
        .retry(backoff)
        .when(|err: &RequestHandleError| err.is_retryable())
        .await
        .map_err(Into::into)
    }
}

#[derive(Debug)]
struct RequestHandleError {
    url: String,
    status: Option<u16>,
    error: String,
    retryable: bool,
}

impl RequestHandleError {
    fn retryable(url: String, status: Option<u16>, error: String) -> Self {
        Self {
            url,
            status,
            error,
            retryable: true,
        }
    }

    fn permanent(url: String, status: Option<u16>, error: String) -> Self {
        Self {
            url,
            status,
            error,
            retryable: false,
        }
    }

    fn is_retryable(&self) -> bool {
        self.retryable
    }
}

impl From<RequestHandleError> for WalletKitError {
    fn from(value: RequestHandleError) -> Self {
        WalletKitError::NetworkError {
            url: value.url,
            status: value.status,
            error: value.error,
        }
    }
}

async fn execute_request_builder(
    request_builder: RequestBuilder,
) -> Result<Response, RequestHandleError> {
    let (client, request) = request_builder.build_split();
    let request = request.map_err(|err| {
        RequestHandleError::permanent(
            err.url()
                .map(|url| url.to_string())
                .unwrap_or_else(|| "<unknown>".to_string()),
            None,
            format!("request build failed: {err}"),
        )
    })?;
    let url = request.url().to_string();

    match client.execute(request).await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            if status == 429 || (500..600).contains(&status) {
                return Err(RequestHandleError::retryable(
                    url,
                    Some(status),
                    format!("request error with bad status code {status}"),
                ));
            }
            Ok(resp)
        }
        Err(err) => {
            if err.is_timeout() || err.is_connect() {
                return Err(RequestHandleError::retryable(
                    url,
                    None,
                    format!("request timeout/connect error: {err}"),
                ));
            }

            Err(RequestHandleError::permanent(
                url,
                None,
                format!("request failed: {err}"),
            ))
        }
    }
}
