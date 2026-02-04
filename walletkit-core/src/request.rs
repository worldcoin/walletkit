use std::time::Duration;

use reqwest::Response;
use serde::ser::Serialize;

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

    /// Makes a POST request to a given URL with a JSON body. Retries are handled internally for
    /// transient failures such as timeouts, 5xx responses, and rate limiting (429)
    pub(crate) async fn post<T>(
        &self,
        url: String,
        body: T,
    ) -> Result<reqwest::Response, WalletKitError>
    where
        T: Serialize + Send + Sync,
    {
        #[cfg(not(test))]
        assert!(url.starts_with("https"));

        let mut attempt = 0;

        loop {
            let result = self
                .client
                .post(&url)
                .timeout(self.timeout)
                .header(
                    "User-Agent",
                    format!("walletkit-core/{}", env!("CARGO_PKG_VERSION")),
                )
                .json(&body)
                .send()
                .await;

            match result {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    // Retry on 429 and 5xx
                    if status == 429 || (500..600).contains(&status) {
                        if attempt >= self.max_retries {
                            return Err(WalletKitError::NetworkError {
                                url,
                                status: Some(status),
                                error: format!(
                                    "request error with bad status code {status}"
                                ),
                            });
                        }
                        attempt += 1;
                        // No sleep to keep runtime-agnostic
                        continue;
                    }

                    return Ok(resp);
                }
                Err(err) => {
                    // Retry on timeouts/connect errors
                    if err.is_timeout() || err.is_connect() {
                        if attempt >= self.max_retries {
                            return Err(WalletKitError::NetworkError {
                                url,
                                status: None,
                                error: format!(
                                    "request timeout/connect error after all retries: {err}"
                                ),
                            });
                        }
                        attempt += 1;
                        continue;
                    }
                    return Err(WalletKitError::NetworkError {
                        url,
                        status: None,
                        error: format!("request failed after all retries: {err}"),
                    });
                }
            }
        }
    }

    /// Makes a POST request with a raw JSON body string and custom headers.
    ///
    /// Use this when you already have a serialized JSON string (e.g., from Oxide).
    /// Retries on 429, 5xx, timeouts and connection errors (same as `post`).
    pub(crate) async fn post_raw_json(
        &self,
        url: &str,
        body: &str,
        headers: &[(&str, &str)],
    ) -> Result<Response, WalletKitError> {
        #[cfg(not(test))]
        assert!(url.starts_with("https"));

        let mut attempt = 0;

        loop {
            let mut builder = self
                .client
                .post(url)
                .timeout(self.timeout)
                .header(
                    "User-Agent",
                    format!("walletkit-core/{}", env!("CARGO_PKG_VERSION")),
                )
                .header("Content-Type", "application/json")
                .body(body.to_string());

            for (name, value) in headers {
                builder = builder.header(*name, *value);
            }

            let result = builder.send().await;

            match result {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    if status == 429 || (500..600).contains(&status) {
                        if attempt >= self.max_retries {
                            return Err(WalletKitError::NetworkError {
                                url: url.to_string(),
                                status: Some(status),
                                error: format!(
                                    "request error with bad status code {status}"
                                ),
                            });
                        }
                        attempt += 1;
                        continue;
                    }
                    return Ok(resp);
                }
                Err(err) => {
                    if err.is_timeout() || err.is_connect() {
                        if attempt >= self.max_retries {
                            return Err(WalletKitError::NetworkError {
                                url: url.to_string(),
                                status: None,
                                error: format!("request timeout/connect error after retries: {err}"),
                            });
                        }
                        attempt += 1;
                        continue;
                    }
                    return Err(WalletKitError::NetworkError {
                        url: url.to_string(),
                        status: None,
                        error: format!("request failed: {err}"),
                    });
                }
            }
        }
    }
}
