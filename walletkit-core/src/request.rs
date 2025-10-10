use std::time::Duration;

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
                            return Err(WalletKitError::NetworkError(format!(
                                "request to {url} failed with status {status} after retries"
                            )));
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
                            return Err(WalletKitError::NetworkError(format!(
                                "request to {url} failed after retries: {err}"
                            )));
                        }
                        attempt += 1;
                        continue;
                    }
                    return Err(WalletKitError::NetworkError(format!(
                        "request to {url} failed: {err}"
                    )));
                }
            }
        }
    }
}
