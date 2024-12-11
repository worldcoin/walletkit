use std::time::Duration;

use serde::ser::Serialize;

/// A simple wrapper on an HTTP client for making requests. Sets sensible defaults such as timeouts,
/// user-agent & ensuring HTTPS.
pub struct Request {
    client: reqwest::Client,
}

impl Request {
    /// Initializes a new `Request` instance.
    pub(crate) fn new() -> Self {
        let client = reqwest::Client::new();
        Self { client }
    }

    /// Makes a POST request to a given URL with a JSON body.
    pub(crate) async fn post<T>(
        &self,
        url: String,
        body: T,
    ) -> Result<reqwest::Response, reqwest::Error>
    where
        T: Serialize + Send + Sync,
    {
        #[cfg(not(test))]
        assert!(url.starts_with("https"));

        self.client
            .post(&url)
            .timeout(Duration::from_secs(3))
            .header(
                "User-Agent",
                format!("walletkit-core/{}", env!("CARGO_PKG_VERSION")),
            )
            .json(&body)
            .send()
            .await
    }
}
