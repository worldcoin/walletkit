use std::time::Duration;

use serde::ser::Serialize;

pub struct Request {
    client: reqwest::Client,
}

impl Request {
    pub(crate) fn new() -> Self {
        let client = reqwest::Client::new();
        Self { client }
    }

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
