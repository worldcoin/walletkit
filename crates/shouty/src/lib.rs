//! Uppercase processor used by the host-mediated composition experiment.

use text_core::{build_response_json, parse_request_json, CoreError};
use thiserror::Error;

/// Errors returned by the shouty processor.
#[derive(Debug, Error, uniffi::Error)]
pub enum ShoutyError {
    /// Shared core model or JSON error.
    #[error("text-core error: {0}")]
    Core(String),
}

impl From<CoreError> for ShoutyError {
    fn from(error: CoreError) -> Self {
        Self::Core(error.to_string())
    }
}

/// Processor that uppercases the input text.
#[derive(uniffi::Object)]
pub struct ShoutyProcessor;

impl Default for ShoutyProcessor {
    fn default() -> Self {
        Self::new()
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl ShoutyProcessor {
    /// Creates a new shouty processor.
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self
    }

    /// Async processing — runs on shouty's own tokio runtime.
    ///
    /// # Errors
    ///
    /// Returns an error if the request JSON is invalid.
    pub async fn process_async(
        &self,
        request_json: String,
    ) -> Result<String, ShoutyError> {
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        let request = parse_request_json(&request_json)?;
        build_response_json("shouty", request.text.to_uppercase()).map_err(Into::into)
    }
}

uniffi::setup_scaffolding!("shouty");

#[cfg(test)]
mod tests {
    use super::ShoutyProcessor;

    #[tokio::test(flavor = "multi_thread")]
    async fn uppercases_the_input() {
        let processor = ShoutyProcessor::new();
        let response = processor
            .process_async(r#"{"text":"hello world"}"#.to_string())
            .await
            .expect("process should succeed");

        assert_eq!(response, r#"{"processor":"shouty","output":"HELLO WORLD"}"#);
    }
}
