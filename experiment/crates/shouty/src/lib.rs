//! Uppercase processor used by the host-mediated composition experiment.

use switchboard::{ProcessorDriver, SwitchboardError, SwitchboardResult};
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

impl ShoutyProcessor {
    fn process_request(&self, request_json: String) -> Result<String, ShoutyError> {
        let request = parse_request_json(&request_json)?;
        build_response_json("shouty", request.text.to_uppercase()).map_err(Into::into)
    }
}

#[uniffi::export]
impl ShoutyProcessor {
    /// Creates a new shouty processor.
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self
    }
}

#[uniffi::export]
impl ProcessorDriver for ShoutyProcessor {
    /// Processes a request by uppercasing the input text.
    ///
    /// # Errors
    ///
    /// Returns an error if the request JSON is invalid.
    fn process(&self, request_json: String) -> SwitchboardResult<String> {
        self.process_request(request_json).map_err(|error| {
            SwitchboardError::UnexpectedUniFFICallback {
                reason: error.to_string(),
            }
        })
    }
}

uniffi::setup_scaffolding!("shouty");

#[cfg(test)]
mod tests {
    use super::ShoutyProcessor;
    use switchboard::{ProcessorDriver, Switchboard};

    #[test]
    fn uppercases_the_input() {
        let processor = ShoutyProcessor::new();
        let response = ProcessorDriver::process(
            &processor,
            r#"{"text":"hello world"}"#.to_string(),
        )
        .expect("process should succeed");

        assert_eq!(response, r#"{"processor":"shouty","output":"HELLO WORLD"}"#);
    }

    #[test]
    fn registers_directly_with_switchboard() {
        let board = Switchboard::new();
        board
            .register_processor(
                "shouty".to_string(),
                std::sync::Arc::new(ShoutyProcessor::new()),
            )
            .expect("register shouty directly");

        let response = board
            .process_with(
                "shouty".to_string(),
                r#"{"text":"hello world"}"#.to_string(),
            )
            .expect("dispatch shouty");

        assert_eq!(response, r#"{"processor":"shouty","output":"HELLO WORLD"}"#);
    }
}
