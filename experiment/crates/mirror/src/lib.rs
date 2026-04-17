//! Reversing processor used by the host-mediated composition experiment.

use text_core::{build_response_json, parse_request_json, CoreError};
use thiserror::Error;

/// Errors returned by the mirror processor.
#[derive(Debug, Error, uniffi::Error)]
pub enum MirrorError {
    /// Shared core model or JSON error.
    #[error("text-core error: {0}")]
    Core(String),
}

impl From<CoreError> for MirrorError {
    fn from(error: CoreError) -> Self {
        Self::Core(error.to_string())
    }
}

/// Processor that reverses the input text.
#[derive(uniffi::Object)]
pub struct MirrorProcessor;

impl Default for MirrorProcessor {
    fn default() -> Self {
        Self::new()
    }
}

#[uniffi::export]
impl MirrorProcessor {
    /// Creates a new mirror processor.
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self
    }

    /// Processes a request by reversing the input text.
    ///
    /// # Errors
    ///
    /// Returns an error if the request JSON is invalid.
    pub fn process(&self, request_json: String) -> Result<String, MirrorError> {
        let request = parse_request_json(&request_json)?;
        let output = request.text.chars().rev().collect::<String>();
        build_response_json("mirror", output).map_err(Into::into)
    }
}

uniffi::setup_scaffolding!("mirror");

#[cfg(test)]
mod tests {
    use super::MirrorProcessor;

    #[test]
    fn reverses_the_input() {
        let processor = MirrorProcessor::new();
        let response = processor
            .process(r#"{"text":"hello world"}"#.to_string())
            .expect("process should succeed");

        assert_eq!(response, r#"{"processor":"mirror","output":"dlrow olleh"}"#);
    }
}
