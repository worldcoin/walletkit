//! Reversing processor used by the host-mediated composition experiment.

use switchboard::{ProcessorDriver, SwitchboardError, SwitchboardResult};
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

impl MirrorProcessor {
    fn process_request(&self, request_json: String) -> Result<String, MirrorError> {
        let request = parse_request_json(&request_json)?;
        let output = request.text.chars().rev().collect::<String>();
        build_response_json("mirror", output).map_err(Into::into)
    }
}

#[uniffi::export]
impl MirrorProcessor {
    /// Creates a new mirror processor.
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self
    }
}

#[uniffi::export]
impl ProcessorDriver for MirrorProcessor {
    /// Processes a request by reversing the input text.
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

uniffi::setup_scaffolding!("mirror");

#[cfg(test)]
mod tests {
    use super::MirrorProcessor;
    use switchboard::{ProcessorDriver, Switchboard};

    #[test]
    fn reverses_the_input() {
        let processor = MirrorProcessor::new();
        let response = ProcessorDriver::process(
            &processor,
            r#"{"text":"hello world"}"#.to_string(),
        )
        .expect("process should succeed");

        assert_eq!(response, r#"{"processor":"mirror","output":"dlrow olleh"}"#);
    }

    #[test]
    fn registers_directly_with_switchboard() {
        let board = Switchboard::new();
        board
            .register_processor(
                "mirror".to_string(),
                std::sync::Arc::new(MirrorProcessor::new()),
            )
            .expect("register mirror directly");

        let response = board
            .process_with(
                "mirror".to_string(),
                r#"{"text":"hello world"}"#.to_string(),
            )
            .expect("dispatch mirror");

        assert_eq!(response, r#"{"processor":"mirror","output":"dlrow olleh"}"#);
    }
}
