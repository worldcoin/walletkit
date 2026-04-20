//! Shared request/response models and JSON helpers for the host-mediated
//! composition experiment.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;

/// Result type used across the shared core crate.
pub type CoreResult<T> = Result<T, CoreError>;

/// Request sent from the host to a processor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransformRequest {
    /// Text that should be transformed by the selected processor.
    pub text: String,
}

/// Response returned by a processor to the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransformResponse {
    /// Name of the processor that produced the output.
    pub processor: String,
    /// Transformed text output.
    pub output: String,
}

/// Shared validation and serialization errors.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CoreError {
    /// JSON could not be parsed or serialized.
    #[error("invalid json: {0}")]
    InvalidJson(String),
    /// Request text was blank after trimming whitespace.
    #[error("text must not be empty")]
    EmptyText,
}

/// Serializes any serde-compatible value into JSON.
pub fn to_json<T>(value: &T) -> CoreResult<String>
where
    T: Serialize,
{
    serde_json::to_string(value)
        .map_err(|error| CoreError::InvalidJson(error.to_string()))
}

/// Parses any serde-compatible value from JSON.
pub fn from_json<T>(json: &str) -> CoreResult<T>
where
    T: DeserializeOwned,
{
    serde_json::from_str(json)
        .map_err(|error| CoreError::InvalidJson(error.to_string()))
}

/// Validates a transform request.
pub fn validate_request(request: &TransformRequest) -> CoreResult<()> {
    if request.text.trim().is_empty() {
        return Err(CoreError::EmptyText);
    }

    Ok(())
}

/// Parses and validates a transform request from JSON.
pub fn parse_request_json(json: &str) -> CoreResult<TransformRequest> {
    let request: TransformRequest = from_json(json)?;
    validate_request(&request)?;
    Ok(request)
}

/// Builds a transform response and serializes it to JSON.
pub fn build_response_json(processor: &str, output: String) -> CoreResult<String> {
    to_json(&TransformResponse {
        processor: processor.to_string(),
        output,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        build_response_json, parse_request_json, CoreError, TransformRequest,
        TransformResponse,
    };

    #[test]
    fn parses_valid_request_json() {
        let request = parse_request_json(r#"{"text":"hello world"}"#)
            .expect("request should parse");
        assert_eq!(
            request,
            TransformRequest {
                text: "hello world".to_string()
            }
        );
    }

    #[test]
    fn rejects_blank_requests() {
        let error = parse_request_json(r#"{"text":"   "}"#)
            .expect_err("blank text should fail");
        assert_eq!(error, CoreError::EmptyText);
    }

    #[test]
    fn builds_response_json() {
        let json = build_response_json("mirror", "dlrow olleh".to_string())
            .expect("response should serialize");
        let response: TransformResponse =
            serde_json::from_str(&json).expect("response json should parse");

        assert_eq!(response.processor, "mirror");
        assert_eq!(response.output, "dlrow olleh");
    }
}
